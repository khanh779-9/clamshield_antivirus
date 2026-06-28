using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.Services;

public class ClamAvService
{
    private readonly ComponentDetectionService _detectionService;
    private readonly SettingsService _settingsService;
    private static readonly string DbDir = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "database"
    );

    private bool _signaturesLoaded;
    private bool _signaturesDirty;
    private long _dbDirTimestamp;

    public ClamAvService(ComponentDetectionService detectionService, SettingsService settingsService)
    {
        _detectionService = detectionService;
        _settingsService = settingsService;
    }

    public async Task<ScanResult> ScanAsync(
        List<string> targets,
        ScanProfile? profile,
        IProgress<ScanProgress> progress,
        CancellationToken cancellationToken)
    {
        var result = new ScanResult
        {
            ScanPath = string.Join(", ", targets),
            Status = "Clean",
            ScanTime = DateTime.Now
        };

        var stopwatch = Stopwatch.StartNew();
        var rawLogBuilder = new System.Text.StringBuilder();
        rawLogBuilder.AppendLine($"[ClamUI Native C# Scan Started: {DateTime.Now}]");
        rawLogBuilder.AppendLine($"Targets: {result.ScanPath}");

        var scanOptions = new ScanOptions
        {
            AllMatchMode = profile?.DeepScan == true || _settingsService.Get("AllMatchMode", false),
            MaxFileSize = _settingsService.Get("MaxFileSize", 100L * 1024 * 1024),
            MaxScanSize = _settingsService.Get("MaxScanSize", 500L * 1024 * 1024),
            MaxRecursion = _settingsService.Get("MaxRecursion", 16),
            MaxFiles = _settingsService.Get("MaxFiles", 10000),
            HeuristicAlerts = _settingsService.Get("HeuristicAlerts", true),
            ParseArchives = _settingsService.Get("ParseArchives", true),
            ParsePe = _settingsService.Get("ParsePe", true),
            ParsePdf = _settingsService.Get("ParsePdf", true),
            ParseMail = _settingsService.Get("ParseMail", true),
            ParseOle2 = _settingsService.Get("ParseOle2", true),
            ParseHtml = _settingsService.Get("ParseHtml", true),
            ParseElf = _settingsService.Get("ParseElf", true),
            ParseSwf = _settingsService.Get("ParseSwf", true),
            ParseRtf = _settingsService.Get("ParseRtf", true),
        };

        if (scanOptions.AllMatchMode)
            rawLogBuilder.AppendLine("Mode: All-match (detect all threats)");
        else
            rawLogBuilder.AppendLine("Mode: First-match (stop at first threat)");

        rawLogBuilder.AppendLine();

        int filesScanned = 0;
        int dirsScanned = 0;
        int threatsFound = 0;
        long totalBytesScanned = 0;
        var exclusionPatterns = _settingsService.Get("ExclusionPatterns", new List<string>());
        var profileExclusions = profile?.ExclusionPatterns ?? new List<string>();
        var allExclusions = new List<string>(exclusionPatterns);
        allExclusions.AddRange(profileExclusions);

        try
        {
            await Task.Run(() => EnsureSignaturesLoaded(), cancellationToken);

            rawLogBuilder.AppendLine($"Signatures loaded: {App.Engine.TotalSignatures}");
            rawLogBuilder.AppendLine();

            await Task.Run(() =>
            {
                int localDirsScanned = 0;
                var fileList = new List<string>();
                foreach (var target in targets)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;

                    if (File.Exists(target))
                    {
                        if (!IsExcluded(target, allExclusions))
                            fileList.Add(target);
                    }
                    else if (Directory.Exists(target))
                    {
                        localDirsScanned++;
                        GetFilesRecursively(target, fileList, ref localDirsScanned, allExclusions, cancellationToken);
                    }
                }
                dirsScanned = localDirsScanned;
                int totalFiles = fileList.Count;

                DateTime lastReportTime = DateTime.MinValue;

                for (int i = 0; i < totalFiles; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    string currentFile = fileList[i];
                    filesScanned++;

                    var fileInfo = new FileInfo(currentFile);
                    if (fileInfo.Length > scanOptions.MaxFileSize)
                    {
                        rawLogBuilder.AppendLine($"{currentFile}: SKIPPED (exceeds max file size limit of {FormatFileSize(scanOptions.MaxFileSize)})");
                        continue;
                    }
                    totalBytesScanned += fileInfo.Length;

                    DateTime now = DateTime.UtcNow;
                    if (now - lastReportTime > TimeSpan.FromMilliseconds(50) || i == totalFiles - 1)
                    {
                        double percentage = totalFiles > 0 ? ((double)filesScanned / totalFiles) * 100 : 0;
                        progress.Report(new ScanProgress
                        {
                            CurrentFile = currentFile,
                            FilesScanned = filesScanned,
                            ProgressPercentage = percentage,
                            IsIndeterminate = false,
                            StatusText = $"Scanning ({filesScanned}/{totalFiles})...",
                            BytesScanned = totalBytesScanned,
                            ThreatsFoundSoFar = threatsFound
                        });
                        lastReportTime = now;
                    }

                    var threats = App.Engine.ScanFile(currentFile, scanOptions);
                    if (threats.Count > 0)
                    {
                        foreach (var threat in threats)
                        {
                            threatsFound++;
                            lock (result.Threats)
                            {
                                result.Threats.Add(threat);
                            }
                            rawLogBuilder.AppendLine($"{currentFile}: {threat.ThreatName} FOUND");
                        }
                    }
                }
            }, cancellationToken);

            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
            result.TotalBytesScanned = totalBytesScanned;
            result.TotalSignaturesLoaded = App.Engine.TotalSignatures;

            rawLogBuilder.AppendLine();
            rawLogBuilder.AppendLine("----------- SCAN SUMMARY -----------");
            rawLogBuilder.AppendLine($"Known virus signatures in memory: {App.Engine.TotalSignatures}");
            rawLogBuilder.AppendLine($"Scanned directories: {dirsScanned}");
            rawLogBuilder.AppendLine($"Scanned files: {filesScanned}");
            rawLogBuilder.AppendLine($"Total data scanned: {FormatFileSize(totalBytesScanned)}");
            rawLogBuilder.AppendLine($"Infected files: {threatsFound}");
            rawLogBuilder.AppendLine($"Time: {stopwatch.Elapsed.TotalSeconds:F3} sec");

            if (totalBytesScanned > 0)
            {
                double mbPerSec = (totalBytesScanned / (1024.0 * 1024.0)) / stopwatch.Elapsed.TotalSeconds;
                rawLogBuilder.AppendLine($"Throughput: {mbPerSec:F1} MB/s");
            }

            result.DirectoriesScanned = dirsScanned;
            result.FilesScanned = filesScanned;
            result.ThreatsFound = threatsFound;

            if (cancellationToken.IsCancellationRequested)
            {
                result.Status = "Cancelled";
                rawLogBuilder.AppendLine("\n[Scan cancelled by user]");
            }
            else if (threatsFound > 0)
            {
                result.Status = "Infected";
            }
            else
            {
                result.Status = "Clean";
            }
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.RawLog = $"An error occurred during scan: {ex.Message}";
            return result;
        }

        result.RawLog = rawLogBuilder.ToString();
        return result;
    }

    private static bool IsExcluded(string path, List<string> exclusionPatterns)
    {
        if (exclusionPatterns == null || exclusionPatterns.Count == 0)
            return false;

        foreach (var pattern in exclusionPatterns)
        {
            if (string.IsNullOrEmpty(pattern)) continue;

            if (path.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                return true;

            if (pattern.Contains('*') || pattern.Contains('?'))
            {
                if (WildcardMatch(path, pattern))
                    return true;
            }

            if (path.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool WildcardMatch(string input, string pattern)
    {
        if (!pattern.Contains('*') && !pattern.Contains('?'))
            return input.Equals(pattern, StringComparison.OrdinalIgnoreCase);

        var regexPattern = System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".");
        try
        {
            return System.Text.RegularExpressions.Regex.IsMatch(input, $"^{regexPattern}$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private void GetFilesRecursively(string dir, List<string> fileList, ref int dirsScanned, List<string> exclusions, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
            return;

        try
        {
            foreach (var file in Directory.GetFiles(dir))
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                if (!IsExcluded(file, exclusions))
                    fileList.Add(file);
            }

            foreach (var subDir in Directory.GetDirectories(dir))
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                if (IsExcluded(subDir, exclusions))
                    continue;

                dirsScanned++;
                GetFilesRecursively(subDir, fileList, ref dirsScanned, exclusions, cancellationToken);
            }
        }
        catch
        {
        }
    }

    public void ReloadSignatures()
    {
        _signaturesDirty = true;
        _signaturesLoaded = false;
        LoadLocalSignatureDatabases();
    }

    public async Task ReloadSignaturesAsync()
    {
        _signaturesDirty = true;
        _signaturesLoaded = false;
        await Task.Run(() => LoadLocalSignatureDatabases());
    }

    private void EnsureSignaturesLoaded()
    {
        if (_signaturesLoaded && !_signaturesDirty)
        {
            long currentTimestamp = Directory.Exists(DbDir)
                ? Directory.GetLastWriteTimeUtc(DbDir).Ticks : 0;
            if (currentTimestamp == _dbDirTimestamp)
                return;
        }
        LoadLocalSignatureDatabases();
    }

    private readonly object _dbLock = new();

    private void LoadLocalSignatureDatabases()
    {
        lock (_dbLock)
        {
            if (!Directory.Exists(DbDir)) return;

            // Double check inside the lock
            if (_signaturesLoaded && !_signaturesDirty)
            {
                long currentTimestamp = Directory.Exists(DbDir)
                    ? Directory.GetLastWriteTimeUtc(DbDir).Ticks : 0;
                if (currentTimestamp == _dbDirTimestamp)
                    return;
            }

            _signaturesDirty = false;
            _dbDirTimestamp = Directory.GetLastWriteTimeUtc(DbDir).Ticks;
            App.Engine.Clear();

            try
            {
                var cvdFiles = Directory.GetFiles(DbDir, "*.c*d");
                foreach (var cvdFile in cvdFiles)
                {
                    try
                    {
                        var cvdInfo = CvdReader.ReadCvdHeader(cvdFile);
                        if (cvdInfo != null)
                        {
                            App.Engine.SetDbBuildTime(cvdInfo.BuildTime);
                        }

                        var files = CvdReader.ExtractCvd(cvdFile);
                        foreach (var file in files)
                        {
                            string content = System.Text.Encoding.ASCII.GetString(file.Content);
                            int loaded = App.Engine.LoadSignaturesFromContent(file.FileName, content);
                            Debug.WriteLine($"CVD {Path.GetFileName(cvdFile)} -> {file.FileName}: loaded {loaded} signatures");
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Failed to parse CVD signature {cvdFile}: {ex.Message}");
                    }
                }

                var supportedExtensions = new[] { "*.hdb", "*.hdu", "*.hsb", "*.hsu", "*.ndb", "*.ndu",
                    "*.ldb", "*.ldu", "*.mdb", "*.mdu", "*.msb", "*.msu", "*.sha256",
                    "*.fp", "*.sfp", "*.ign", "*.ign2", "*.db", "*.sdb", "*.cdb" };

                foreach (var ext in supportedExtensions)
                {
                    var sigFiles = Directory.GetFiles(DbDir, ext);
                    foreach (var sigFile in sigFiles)
                    {
                        try
                        {
                            string content = File.ReadAllText(sigFile);
                            int loaded = App.Engine.LoadSignaturesFromContent(Path.GetFileName(sigFile), content);
                            Debug.WriteLine($"Loaded {loaded} signatures from {Path.GetFileName(sigFile)}");
                        }
                        catch { }
                    }
                }
                _signaturesLoaded = true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading local databases: {ex.Message}");
            }
        }
    }

    private static string FormatFileSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        double size = bytes;
        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }
        return $"{size:F1} {units[unitIndex]}";
    }
}
