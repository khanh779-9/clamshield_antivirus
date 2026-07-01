using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using clamshield_antivirus.Models;

using clamshield_antivirus.Services;
using clamshield_antivirus.Services.UpdateSvc;

namespace clamshield_antivirus.Services.ScanSvc;

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
    private bool _isSignatureLoading;

    public bool IsSignatureLoading
    {
        get => _isSignatureLoading;
        private set
        {
            if (_isSignatureLoading != value)
            {
                _isSignatureLoading = value;
                SignatureLoadingStateChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    public event EventHandler? SignatureLoadingStateChanged;

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
            AlertPdf = _settingsService.Get("AlertPdf", false),
            AlertMacros = _settingsService.Get("AlertMacros", false),
            AlertSwf = _settingsService.Get("AlertSwf", false),
            AlertPua = _settingsService.Get("AlertPua", false),
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
            await Task.Run(() => EnsureSignaturesLoaded(cancellationToken), cancellationToken);
            
            cancellationToken.ThrowIfCancellationRequested();

            rawLogBuilder.AppendLine($"Signatures loaded: {App.Engine.TotalSignatures}");
            rawLogBuilder.AppendLine();

            await Task.Run(() =>
            {
                int localDirsScanned = 0;
                var fileList = new List<string>();
                foreach (var target in targets)
                {
                    cancellationToken.ThrowIfCancellationRequested();

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
                object reportLock = new object();
                object logLock = new object();

                var parallelOptions = new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount,
                    CancellationToken = cancellationToken
                };

                Parallel.ForEach(fileList, parallelOptions, (currentFile) =>
                {
                    var fileInfo = new FileInfo(currentFile);
                    if (fileInfo.Length > scanOptions.MaxFileSize)
                    {
                        lock (logLock)
                        {
                            rawLogBuilder.AppendLine($"{currentFile}: SKIPPED (exceeds max file size limit of {FormatFileSize(scanOptions.MaxFileSize)})");
                        }
                        return;
                    }

                    int currentFilesScanned = Interlocked.Increment(ref filesScanned);
                    Interlocked.Add(ref totalBytesScanned, fileInfo.Length);

                    DateTime now = DateTime.UtcNow;
                    bool shouldReport = false;
                    lock (reportLock)
                    {
                        if (now - lastReportTime > TimeSpan.FromMilliseconds(100) || currentFilesScanned == totalFiles)
                        {
                            shouldReport = true;
                            lastReportTime = now;
                        }
                    }

                    if (shouldReport)
                    {
                        double percentage = totalFiles > 0 ? ((double)currentFilesScanned / totalFiles) * 100 : 0;
                        progress.Report(new ScanProgress
                        {
                            CurrentFile = currentFile,
                            FilesScanned = currentFilesScanned,
                            ProgressPercentage = percentage,
                            IsIndeterminate = false,
                            StatusText = $"Scanning ({currentFilesScanned}/{totalFiles})...",
                            BytesScanned = Interlocked.Read(ref totalBytesScanned),
                            ThreatsFoundSoFar = Interlocked.CompareExchange(ref threatsFound, 0, 0)
                        });
                    }

                    var threats = App.Engine.ScanFile(currentFile, scanOptions, cancellationToken);
                    System.Diagnostics.Debug.WriteLine($"=== ScanAsync: {currentFile} found {threats.Count} threats ===");
                    if (threats.Count > 0)
                    {
                        foreach (var threat in threats)
                        {
                            System.Diagnostics.Debug.WriteLine($"=== Threat: {threat.ThreatName} type={threat.MatchType} ===");
                            Interlocked.Increment(ref threatsFound);
                            lock (result.Threats)
                            {
                                result.Threats.Add(threat);
                            }
                            lock (logLock)
                            {
                                rawLogBuilder.AppendLine($"{currentFile}: {threat.ThreatName} FOUND");
                            }
                        }
                    }
                });
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

            cancellationToken.ThrowIfCancellationRequested();

            if (threatsFound > 0)
            {
                result.Status = "Infected";
            }
            else
            {
                result.Status = "Clean";
            }
        }
        catch (OperationCanceledException)
        {
            result.Status = "Cancelled";
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
            result.TotalBytesScanned = totalBytesScanned;
            result.TotalSignaturesLoaded = App.Engine.TotalSignatures;
            result.DirectoriesScanned = dirsScanned;
            result.FilesScanned = filesScanned;
            result.ThreatsFound = threatsFound;
            
            rawLogBuilder.AppendLine();
            rawLogBuilder.AppendLine("\n[Scan cancelled by user]");
            result.RawLog = rawLogBuilder.ToString();
            return result;
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
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                if (IsExcluded(entry, exclusions))
                    continue;

                if (File.Exists(entry))
                {
                    fileList.Add(entry);
                }
                else if (Directory.Exists(entry))
                {
                    dirsScanned++;
                    GetFilesRecursively(entry, fileList, ref dirsScanned, exclusions, cancellationToken);
                }
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
        LoadLocalSignatureDatabases(CancellationToken.None);
    }

    public async Task ReloadSignaturesAsync()
    {
        _signaturesDirty = true;
        _signaturesLoaded = false;
        await Task.Run(() => LoadLocalSignatureDatabases(CancellationToken.None));
    }

    private void EnsureSignaturesLoaded(CancellationToken cancellationToken)
    {
        if (_signaturesLoaded && !_signaturesDirty)
        {
            long currentTimestamp = Directory.Exists(DbDir)
                ? Directory.GetLastWriteTimeUtc(DbDir).Ticks : 0;
            if (currentTimestamp == _dbDirTimestamp)
                return;
        }
        LoadLocalSignatureDatabases(cancellationToken);
    }

    private readonly object _dbLock = new();

    private void LoadLocalSignatureDatabases(CancellationToken cancellationToken)
    {
        IsSignatureLoading = true;
        try
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
                        cancellationToken.ThrowIfCancellationRequested();
                        try
                        {
                            var cvdInfo = CvdReader.ReadCvdHeader(cvdFile);
                            if (cvdInfo != null)
                            {
                                App.Engine.SetDbBuildTime(cvdInfo.BuildTime);
                            }

                            var files = CvdReader.ExtractCvd(cvdFile);
                            var sortedFiles = files.OrderBy(f =>
                            {
                                string e = Path.GetExtension(f.FileName).ToLowerInvariant();
                                if (e == ".fp" || e == ".sfp") return 0;
                                if (e == ".crb" || e == ".cat") return 1;
                                if (e == ".ign" || e == ".ign2") return 2;
                                return 3;
                            }).ToList();

                            foreach (var file in sortedFiles)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                using (var ms = new MemoryStream(file.Content))
                                {
                                    int loaded = App.Engine.LoadSignaturesFromStream(file.FileName, ms);
                                    Debug.WriteLine($"CVD {Path.GetFileName(cvdFile)} -> {file.FileName}: loaded {loaded} signatures");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Failed to parse CVD signature {cvdFile}: {ex.Message}");
                        }
                    }

                    var supportedExtensions = new[] { 
                        "*.fp", "*.sfp", 
                        "*.crb", "*.cat",
                        "*.ign", "*.ign2", 
                        "*.hdb", "*.hdu", "*.hsb", "*.hsu", 
                        "*.ndb", "*.ndu", "*.ldb", "*.ldu", 
                        "*.mdb", "*.mdu", "*.msb", "*.msu", 
                        "*.sha256", "*.db", "*.sdb", "*.cdb", "*.idb" 
                    };

                    foreach (var ext in supportedExtensions)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var sigFiles = Directory.GetFiles(DbDir, ext);
                        foreach (var sigFile in sigFiles)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            try
                            {
                                using (var fs = File.OpenRead(sigFile))
                                {
                                    int loaded = App.Engine.LoadSignaturesFromStream(Path.GetFileName(sigFile), fs);
                                    Debug.WriteLine($"Loaded {loaded} signatures from {Path.GetFileName(sigFile)}");
                                }
                            }
                            catch { }
                        }
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    App.Engine.Compile();
                    _signaturesLoaded = true;
                    TrimMemory();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error loading local databases: {ex.Message}");
                }
            }
        }
        finally
        {
            IsSignatureLoading = false;
        }
    }

    [DllImport("psapi.dll")]
    private static extern int EmptyWorkingSet(IntPtr hwProc);

    private static void TrimMemory()
    {
        GC.Collect(2, GCCollectionMode.Forced, true, true);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Forced, true, true);
        try
        {
            using var process = Process.GetCurrentProcess();
            EmptyWorkingSet(process.Handle);
        }
        catch { }
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
