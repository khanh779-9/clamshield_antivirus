using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using clamshield_antivirus.Models;
using clamshield_antivirus.Converters;

namespace clamshield_antivirus.Services;

public class FreshclamService
{
    private readonly ComponentDetectionService _detectionService;
    private static readonly string DbDir = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "database"
    );

    private static readonly string[] DefaultMirrors = new[]
    {
        "https://database.clamav.net",
        //"https://clamav.caminobitcoin.com",
        //"https://mirrors.mediatemple.net/clamav",
        //"https://repo.vector.co.jp/clamav"
    };

    private static readonly string[] DefaultDatabases = new[]
    {
        "main.cvd", "daily.cvd", "bytecode.cvd", "windows.cvd"
    };

    public FreshclamService(ComponentDetectionService detectionService)
    {
        _detectionService = detectionService;
        EnsureDirectoryExists();
    }

    private void EnsureDirectoryExists()
    {
        if (!Directory.Exists(DbDir))
            Directory.CreateDirectory(DbDir);
    }

    private int GetLocalCvdVersion(string dbFile)
    {
        string localPath = Path.Combine(DbDir, dbFile);
        if (!File.Exists(localPath))
            return 0;

        var info = CvdReader.ReadCvdHeader(localPath);
        return info?.Version ?? 0;
    }

    private async Task<int> GetRemoteCvdVersionAsync(HttpClient client, string dbFile, string mirror, CancellationToken ct)
    {
        string url = $"{mirror}/{dbFile}";
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Head, url);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (!response.IsSuccessStatusCode)
                return -1;

            if (response.Content.Headers.ContentRange != null)
            {
                var range = response.Content.Headers.ContentRange;
                if (range.HasRange && range.From == 0 && range.To.HasValue && range.To.Value >= 511)
                {
                    using var rangeRequest = new HttpRequestMessage(HttpMethod.Get, url);
                    rangeRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 511);
                    using var rangeResponse = await client.SendAsync(rangeRequest, HttpCompletionOption.ResponseHeadersRead, ct);
                    if (rangeResponse.IsSuccessStatusCode)
                    {
                        byte[] headerBytes = await rangeResponse.Content.ReadAsByteArrayAsync(ct);
                        if (headerBytes.Length >= 512)
                        {
                            string headerStr = System.Text.Encoding.ASCII.GetString(headerBytes, 0, 512);
                            var info = ParseCvdHeaderString(headerStr);
                            return info?.Version ?? -1;
                        }
                    }
                }
            }

            return -1;
        }
        catch
        {
            return -1;
        }
    }

    private CvdInfo? ParseCvdHeaderString(string header)
    {
        if (string.IsNullOrEmpty(header)) return null;
        var parts = header.Split(':');
        if (parts.Length < 6) return null;

        var info = new CvdInfo();
        info.DatabaseName = parts[0].Trim();
        if (int.TryParse(parts[1].Trim(), out int ver))
            info.Version = ver;
        if (int.TryParse(parts[2].Trim(), out int sigCount))
            info.SignatureCount = sigCount;
        return info;
    }

    private async Task<bool> DownloadWithRetryAsync(
        HttpClient client,
        string url,
        string destFile,
        string label,
        IProgress<string> progress,
        int maxRetries,
        CancellationToken cancellationToken)
    {
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            if (cancellationToken.IsCancellationRequested)
                return false;

            try
            {
                if (attempt > 1)
                {
                    int delayMs = (int)Math.Min(1000 * Math.Pow(2, attempt - 2), 30000);
                    progress.Report($"[Retry {attempt}/{maxRetries}] Waiting {delayMs / 1000}s before retry...");
                    await Task.Delay(delayMs, cancellationToken);
                }

                using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    progress.Report($"[{label}] Server returned {response.StatusCode}");
                    continue;
                }

                long? totalBytes = response.Content.Headers.ContentLength;
                using var downloadStream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var fileStream = new FileStream(destFile, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true);

                var buffer = new byte[8192];
                long bytesRead = 0;
                int read;
                DateTime lastReportTime = DateTime.MinValue;

                while ((read = await downloadStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                {
                    await fileStream.WriteAsync(buffer, 0, read, cancellationToken);
                    bytesRead += read;

                    DateTime now = DateTime.UtcNow;
                    if (now - lastReportTime > TimeSpan.FromMilliseconds(200) || bytesRead == totalBytes)
                    {
                        if (totalBytes.HasValue)
                        {
                            double pct = ((double)bytesRead / totalBytes.Value) * 100;
                            progress.Report($"[{label}] Downloaded {FileSizeConverter.FormatFileSize(bytesRead)} of {FileSizeConverter.FormatFileSize(totalBytes.Value)} ({pct:F1}%)");
                        }
                        else
                        {
                            progress.Report($"[{label}] Downloaded {FileSizeConverter.FormatFileSize(bytesRead)}...");
                        }
                        lastReportTime = now;
                    }
                }

                fileStream.Close();
                return true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                progress.Report($"[{label}] Attempt {attempt} failed: {ex.Message}");
            }
        }

        return false;
    }

    public async Task<LogEntry> UpdateDatabaseAsync(IProgress<string> progress, CancellationToken cancellationToken)
    {
        var logEntry = new LogEntry
        {
            Type = "Update",
            Timestamp = DateTime.Now,
            Summary = "Database update started",
            Status = "Success"
        };

        EnsureDirectoryExists();

        var rawLogBuilder = new System.Text.StringBuilder();
        rawLogBuilder.AppendLine($"[ClamUI C# Native Database Update Started: {DateTime.Now}]");
        rawLogBuilder.AppendLine($"Downloading definitions to: {DbDir}");
        rawLogBuilder.AppendLine();

        progress.Report("Contacting ClamAV signature servers...");

        // Check for forced offline mode – skip network activity and rely on existing local signatures.
        bool forceOffline = App.Settings.Get("ForceOffline", false);
        if (forceOffline)
        {
            progress.Report("[Offline] Forced offline mode – skipping remote updates.");
            rawLogBuilder.AppendLine("[Offline] Skipping download of signature files due to forced offline mode.");
            // Directly finish with a successful status – existing local signatures (including offline backup) will be used.
            logEntry.Status = "Success";
            logEntry.Summary = "Offline mode: using existing local signatures.";
            logEntry.Details = rawLogBuilder.ToString();
            return logEntry;
        }

        try
        {
            using var handler = new HttpClientHandler
            {
                AutomaticDecompression = System.Net.DecompressionMethods.None,
                MaxConnectionsPerServer = 4
            };

            // Load CA root certificate from certs/clamav.crt (next to the exe)
            string certsDir = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "certs"
            );
            if (Directory.Exists(certsDir))
            {
                var caCertificates = new X509Certificate2Collection();
                foreach (string crtFile in Directory.GetFiles(certsDir, "*.crt"))
                {
                    try
                    {
                        var cert = X509CertificateLoader.LoadCertificateFromFile(crtFile);
                        if (cert != null)
                        {
                            caCertificates.Add(cert);
                            rawLogBuilder.AppendLine($"Loaded CA certificate: {crtFile}");
                        }
                    }
                    catch (Exception ex)
                    {
                        rawLogBuilder.AppendLine($"[Warning] Failed to load {crtFile}: {ex.Message}");
                    }
                }

                if (caCertificates.Count > 0)
                {
                    handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                    {
                        if (errors == System.Net.Security.SslPolicyErrors.None)
                            return true;

                        if (cert == null)
                            return false;

                        // Build custom chain with our CA cert(s)
                        using var customChain = new X509Chain();
                        customChain.ChainPolicy.ExtraStore.AddRange(caCertificates);
                        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                        return customChain.Build(cert);
                    };
                }
            }
            else
            {
                rawLogBuilder.AppendLine($"[Warning] No certs/ directory found at {certsDir} – trying default system trust store.");
            }
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromMinutes(10);
            string uuid = App.Settings.Get("FreshclamUUID", string.Empty);
            if (string.IsNullOrEmpty(uuid))
            {
                uuid = Guid.NewGuid().ToString();
                App.Settings.Set("FreshclamUUID", uuid);
            }
            string userAgent = $"ClamAV/1.3.1 (OS: win32, ARCH: x86_64, CPU: x86_64, CLAMAVVER: 1.3.1, UUID: {uuid})";
            client.DefaultRequestHeaders.Add("User-Agent", userAgent);
            client.DefaultRequestHeaders.Add("Cache-Control", "no-cache");

            var mirrors = new List<string>(DefaultMirrors);
            var customMirrors = App.Settings.Get("DatabaseMirrorUrls", new List<string>());
            if (customMirrors?.Count > 0)
            {
                mirrors.InsertRange(0, customMirrors);
            }

            int maxRetries = App.Settings.Get("DownloadMaxRetries", 3);

            var databases = new List<string>(DefaultDatabases);
            var customDbNames = App.Settings.Get("DatabaseCustomNames", new List<string>());
            if (customDbNames?.Count > 0)
                databases.AddRange(customDbNames);

            int successCount = 0;
            int totalExtractedSignatures = 0;
            int skippedCount = 0;
            var downloadedFiles = new List<string>();

            for (int i = 0; i < databases.Count; i++)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                string dbFile = databases[i];
                string label = $"{i + 1}/{databases.Count}";

                int localVersion = GetLocalCvdVersion(dbFile);
                string destFile = Path.Combine(DbDir, dbFile);

                bool downloaded = false;
                string? usedMirror = null;

                foreach (var mirror in mirrors)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    string url = $"{mirror}/{dbFile}";
                    progress.Report($"[{label}] Checking {dbFile} on {new Uri(mirror).Host}...");
                    rawLogBuilder.AppendLine($"HTTP HEAD {url}");

                    try
                    {
                        int remoteVersion = await GetRemoteCvdVersionAsync(client, dbFile, mirror, cancellationToken);

                        if (remoteVersion >= 0 && localVersion >= remoteVersion)
                        {
                            progress.Report($"[{label}] {dbFile} is up to date (local v{localVersion} >= remote v{remoteVersion})");
                            rawLogBuilder.AppendLine($"[SKIP] {dbFile}: local v{localVersion} >= remote v{remoteVersion}");
                            skippedCount++;
                            downloaded = true;
                            break;
                        }

                        if (remoteVersion >= 0)
                        {
                            rawLogBuilder.AppendLine($"[UPDATE] {dbFile}: local v{localVersion} -> remote v{remoteVersion}");
                        }

                        progress.Report($"[{label}] Downloading {dbFile} from {new Uri(mirror).Host}...");
                        rawLogBuilder.AppendLine($"HTTP GET {url}");

                        bool ok = await DownloadWithRetryAsync(client, url, destFile, label, progress, maxRetries, cancellationToken);
                        if (ok)
                        {
                            downloaded = true;
                            usedMirror = mirror;
                            rawLogBuilder.AppendLine($"Downloaded {dbFile} from {new Uri(mirror).Host} successfully.");
                            downloadedFiles.Add(destFile);
                            break;
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (System.Net.Http.HttpRequestException ex)
                    {
                        // Network likely blocked – switch to offline handling.
                        progress.Report($"[{label}] Network error contacting {new Uri(mirror).Host}: {ex.Message}. Switching to offline mode.");
                        rawLogBuilder.AppendLine($"[NetworkError] {ex.Message}");
                        // Abort further network attempts and fall back to offline.
                        logEntry.Status = "Success";
                        logEntry.Summary = "Network blocked – using existing local signatures.";
                        logEntry.Details = rawLogBuilder.ToString();
                        return logEntry;
                    }
                    catch (Exception ex)
                    {
                        progress.Report($"[{label}] Mirror {new Uri(mirror).Host} failed: {ex.Message}");
                        rawLogBuilder.AppendLine($"[Warning] Mirror {mirror} failed for {dbFile}: {ex.Message}");
                    }
                }

                if (!downloaded)
                {
                    progress.Report($"[{label}] Skip {dbFile} (all mirrors failed)");
                    rawLogBuilder.AppendLine($"[Warning] {dbFile} not available on any mirror");
                    continue;
                }
            }

            var customUrls = App.Settings.Get("DatabaseCustomUrls", new List<string>());
            if (customUrls?.Count > 0)
            {
                rawLogBuilder.AppendLine();
                rawLogBuilder.AppendLine("----------- CUSTOM DATABASES -----------");

                for (int i = 0; i < customUrls.Count; i++)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    string url = customUrls[i];
                    if (string.IsNullOrWhiteSpace(url)) continue;

                    string customFileName = Path.GetFileName(new Uri(url).LocalPath);
                    if (string.IsNullOrEmpty(customFileName))
                        customFileName = $"custom_sig_{i}.ndb";

                    string destFile = Path.Combine(DbDir, customFileName);
                    string label = $"Custom {i + 1}/{customUrls.Count}";
                    progress.Report($"[{label}] Downloading {customFileName}...");
                    rawLogBuilder.AppendLine($"HTTP GET {url}");

                    try
                    {
                        bool ok = await DownloadWithRetryAsync(client, url, destFile, label, progress, maxRetries, cancellationToken);
                        if (ok)
                        {
                            rawLogBuilder.AppendLine($"Downloaded custom file {customFileName} successfully.");

                            string ext = Path.GetExtension(customFileName).ToLower();
                            if (ext == ".cvd" || ext == ".cld")
                            {
                                downloadedFiles.Add(destFile);
                            }
                            else
                            {
                                successCount++;
                            }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        progress.Report($"[{label}] Failed: {ex.Message}");
                        rawLogBuilder.AppendLine($"[Error] Failed downloading custom URL {url}: {ex.Message}");
                    }
                }
            }

            // Extract/parse all downloaded database files
            if (downloadedFiles.Count > 0)
            {
                rawLogBuilder.AppendLine();
                rawLogBuilder.AppendLine("----------- EXTRACTING & PARSING -----------");

                for (int i = 0; i < downloadedFiles.Count; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    string destFile = downloadedFiles[i];
                    string dbFile = Path.GetFileName(destFile);
                    string label = $"Extract {i + 1}/{downloadedFiles.Count}";

                    if (File.Exists(destFile))
                    {
                        try
                        {
                            progress.Report($"[{label}] Extracting {dbFile}...");
                            var extracted = await Task.Run(() => CvdReader.ExtractCvd(destFile), cancellationToken);
                            totalExtractedSignatures += extracted.Count;
                            successCount++;
                            rawLogBuilder.AppendLine($"Extracted {dbFile} containing {extracted.Count} files.");
                        }
                        catch (Exception ex)
                        {
                            rawLogBuilder.AppendLine($"[Warning] Failed to extract {dbFile}: {ex.Message}");
                        }
                    }
                }
            }

            if (successCount > 0)
            {
                logEntry.Status = "Success";
                logEntry.Summary = $"Database updated ({successCount} files updated, {skippedCount} up-to-date). {totalExtractedSignatures} signature files loaded.";
            }
            else
            {
                logEntry.Status = "Fail";
                logEntry.Summary = "Failed updating database files";
            }
        }
        catch (OperationCanceledException)
        {
            logEntry.Status = "Fail";
            logEntry.Summary = "Update cancelled";
            rawLogBuilder.AppendLine("\n[Update cancelled by user]");
            progress.Report("[Cancelled]");
        }
        catch (Exception ex)
        {
            logEntry.Status = "Fail";
            logEntry.Summary = "Update failed, using local signatures";
            rawLogBuilder.AppendLine($"\n[Error] {ex.Message}");
            progress.Report("[Connection issues] Could not contact ClamAV network. Falling back to local offline signatures.");
            WriteBackupOfflineSignatures();
        }

        logEntry.Details = rawLogBuilder.ToString();
        return logEntry;
    }

    public async Task<bool> IsDatabaseOutdatedAsync()
    {
        try
        {
            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(10);
            string uuid = App.Settings.Get("FreshclamUUID", string.Empty);
            if (string.IsNullOrEmpty(uuid))
            {
                uuid = Guid.NewGuid().ToString();
                App.Settings.Set("FreshclamUUID", uuid);
            }
            string userAgent = $"ClamAV/1.3.1 (OS: win32, ARCH: x86_64, CPU: x86_64, CLAMAVVER: 1.3.1, UUID: {uuid})";
            client.DefaultRequestHeaders.Add("User-Agent", userAgent);

            foreach (var dbFile in DefaultDatabases)
            {
                int localVersion = GetLocalCvdVersion(dbFile);
                if (localVersion == 0) continue;

                foreach (var mirror in DefaultMirrors)
                {
                    int remoteVersion = await GetRemoteCvdVersionAsync(client, dbFile, mirror, CancellationToken.None);
                    if (remoteVersion > localVersion)
                        return true;
                    if (remoteVersion >= 0)
                        break;
                }
            }
        }
        catch
        {
            // Network unavailable – use time-based heuristic
        }

        // Fallback: if last update is more than 7 days old, consider outdated
        string lastUpdate = App.Settings.Get("LastDatabaseUpdateTime", string.Empty);
        if (!string.IsNullOrEmpty(lastUpdate) && DateTime.TryParse(lastUpdate, out var lastUpdateTime))
        {
            return (DateTime.Now - lastUpdateTime).TotalDays > 7;
        }

        return false;
    }

    private void WriteBackupOfflineSignatures()
    {
        try
        {
            string backupHdb = Path.Combine(DbDir, "offline_backup.hdb");
            if (!File.Exists(backupHdb))
            {
                string hdbContent = "# ClamUI Offline Backup Signatures\n44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature-MD5\n";
                File.WriteAllText(backupHdb, hdbContent);
            }
        }
        catch { }
    }
}
