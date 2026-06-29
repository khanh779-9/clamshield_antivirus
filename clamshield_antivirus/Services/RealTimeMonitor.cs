using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace clamshield_antivirus.Services;

public class RealTimeMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly object _lock = new();
    private Timer? _debounceTimer;
    private bool _enabled;
    private int _totalScanned;
    private List<string> _exclusionPatterns = new();

    // Fields for refined real-time scanning
    private readonly Dictionary<string, DateTime> _pendingFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _concurrencySemaphore = new(8);

    public bool IsRunning => _enabled;
    public int TotalScanned => _totalScanned;
    public List<string> ActiveMonitoredPaths
    {
        get
        {
            lock (_watchers)
            {
                return _watchers.Select(w => w.Path).ToList();
            }
        }
    }

    public event Action<string>? FileScanned;
    public event Action<string, string>? ThreatDetected; // (filePath, threatName)
    public event Action? ProtectionStarted;
    public event Action? ProtectionStopped;

    public async Task StartAsync(IEnumerable<string> directories, bool includeSubdirectories = false, List<string>? exclusionPatterns = null)
    {
        _exclusionPatterns = exclusionPatterns ?? new List<string>();
        Stop();

        lock (_lock)
        {
            lock (_pendingFiles)
            {
                _pendingFiles.Clear();
            }
            _enabled = true;
        }

        ProtectionStarted?.Invoke();

        await Task.Run(() =>
        {
            foreach (var dir in directories)
            {
                if (!Directory.Exists(dir)) continue;

                try
                {
                    var watcher = new FileSystemWatcher
                    {
                        Path = dir,
                        IncludeSubdirectories = includeSubdirectories,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        Filter = "*.*",
                        InternalBufferSize = 65536 // Max buffer size to prevent buffer overflow exceptions
                    };

                    watcher.Created += OnFileChanged;
                    watcher.Changed += OnFileChanged;
                    watcher.Error += OnWatcherError;
                    watcher.EnableRaisingEvents = true;

                    lock (_watchers)
                    {
                        _watchers.Add(watcher);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Failed to start watcher for {dir}: {ex.Message}");
                }
            }
        });
    }

    public async Task StartSystemWideAsync(List<string>? exclusionPatterns = null)
    {
        await Task.Run(async () =>
        {
            var fixedDrives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                .Select(d => d.RootDirectory.FullName)
                .ToList();

            await StartAsync(fixedDrives, includeSubdirectories: true, exclusionPatterns: exclusionPatterns);
        });
    }

    public void Stop()
    {
        _enabled = false;
        ProtectionStopped?.Invoke();

        lock (_watchers)
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _watchers.Clear();
        }

        lock (_lock)
        {
            lock (_pendingFiles)
            {
                _pendingFiles.Clear();
            }
        }

        _debounceTimer?.Dispose();
        _debounceTimer = null;
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (!_enabled) return;

        string filePath = e.FullPath;

        lock (_pendingFiles)
        {
            _pendingFiles[filePath] = DateTime.UtcNow;
        }

        lock (_lock)
        {
            if (!_enabled) return;
            if (_debounceTimer == null)
            {
                _debounceTimer = new Timer(_ => ProcessPendingFiles(), null, 500, Timeout.Infinite);
            }
        }
    }

    private void ProcessPendingFiles()
    {
        var filesToScan = new List<string>();
        var now = DateTime.UtcNow;

        lock (_pendingFiles)
        {
            var keysToRemove = new List<string>();
            foreach (var kvp in _pendingFiles)
            {
                if ((now - kvp.Value).TotalMilliseconds >= 1000)
                {
                    filesToScan.Add(kvp.Key);
                    keysToRemove.Add(kvp.Key);
                }
            }
            foreach (var key in keysToRemove)
            {
                _pendingFiles.Remove(key);
            }
        }

        foreach (var file in filesToScan)
        {
            _ = Task.Run(async () =>
            {
                await _concurrencySemaphore.WaitAsync();
                try
                {
                    await ScanFileAsync(file);
                }
                finally
                {
                    _concurrencySemaphore.Release();
                }
            });
        }

        lock (_lock)
        {
            _debounceTimer?.Dispose();
            _debounceTimer = null;

            bool hasPending;
            lock (_pendingFiles)
            {
                hasPending = _pendingFiles.Count > 0;
            }

            if (hasPending && _enabled)
            {
                _debounceTimer = new Timer(_ => ProcessPendingFiles(), null, 500, Timeout.Infinite);
            }
        }
    }

    private async Task ScanFileAsync(string file)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            if (!File.Exists(file)) return;
            if (IsExcluded(file)) return;

            FileScanned?.Invoke(file);

            var progress = new Progress<Models.ScanProgress>(_ => { });
            var result = await App.ClamAv.ScanAsync(new List<string> { file }, null, progress, cts.Token);

            if (cts.Token.IsCancellationRequested || result.Status == "Cancelled")
            {
                System.Diagnostics.Debug.WriteLine($"Scan for {file} was cancelled or timed out.");
                return;
            }

            Interlocked.Increment(ref _totalScanned);

            if (result.ThreatsFound > 0)
            {
                var threat = result.Threats.FirstOrDefault();
                string threatName = threat?.ThreatName ?? "Unknown Threat";

                // Quarantine the threat automatically
                await App.Quarantine.QuarantineFileAsync(file, threatName);

                ThreatDetected?.Invoke(file, threatName);
            }
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine($"Scan for {file} timed out.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {file}: {ex.Message}");
        }
    }

    private bool IsExcluded(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;

        // Default system exclusions
        if (path.IndexOf(@"\Windows\", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\$Recycle.Bin", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\AppData\Local\Microsoft\Windows\INetCache", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (path.IndexOf(baseDir + "quarantine", StringComparison.OrdinalIgnoreCase) >= 0) return true;

        string fileName = Path.GetFileName(path);
        if (fileName.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("dumpstack.log", StringComparison.OrdinalIgnoreCase)) return true;

        // Settings-based exclusions (same logic as ClamAvService)
        foreach (var pattern in _exclusionPatterns)
        {
            if (string.IsNullOrEmpty(pattern)) continue;
            if (path.Equals(pattern, StringComparison.OrdinalIgnoreCase)) return true;
            if (pattern.Contains('*') || pattern.Contains('?'))
            {
                if (WildcardMatch(path, pattern)) return true;
            }
            if (path.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) return true;
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
        return System.Text.RegularExpressions.Regex.IsMatch(input, regexPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private static void OnWatcherError(object sender, ErrorEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine($"FileWatcher error: {e.GetException().Message}");
    }

    public void Dispose()
    {
        Stop();
        _debounceTimer?.Dispose();
        _concurrencySemaphore.Dispose();
    }
}
