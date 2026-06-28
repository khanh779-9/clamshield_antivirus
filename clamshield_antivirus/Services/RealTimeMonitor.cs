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
    private readonly HashSet<string> _pending = new();
    private readonly object _lock = new();
    private Timer? _debounceTimer;
    private bool _enabled;
    private int _totalScanned;
    private List<string> _exclusionPatterns = new();

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

    public async Task StartAsync(IEnumerable<string> directories, bool includeSubdirectories = false, List<string>? exclusionPatterns = null)
    {
        _exclusionPatterns = exclusionPatterns ?? new List<string>();
        Stop();

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

        _enabled = true;
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

        lock (_watchers)
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _watchers.Clear();
        }

        lock (_lock) _pending.Clear();
        _debounceTimer?.Dispose();
        _debounceTimer = null;
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (!_enabled) return;

        lock (_lock)
        {
            _pending.Add(e.FullPath);
            _debounceTimer?.Dispose();
            _debounceTimer = new Timer(_ => ProcessPending(), null, 1500, Timeout.Infinite);
        }
    }

    private void ProcessPending()
    {
        List<string> files;
        lock (_lock)
        {
            files = _pending.ToList();
            _pending.Clear();
        }

        foreach (var file in files)
        {
            try
            {
                if (!File.Exists(file)) continue;
                if (IsExcluded(file)) continue;

                FileScanned?.Invoke(file);

                // Run ScanAsync on background thread
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                        var progress = new Progress<Models.ScanProgress>(_ => { });
                        var result = await App.ClamAv.ScanAsync(new List<string> { file }, null, progress, cts.Token);
                        
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
                    catch { }
                });
            }
            catch { }
        }
    }

    private bool IsExcluded(string path)
    {
        // Default system exclusions to avoid performance bottlenecks
        var systemExclusions = new[]
        {
            @"\Windows\",
            @"\$Recycle.Bin",
            @"\System Volume Information",
            @"\AppData\Local\Temp",
            @"\AppData\Local\Microsoft\Windows\INetCache",
            @"pagefile.sys",
            @"hiberfil.sys",
            @"swapfile.sys",
            @"dumpstack.log"
        };

        foreach (var exclude in systemExclusions)
        {
            if (path.IndexOf(exclude, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        foreach (var pattern in _exclusionPatterns)
        {
            if (string.IsNullOrEmpty(pattern)) continue;
            if (path.Equals(pattern, StringComparison.OrdinalIgnoreCase)) return true;
            if (path.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        }
        return false;
    }

    private static void OnWatcherError(object sender, ErrorEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine($"FileWatcher error: {e.GetException().Message}");
    }

    public void Dispose()
    {
        Stop();
        _debounceTimer?.Dispose();
    }
}
