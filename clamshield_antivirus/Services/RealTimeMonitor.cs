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
    private class ScanItem
    {
        public string FilePath { get; }
        public long SequenceId { get; }

        public ScanItem(string filePath, long sequenceId)
        {
            FilePath = filePath;
            SequenceId = sequenceId;
        }
    }

    private readonly Queue<ScanItem> _scanQueue = new();
    private long _latestSeq = -1;
    private long _scanningSeq = -1;
    private CancellationTokenSource? _scanningCts;
    private string? _pendingFile;
    private long _pendingSeq = -1;
    private Task? _queueProcessorTask;
    private readonly SemaphoreSlim _queueSemaphore = new(0);

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
            _latestSeq = -1;
            _scanningSeq = -1;
            _pendingFile = null;
            _pendingSeq = -1;
            _scanQueue.Clear();
            _enabled = true;
            _queueProcessorTask = Task.Run(ProcessQueueAsync);
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
            _scanningCts?.Cancel();
            _scanningCts?.Dispose();
            _scanningCts = null;
            _scanningSeq = -1;
            _pendingFile = null;
            _pendingSeq = -1;
            _scanQueue.Clear();
        }

        _debounceTimer?.Dispose();
        _debounceTimer = null;

        try
        {
            _queueSemaphore.Release();
        }
        catch (ObjectDisposedException) { }
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (!_enabled) return;

        string filePath = e.FullPath;

        lock (_lock)
        {
            _latestSeq++;
            long n = _latestSeq;

            if (_scanningSeq != -1 && _scanningSeq <= n - 2)
            {
                System.Diagnostics.Debug.WriteLine($"Cancelling active scan (seq {_scanningSeq}) because new file (seq {n}) was detected: {filePath}");
                try
                {
                    _scanningCts?.Cancel();
                }
                catch (ObjectDisposedException) { }
            }

            _pendingFile = filePath;
            _pendingSeq = n;

            _debounceTimer?.Dispose();
            _debounceTimer = new Timer(_ => ProcessPending(), null, 1500, Timeout.Infinite);
        }
    }

    private void ProcessPending()
    {
        string? fileToQueue = null;
        long seqToQueue = -1;

        lock (_lock)
        {
            if (!_enabled || _pendingFile == null) return;

            fileToQueue = _pendingFile;
            seqToQueue = _pendingSeq;
            _pendingFile = null;
            _pendingSeq = -1;

            _scanQueue.Enqueue(new ScanItem(fileToQueue, seqToQueue));
            try
            {
                _queueSemaphore.Release();
            }
            catch (ObjectDisposedException) { }
        }
    }

    private async Task ProcessQueueAsync()
    {
        while (_enabled)
        {
            ScanItem? item = null;
            lock (_lock)
            {
                if (_scanQueue.Count > 0)
                {
                    item = _scanQueue.Dequeue();
                }
            }

            if (item == null)
            {
                try
                {
                    await _queueSemaphore.WaitAsync();
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                continue;
            }

            await ScanFileAsync(item);
        }
    }

    private async Task ScanFileAsync(ScanItem item)
    {
        CancellationTokenSource cts;
        lock (_lock)
        {
            if (!_enabled) return;

            long newestSeq = _latestSeq;
            if (item.SequenceId <= newestSeq - 2)
            {
                System.Diagnostics.Debug.WriteLine($"Skipping queue item {item.FilePath} (seq {item.SequenceId}) because newest is {newestSeq}");
                return;
            }

            _scanningSeq = item.SequenceId;
            _scanningCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            cts = _scanningCts;
        }

        try
        {
            string file = item.FilePath;
            if (!File.Exists(file)) return;
            if (IsExcluded(file)) return;

            FileScanned?.Invoke(file);

            var progress = new Progress<Models.ScanProgress>(_ => { });
            var result = await App.ClamAv.ScanAsync(new List<string> { file }, null, progress, cts.Token);

            if (cts.Token.IsCancellationRequested || result.Status == "Cancelled")
            {
                System.Diagnostics.Debug.WriteLine($"Scan for {file} (seq {item.SequenceId}) was cancelled.");
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
            System.Diagnostics.Debug.WriteLine($"Scan for {item.FilePath} (seq {item.SequenceId}) threw OperationCanceledException.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {item.FilePath}: {ex.Message}");
        }
        finally
        {
            lock (_lock)
            {
                if (_scanningSeq == item.SequenceId)
                {
                    _scanningSeq = -1;
                    _scanningCts?.Dispose();
                    _scanningCts = null;
                }
            }
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
            @"dumpstack.log",
            // Application startup path
            AppDomain.CurrentDomain.BaseDirectory+"\\quarantine",
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
        _queueSemaphore.Dispose();
        _debounceTimer?.Dispose();
    }
}
