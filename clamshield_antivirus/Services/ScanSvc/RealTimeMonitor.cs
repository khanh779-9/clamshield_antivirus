using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Management;

using clamshield_antivirus.Services;

namespace clamshield_antivirus.Services.ScanSvc;

public class RealTimeMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private Timer? _debounceTimer;
    private ManagementEventWatcher? _processWatcher;
    private bool _enabled;
    private int _totalScanned;
    private List<string> _exclusionPatterns = new();

    private readonly Queue<string> _pendingFiles = new();
    private readonly HashSet<string> _pendingSet = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _cooldownCache = new(StringComparer.OrdinalIgnoreCase);
    private const int PendingMax = 2000;
    private const int CooldownMax = 5000;

    private readonly SemaphoreSlim _concurrencySemaphore = new(2);

    private static readonly HashSet<string> TargetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".cpl", ".ocx", ".ax",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sh",
        ".msi", ".msp", ".mst",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm", ".rtf",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".cab", ".iso", ".img",
        ".jar", ".class",
        ".htm", ".html", ".xhtml",
        ".lnk", ".inf", ".reg"
    };

    private readonly HashSet<string> _customExtensions = new(StringComparer.OrdinalIgnoreCase);

    public void UpdateCustomExtensions(string customExtensionsStr)
    {
        lock (_customExtensions)
        {
            _customExtensions.Clear();
            if (string.IsNullOrWhiteSpace(customExtensionsStr)) return;
            var parts = customExtensionsStr.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                string ext = part.Trim();
                if (string.IsNullOrEmpty(ext)) continue;
                if (!ext.StartsWith(".")) ext = "." + ext;
                _customExtensions.Add(ext);
            }
        }
    }

    public bool IsRunning => _enabled;
    public int TotalScanned => _totalScanned;
    public int PendingCount { get; private set; }

    public List<string> ActiveMonitoredPaths
    {
        get
        {
            lock (_watchers) { return _watchers.Select(w => w.Path).ToList(); }
        }
    }

    public event Action<string>? FileScanned;
    public event Action<string, string>? ThreatDetected;
    public event Action? ProtectionStarted;
    public event Action? ProtectionStopped;

    public Task StartAsync(IEnumerable<string> directories, bool includeSubdirectories = false, List<string>? exclusionPatterns = null)
    {
        _exclusionPatterns = exclusionPatterns ?? new List<string>();
        return Task.Run(() =>
        {
            Stop();

            _enabled = true;

            foreach (var dir in directories)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    var watcher = new FileSystemWatcher
                    {
                        Path = dir,
                        IncludeSubdirectories = includeSubdirectories,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                        Filter = "*.*",
                        InternalBufferSize = 65536
                    };
                    watcher.Created += OnFileChanged;
                    watcher.Changed += OnFileChanged;
                    watcher.Error += OnWatcherError;
                    watcher.EnableRaisingEvents = true;
                    lock (_watchers) { _watchers.Add(watcher); }
                }
                catch { }
            }

            _ = FireProtectionStartedAsync();
        });
    }

    public Task StartSystemWideAsync(List<string>? exclusionPatterns = null)
    {
        _exclusionPatterns = exclusionPatterns ?? new List<string>();
        return Task.Run(() =>
        {
            Stop();

            string[] fixedDrives;
            try
            {
                fixedDrives = DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Fixed && d.RootDirectory.FullName != null)
                    .Select(d => d.RootDirectory.FullName)
                    .ToArray();
            }
            catch { fixedDrives = new[] { "C:\\" }; }

            _enabled = true;

            foreach (var root in fixedDrives)
            {
                try
                {
                    var watcher = new FileSystemWatcher
                    {
                        Path = root,
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                        Filter = "*.*",
                        InternalBufferSize = 65536
                    };
                    watcher.Created += OnFileChanged;
                    watcher.Changed += OnFileChanged;
                    watcher.Error += OnWatcherError;
                    watcher.EnableRaisingEvents = true;
                    lock (_watchers) { _watchers.Add(watcher); }
                }
                catch { }
            }

            StartProcessMonitor();
            _ = FireProtectionStartedAsync();
        });
    }

    private Task FireProtectionStartedAsync()
    {
        return Task.Run(async () =>
        {
            try
            {
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    ProtectionStarted?.Invoke());
            }
            catch { }
        });
    }

    private void StartProcessMonitor()
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _processWatcher = new ManagementEventWatcher(query);
            _processWatcher.EventArrived += OnProcessStarted;
            _processWatcher.Start();
        }
        catch { }
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        if (!_enabled) return;
        try
        {
            uint pid = (uint)e.NewEvent.Properties["ProcessID"].Value;
            string? processName = e.NewEvent.Properties["ProcessName"].Value as string;
            if (string.IsNullOrEmpty(processName)) return;

            string? fullPath = ResolveProcessPath(pid, processName);
            if (!string.IsNullOrEmpty(fullPath) && File.Exists(fullPath))
                EnqueueFile(fullPath);
        }
        catch { }
    }

    private static string? ResolveProcessPath(uint pid, string? processName)
    {
        if (string.IsNullOrEmpty(processName)) return null;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess != IntPtr.Zero)
        {
            try
            {
                var sb = new System.Text.StringBuilder(1024);
                uint size = (uint)sb.Capacity;
                if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                    return sb.ToString();
            }
            finally { CloseHandle(hProcess); }
        }

        return SearchPathEnvironment(processName);
    }

    private static string? SearchPathEnvironment(string fileName)
    {
        try
        {
            string? pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (pathEnv == null) return null;
            foreach (var p in pathEnv.Split(Path.PathSeparator))
            {
                string full = Path.Combine(p.Trim(), fileName);
                if (File.Exists(full)) return full;
            }
        }
        catch { }
        return null;
    }

    public void Stop()
    {
        _enabled = false;
        ProtectionStopped?.Invoke();

        lock (_watchers)
        {
            foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
            _watchers.Clear();
        }

        try { _processWatcher?.Stop(); } catch { }
        _processWatcher?.Dispose();
        _processWatcher = null;

        _debounceTimer?.Dispose();
        _debounceTimer = null;

        lock (_pendingFiles) { _pendingFiles.Clear(); _pendingSet.Clear(); }
        lock (_cooldownCache) { _cooldownCache.Clear(); }
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (!_enabled) return;
        if (IsExcluded(e.FullPath)) return;
        if (IsInCooldown(e.FullPath)) return;

        bool scanAll = App.Settings.Get("RealtimeScanAllExtensions", false);
        if (!scanAll)
        {
            string ext = Path.GetExtension(e.FullPath);
            if (string.IsNullOrEmpty(ext)) return;
            if (!TargetExtensions.Contains(ext))
            {
                lock (_customExtensions) { if (!_customExtensions.Contains(ext)) return; }
            }
        }

        EnqueueFile(e.FullPath);
    }

    private bool IsInCooldown(string path)
    {
        lock (_cooldownCache) { return _cooldownCache.Contains(path); }
    }

    private void EnqueueFile(string path)
    {
        lock (_pendingFiles)
        {
            if (_pendingSet.Contains(path)) return;
            if (_pendingFiles.Count >= PendingMax) return;

            _pendingFiles.Enqueue(path);
            _pendingSet.Add(path);
            PendingCount = _pendingFiles.Count;
        }

        lock (this)
        {
            if (_debounceTimer == null)
                _debounceTimer = new Timer(_ => DrainQueue(), null, 1000, Timeout.Infinite);
        }
    }

    private void DrainQueue()
    {
        string[] batch;
        lock (_pendingFiles)
        {
            batch = _pendingFiles.ToArray();
            _pendingFiles.Clear();
            _pendingSet.Clear();
            PendingCount = 0;
        }

        foreach (var file in batch)
        {
            _ = Task.Run(async () =>
            {
                await _concurrencySemaphore.WaitAsync();
                try { await ScanFileAsync(file); }
                finally { _concurrencySemaphore.Release(); }
            });
        }

        lock (this)
        {
            _debounceTimer?.Dispose();
            _debounceTimer = null;

            bool hasPending;
            lock (_pendingFiles) { hasPending = _pendingFiles.Count > 0; }
            if (hasPending && _enabled)
                _debounceTimer = new Timer(_ => DrainQueue(), null, 1000, Timeout.Infinite);
        }
    }

    private async Task ScanFileAsync(string file)
    {
        if (!_enabled) return;
        if (!File.Exists(file)) return;
        if (IsExcluded(file)) return;

        AddCooldown(file);

        try
        {
            FileScanned?.Invoke(file);

            var progress = new Progress<Models.ScanProgress>(_ => { });
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var result = await App.ClamAv.ScanAsync(new List<string> { file }, null, progress, cts.Token);

            if (result.Status == "Cancelled") return;

            Interlocked.Increment(ref _totalScanned);

            if (result.ThreatsFound > 0)
            {
                var threat = result.Threats.FirstOrDefault();
                string threatName = threat?.ThreatName ?? "Unknown Threat";
                await App.Quarantine.QuarantineFileAsync(file, threatName);
                ThreatDetected?.Invoke(file, threatName);
            }
        }
        catch { }
    }

    private void AddCooldown(string path)
    {
        lock (_cooldownCache)
        {
            _cooldownCache.Add(path);
            if (_cooldownCache.Count > CooldownMax)
            {
                _cooldownCache.Clear();
            }
        }
    }

    private bool IsExcluded(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;

        if (path.IndexOf(@"\Windows\", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\$Recycle.Bin", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (path.IndexOf(@"\AppData\Local\Microsoft\Windows\INetCache", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (path.IndexOf(baseDir + "quarantine", StringComparison.OrdinalIgnoreCase) >= 0) return true;

        string fileName = Path.GetFileName(path);
        if (fileName.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("dumpstack.log", StringComparison.OrdinalIgnoreCase)) return true;

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
    }

    public void Dispose()
    {
        Stop();
        _debounceTimer?.Dispose();
        _concurrencySemaphore.Dispose();
    }

    #region Win32 P/Invoke
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);
    #endregion
}
