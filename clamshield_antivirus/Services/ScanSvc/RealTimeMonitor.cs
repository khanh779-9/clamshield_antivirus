using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using clamshield_antivirus.Services;

namespace clamshield_antivirus.Services.ScanSvc;

public class RealTimeMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly object _lock = new();
    private Timer? _debounceTimer;
    private Timer? _processScanTimer;
    private readonly HashSet<int> _knownProcessIds = new();
    private bool _enabled;
    private int _totalScanned;
    private List<string> _exclusionPatterns = new();

    // Fields for refined real-time scanning
    private readonly Dictionary<string, DateTime> _pendingFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _concurrencySemaphore = new(8);

    private static readonly HashSet<string> OptimizedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".cpl", ".ocx", ".ax", // PE binaries
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sh", // Scripts / Batch
        ".msi", ".msp", ".mst", // Installers
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm", ".rtf", // Office & PDF documents
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".cab", ".iso", ".img", // Archives & Disk images
        ".jar", ".class", // Java
        ".htm", ".html", ".xhtml", // Web documents
        ".lnk", ".inf", ".reg" // Windows files
    };

    private readonly HashSet<string> _customExtensions = new(StringComparer.OrdinalIgnoreCase);

    public void UpdateCustomExtensions(string customExtensionsStr)
    {
        lock (_lock)
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
            lock (_knownProcessIds)
            {
                _knownProcessIds.Clear();
                try
                {
                    foreach (var p in System.Diagnostics.Process.GetProcesses())
                    {
                        _knownProcessIds.Add(p.Id);
                        p.Dispose();
                    }
                }
                catch { }
            }
            _enabled = true;
            _processScanTimer = new Timer(_ => CheckNewProcesses(), null, 1000, 1000);
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
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.LastAccess,
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
            _processScanTimer?.Dispose();
            _processScanTimer = null;

            lock (_knownProcessIds)
            {
                _knownProcessIds.Clear();
            }

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
        QueueFileForScan(e.FullPath);
    }

    private void QueueFileForScan(string filePath)
    {
        // Filter by extension if optimized scanning is enabled
        if (!App.Settings.Get("RealtimeScanAllExtensions", false))
        {
            string ext = Path.GetExtension(filePath);
            if (string.IsNullOrEmpty(ext)) return;

            bool match = OptimizedExtensions.Contains(ext);
            if (!match)
            {
                lock (_lock)
                {
                    match = _customExtensions.Contains(ext);
                }
            }

            if (!match) return;
        }

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

    private void CheckNewProcesses()
    {
        if (!_enabled) return;

        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == IntPtr.Zero) return;

        try
        {
            var pe32 = new PROCESSENTRY32();
            pe32.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (!Process32First(hSnapshot, ref pe32)) return;

            var currentIds = new HashSet<int>();
            var newProcessIds = new List<uint>();

            lock (_knownProcessIds)
            {
                do
                {
                    int pid = (int)pe32.th32ProcessID;
                    currentIds.Add(pid);

                    if (!_knownProcessIds.Contains(pid))
                    {
                        newProcessIds.Add(pe32.th32ProcessID);
                        _knownProcessIds.Add(pid);
                    }
                } while (Process32Next(hSnapshot, ref pe32));

                // Clean up dead process IDs
                _knownProcessIds.RemoveWhere(id => !currentIds.Contains(id));
            }

            // Scan the executable paths of new processes
            foreach (uint pid in newProcessIds)
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hProcess != IntPtr.Zero)
                {
                    try
                    {
                        var sb = new System.Text.StringBuilder(1024);
                        uint size = (uint)sb.Capacity;
                        if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                        {
                            string path = sb.ToString();
                            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                            {
                                QueueFileForScan(path);
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error checking running processes via native APIs: {ex.Message}");
        }
        finally
        {
            CloseHandle(hSnapshot);
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

    #region Win32 Process Snapshot P/Invoke
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
    #endregion
}
