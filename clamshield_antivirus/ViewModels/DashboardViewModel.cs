using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows.Media;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

// ─── AuditItem: một mục kiểm tra bảo mật trong phần System Audit ───

public class AuditItem : ViewModelBase
{
    public string TitleKey { get; set; } = string.Empty;
    public string DescriptionKey { get; set; } = string.Empty;
    public object[] DescriptionArgs { get; set; } = Array.Empty<object>();
    public string Status { get; set; } = "unknown"; // pass, warning, fail
    public string SuggestionKey { get; set; } = string.Empty;
    public string FixCommandKey { get; set; } = string.Empty;

    public string Title => LocalizationService.Instance[TitleKey];
    public string Description => DescriptionArgs != null && DescriptionArgs.Length > 0
        ? string.Format(LocalizationService.Instance[DescriptionKey], DescriptionArgs)
        : LocalizationService.Instance[DescriptionKey];
    public string Suggestion => LocalizationService.Instance[SuggestionKey];
    public string FixCommand => LocalizationService.Instance[FixCommandKey];

    public void Refresh()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Description));
        OnPropertyChanged(nameof(Suggestion));
        OnPropertyChanged(nameof(FixCommand));
    }
}

// ─── DashboardViewModel: gộp SecurityStatus, Statistics, và Audit ───

public class DashboardViewModel : ViewModelBase
{
    private readonly MainViewModel _mainVm;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    // ── Security Status properties (from SecurityStatusViewModel) ──
    private string _statusState = "safe";
    private string _statusTitle = string.Empty;
    private string _statusMessage = string.Empty;
    private string _realtimeStatusText = string.Empty;
    private string _dbVersionText = string.Empty;
    private string _lastScanText = string.Empty;

    public string StatusState
    {
        get => _statusState;
        set
        {
            if (SetProperty(ref _statusState, value))
            {
                OnPropertyChanged(nameof(StatusColorBrush));
                OnPropertyChanged(nameof(StatusBgBrush));
                OnPropertyChanged(nameof(StatusBorderBrush));
                OnPropertyChanged(nameof(StatusSymbolBrush));
                OnPropertyChanged(nameof(StatusSymbolPath));
                
                // Synchronize with duplicate properties to avoid breaking any legacy XAML bindings
                ProtectionStatus = value == "safe" ? "clean" : (value == "danger" ? "infected" : value);

                // Dynamically update system tray icon & tooltip
                App.TrayService?.UpdateIconByState(value);
            }
        }
    }

    public string StatusTitle
    {
        get => _statusTitle;
        set
        {
            if (SetProperty(ref _statusTitle, value))
            {
                ProtectionStatusText = value;
            }
        }
    }

    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public string RealtimeStatusText { get => _realtimeStatusText; set => SetProperty(ref _realtimeStatusText, value); }
    public string DbVersionText { get => _dbVersionText; set => SetProperty(ref _dbVersionText, value); }
    public string LastScanText { get => _lastScanText; set => SetProperty(ref _lastScanText, value); }

    public bool IsDatabaseLoading => App.ClamAv.IsSignatureLoading;

    public SolidColorBrush StatusColorBrush => StatusState switch
    {
        "warning" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F59E0B")), // amber-500
        "danger" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444")),  // red-500
        "loading" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#3B82F6")), // blue-500
        _ => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#10B981"))         // emerald-500
    };

    public SolidColorBrush StatusBgBrush => StatusState switch
    {
        "warning" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#78350F")), // amber-900 / dark amber
        "danger" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#7F1D1D")),  // red-900 / dark red
        "loading" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#1E3A8A")), // blue-900 / dark blue
        _ => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#064E3B"))         // emerald-900 / dark green
    };

    public SolidColorBrush StatusBorderBrush => StatusColorBrush;
    public SolidColorBrush StatusSymbolBrush => new SolidColorBrush(Colors.White);

    public string StatusSymbolPath => StatusState switch
    {
        "warning" => "M 18,8 V 18 M 18,24 H 18.02", // Exclamation
        "danger" => "M 10,10 L 26,26 M 26,10 L 10,26", // X Cross
        _ => "M 6,17 L 14,25 L 30,9" // Checkmark
    };

    // ── Statistics properties ──
    private int _totalScans;
    private int _filesScanned;
    private int _threatsDetected;
    private string _avgDurationText = "00:00";
    private string _protectionStatusText = "Checking...";
    private string _protectionStatus = "unknown"; // clean, infected, warning, unknown
    private string _selectedTimeframe = "Weekly";
    private bool _isLoading;

    public int TotalScans { get => _totalScans; set => SetProperty(ref _totalScans, value); }
    public int FilesScanned { get => _filesScanned; set => SetProperty(ref _filesScanned, value); }
    public int ThreatsDetected { get => _threatsDetected; set => SetProperty(ref _threatsDetected, value); }
    public string AvgDurationText { get => _avgDurationText; set => SetProperty(ref _avgDurationText, value); }
    public string ProtectionStatusText { get => _protectionStatusText; set => SetProperty(ref _protectionStatusText, value); }
    public string ProtectionStatus { get => _protectionStatus; set => SetProperty(ref _protectionStatus, value); }

    public string SelectedTimeframe
    {
        get => _selectedTimeframe;
        set { if (SetProperty(ref _selectedTimeframe, value)) _ = LoadStatisticsAsync(); }
    }

    public bool IsLoading { get => _isLoading; set => SetProperty(ref _isLoading, value); }

    // ── Audit properties ──
    private bool _isAuditing;
    private string _summaryText = string.Empty;
    private int _issuesCount;

    public ObservableCollection<AuditItem> AuditItems { get; } = new();
    public bool IsAuditing { get => _isAuditing; set => SetProperty(ref _isAuditing, value); }
    public bool HasIssues => IssuesCount > 0;

    public string SummaryText
    {
        get => _summaryText;
        set => SetProperty(ref _summaryText, value);
    }

    public int IssuesCount
    {
        get => _issuesCount;
        set { if (SetProperty(ref _issuesCount, value)) OnPropertyChanged(nameof(HasIssues)); }
    }

    // ── Commands ──
    public ICommand SmartScanCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand RunAuditCommand { get; }

    public DashboardViewModel(MainViewModel mainVm)
    {
        _mainVm = mainVm;
        _summaryText = LocalizationService.Instance["Audit.CheckingPosture"];
        
        SmartScanCommand = new RelayCommand(TriggerSmartScan);
        RefreshCommand = new AsyncRelayCommand(async _ =>
        {
            await RefreshAllAsync();
            await RunAuditAsync();
        });
        RunAuditCommand = new AsyncRelayCommand(_ => RunAuditAsync());

        // Perform initial loads
        _ = Task.Run(async () =>
        {
            await RefreshAllAsync();
            await RunAuditAsync();
        });

        // Listen for language changes and refresh texts
        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                _ = RefreshAllAsync();
                foreach (var item in AuditItems) item.Refresh();
                UpdateSummaryText();
            }
        };

        // Listen for signature loading status changes
        App.ClamAv.SignatureLoadingStateChanged += (sender, args) =>
        {
            OnPropertyChanged(nameof(IsDatabaseLoading));
            _ = RefreshAllAsync();
        };

        // Listen for Real-Time Protection updates
        App.RealTimeMonitor.ProtectionStarted += () => _ = RefreshAllAsync();
        App.RealTimeMonitor.ProtectionStopped += () => _ = RefreshAllAsync();
    }

    private void TriggerSmartScan()
    {
        _mainVm.HandleProfileScanRequest("smart");
    }

    // ── Consolidated data loading — single I/O for status + statistics ──

    public async Task RefreshAllAsync()
    {
        if (!await _refreshLock.WaitAsync(0)) return; // Skip if already refreshing
        try
        {
            IsLoading = true;

            // Load logs and quarantine ONCE
            var logs = await App.Logs.GetLogsAsync();
            var quarantine = await App.Quarantine.GetAllEntriesAsync();
            int quarantineCount = quarantine.Count;

            UpdateStatus(logs, quarantineCount);
            UpdateStatistics(logs);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to refresh dashboard: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
            _refreshLock.Release();
        }
    }

    // Keep public wrappers for external callers that only need status
    public async Task LoadStatusAsync() => await RefreshAllAsync();
    public async Task LoadStatisticsAsync() => await RefreshAllAsync();

    private void UpdateStatus(List<Models.LogEntry> logs, int quarantineCount)
    {
        try
        {
            bool realtimeEnabled = App.Settings.Get("RealtimeEnabled", false);
            bool engineReady = App.Engine != null;

            var scanLogs = logs
                .Where(l => l.Type.Equals("Scan", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(l => l.Timestamp)
                .ToList();
            var lastScan = scanLogs.FirstOrDefault();

            // Determine State
            if (IsDatabaseLoading)
            {
                StatusState = "loading";
                StatusTitle = LocalizationService.Instance["SecurityStatus.TitleLoading"];
                StatusMessage = LocalizationService.Instance["SecurityStatus.MessageLoading"];
            }
            else if (!engineReady)
            {
                StatusState = "danger";
                StatusTitle = LocalizationService.Instance["SecurityStatus.DangerStatus"];
                StatusMessage = LocalizationService.Instance["Audit.EngineFailed"];
            }
            else if (quarantineCount > 0)
            {
                StatusState = "danger";
                StatusTitle = LocalizationService.Instance["SecurityStatus.DangerStatus"];
                StatusMessage = string.Format(LocalizationService.Instance["SecurityStatus.ThreatsDetectedText"], quarantineCount);
            }
            else if (!realtimeEnabled)
            {
                StatusState = "warning";
                StatusTitle = LocalizationService.Instance["SecurityStatus.WarningStatus"];
                StatusMessage = LocalizationService.Instance["SecurityStatus.StatusDisabled"];
            }
            else if (lastScan == null)
            {
                StatusState = "warning";
                StatusTitle = LocalizationService.Instance["SecurityStatus.WarningStatus"];
                StatusMessage = LocalizationService.Instance["SecurityStatus.NeverScanned"];
            }
            else if (lastScan.Timestamp < DateTime.Now.AddDays(-7))
            {
                StatusState = "warning";
                StatusTitle = LocalizationService.Instance["SecurityStatus.WarningStatus"];
                StatusMessage = LocalizationService.Instance["Statistics.StatusOutdatedScan"];
            }
            else
            {
                StatusState = "safe";
                StatusTitle = LocalizationService.Instance["SecurityStatus.SafeStatus"];
                StatusMessage = LocalizationService.Instance["SecurityStatus.NoThreatsText"];
            }

            // Checklist details
            RealtimeStatusText = realtimeEnabled 
                ? LocalizationService.Instance["SecurityStatus.StatusActive"] 
                : LocalizationService.Instance["SecurityStatus.StatusDisabled"];

            var dbUpdateTime = App.Settings.Get("LastDatabaseUpdateTime", string.Empty);
            DbVersionText = string.IsNullOrEmpty(dbUpdateTime)
                ? LocalizationService.Instance["Database.NeverUpdated"]
                : dbUpdateTime;

            LastScanText = lastScan != null
                ? lastScan.Timestamp.ToString("yyyy-MM-dd HH:mm")
                : LocalizationService.Instance["Database.NeverUpdated"];
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to update security status: {ex.Message}");
        }
    }

    private void UpdateStatistics(List<Models.LogEntry> logs)
    {
        try
        {
            var scanLogs = logs.Where(l => l.Type == "Scan").ToList();

            DateTime cutoff = SelectedTimeframe switch
            {
                "Daily" => DateTime.Now.AddDays(-1),
                "Weekly" => DateTime.Now.AddDays(-7),
                "Monthly" => DateTime.Now.AddMonths(-1),
                _ => DateTime.MinValue
            };

            var filteredLogs = cutoff == DateTime.MinValue
                ? scanLogs
                : scanLogs.Where(l => l.Timestamp >= cutoff).ToList();

            TotalScans = filteredLogs.Count;
            int totalFiles = 0;
            int totalThreats = 0;
            double totalSeconds = 0;
            int secondsCount = 0;

            foreach (var log in filteredLogs)
            {
                var fileMatch = Regex.Match(log.Details, @"Scanned files:\s+(\d+)");
                if (fileMatch.Success) totalFiles += int.Parse(fileMatch.Groups[1].Value);

                var threatMatch = Regex.Match(log.Details, @"Infected files:\s+(\d+)");
                if (threatMatch.Success) totalThreats += int.Parse(threatMatch.Groups[1].Value);

                var timeMatch = Regex.Match(log.Details, @"Time:\s+([\d\.]+)\s+sec");
                if (timeMatch.Success)
                {
                    totalSeconds += double.Parse(timeMatch.Groups[1].Value);
                    secondsCount++;
                }
            }

            FilesScanned = totalFiles;
            ThreatsDetected = totalThreats;
            AvgDurationText = secondsCount > 0
                ? TimeSpan.FromSeconds(totalSeconds / secondsCount).ToString(@"mm\:ss")
                : "00:00";
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to update statistics: {ex.Message}");
        }
    }

    // ── Audit logic ──

    private void UpdateSummaryText()
    {
        if (IsAuditing)
        {
            SummaryText = LocalizationService.Instance["Audit.RunningChecks"];
            return;
        }
        SummaryText = IssuesCount == 0
            ? LocalizationService.Instance["Audit.AllPassed"]
            : string.Format(LocalizationService.Instance["Audit.IssuesFound"], IssuesCount);
    }

    public async Task RunAuditAsync()
    {
        IsAuditing = true;
        SummaryText = LocalizationService.Instance["Audit.RunningChecks"];
        AuditItems.Clear();
        int issues = 0;

        try
        {
            await Task.Run(() =>
            {
                bool engineReady = App.Engine != null;
                var clamItem = new AuditItem
                {
                    TitleKey = "Audit.EngineTitle",
                    DescriptionKey = engineReady ? "Audit.EngineReady" : "Audit.EngineFailed",
                    Status = engineReady ? "pass" : "fail",
                    SuggestionKey = engineReady ? "Audit.EngineReadySuggestion" : "Audit.EngineFailedSuggestion",
                    FixCommandKey = "Audit.EngineFix"
                };
                if (!engineReady) issues++;

                bool definitionsActive = false;
                string dbDescKey = "Audit.DbMissing";
                object[] dbArgs = Array.Empty<object>();
                string localDbDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "database");

                var pathsToTry = new[]
                {
                    Path.Combine(localDbDir, "daily.cvd"),
                    Path.Combine(localDbDir, "main.cvd"),
                    Path.Combine(localDbDir, "bytecode.cvd"),
                    Path.Combine(localDbDir, "windows.cvd")
                };

                foreach (var path in pathsToTry)
                {
                    if (File.Exists(path))
                    {
                        var lastWrite = File.GetLastWriteTime(path);
                        definitionsActive = lastWrite > DateTime.Now.AddDays(-7);
                        dbDescKey = definitionsActive ? "Audit.DbActive" : "Audit.DbOutdated";
                        dbArgs = new object[] { lastWrite.ToString("yyyy-MM-dd HH:mm") };
                        break;
                    }
                }

                var dbItem = new AuditItem
                {
                    TitleKey = "Audit.DbTitle",
                    DescriptionKey = dbDescKey,
                    DescriptionArgs = dbArgs,
                    Status = definitionsActive ? "pass" : "warning",
                    SuggestionKey = definitionsActive ? "Audit.DbActiveSuggestion" : "Audit.DbOutdatedSuggestion",
                    FixCommandKey = "Audit.DbFix"
                };
                if (!definitionsActive) issues++;

                bool defenderRunning = IsServiceRunning("WinDefend");
                var defenderItem = new AuditItem
                {
                    TitleKey = "Audit.DefenderTitle",
                    DescriptionKey = defenderRunning ? "Audit.DefenderActive" : "Audit.DefenderInactive",
                    Status = defenderRunning ? "pass" : "warning",
                    SuggestionKey = defenderRunning ? "Audit.DefenderActiveSuggestion" : "Audit.DefenderInactiveSuggestion",
                    FixCommandKey = "powershell Start-Service WinDefend"
                };
                if (!defenderRunning) issues++;

                bool firewallRunning = IsServiceRunning("MpsSvc");
                var firewallItem = new AuditItem
                {
                    TitleKey = "Audit.FirewallTitle",
                    DescriptionKey = firewallRunning ? "Audit.FirewallActive" : "Audit.FirewallInactive",
                    Status = firewallRunning ? "pass" : "fail",
                    SuggestionKey = firewallRunning ? "Audit.FirewallActiveSuggestion" : "Audit.FirewallInactiveSuggestion",
                    FixCommandKey = "powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
                };
                if (!firewallRunning) issues++;

                App.Current.Dispatcher.Invoke(() =>
                {
                    AuditItems.Add(clamItem);
                    AuditItems.Add(dbItem);
                    AuditItems.Add(defenderItem);
                    AuditItems.Add(firewallItem);
                });
            });

            IssuesCount = issues;
            UpdateSummaryText();
        }
        catch (Exception ex)
        {
            SummaryText = LocalizationService.Instance["Audit.AbortedError"];
            Debug.WriteLine($"Failed executing system audit: {ex.Message}");
        }
        finally
        {
            IsAuditing = false;
        }
    }

    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {serviceName}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output.Contains("RUNNING");
            }
        }
        catch { }
        return false;
    }
}