using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Media;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class SecurityStatusViewModel : ViewModelBase
{
    private readonly MainViewModel _mainVm;
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
                
                // Dynamically update system tray icon & tooltip
                App.TrayService?.UpdateIconByState(value);
            }
        }
    }

    public string StatusTitle
    {
        get => _statusTitle;
        set => SetProperty(ref _statusTitle, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string RealtimeStatusText
    {
        get => _realtimeStatusText;
        set => SetProperty(ref _realtimeStatusText, value);
    }

    public string DbVersionText
    {
        get => _dbVersionText;
        set => SetProperty(ref _dbVersionText, value);
    }

    public string LastScanText
    {
        get => _lastScanText;
        set => SetProperty(ref _lastScanText, value);
    }

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

    public SolidColorBrush StatusSymbolBrush => new SolidColorBrush(System.Windows.Media.Colors.White);

    public string StatusSymbolPath => StatusState switch
    {
        "warning" => "M 18,8 V 18 M 18,24 H 18.02", // Exclamation
        "danger" => "M 10,10 L 26,26 M 26,10 L 10,26", // X Cross
        _ => "M 6,17 L 14,25 L 30,9" // Checkmark
    };

    public ICommand SmartScanCommand { get; }

    public SecurityStatusViewModel(MainViewModel mainVm)
    {
        _mainVm = mainVm;
        SmartScanCommand = new RelayCommand(TriggerSmartScan);

        _ = LoadStatusAsync();

        // Listen for language changes and refresh texts
        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                _ = LoadStatusAsync();
            }
        };

        // Listen for signature loading status changes
        App.ClamAv.SignatureLoadingStateChanged += (sender, args) =>
        {
            OnPropertyChanged(nameof(IsDatabaseLoading));
            _ = LoadStatusAsync();
        };
    }

    private void TriggerSmartScan()
    {
        _mainVm.HandleProfileScanRequest("smart");
    }

    public async Task LoadStatusAsync()
    {
        try
        {
            // 1. Fetch system states
            bool realtimeEnabled = App.Settings.Get("RealtimeProtectionEnabled", false);
            bool engineReady = App.Engine != null;

            // 2. Fetch logs and last scan
            var logs = await App.Logs.GetLogsAsync();
            var scanLogs = logs
                .Where(l => l.Type.Equals("Scan", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(l => l.Timestamp)
                .ToList();
            var lastScan = scanLogs.FirstOrDefault();

            // 3. Fetch quarantine count
            var quarantine = await App.Quarantine.GetAllEntriesAsync();
            int quarantineCount = quarantine.Count;

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
            System.Diagnostics.Debug.WriteLine($"Failed to load security status details: {ex.Message}");
        }
    }
}
