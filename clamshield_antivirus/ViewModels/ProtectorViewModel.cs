using System;
using System.Linq;
using System.IO;
using System.Windows.Input;
using System.Windows.Threading;
using System.Collections.ObjectModel;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Services;
using clamshield_antivirus.Services.ScanSvc;

namespace clamshield_antivirus.ViewModels;

public class ProtectorViewModel : ViewModelBase
{
    private bool _isRunning;
    private int _totalScanned;
    private int _threatsBlocked;
    private string _currentStatusText = "Real-Time Protection Disabled";
    private string _statusColor = "#F38BA8"; // Red/Warning by default
    private string _protectionStatus = "disabled";
    private readonly Dispatcher _dispatcher;

    public bool IsRunning
    {
        get => _isRunning;
        set
        {
            if (SetProperty(ref _isRunning, value))
            {
                App.Settings.Set("RealtimeEnabled", value);
                if (value)
                    _ = StartSystemProtectionAsync();
                else
                    StopSystemProtection();
            }
        }
    }

    public int TotalScanned
    {
        get => _totalScanned;
        set => SetProperty(ref _totalScanned, value);
    }

    public int ThreatsBlocked
    {
        get => _threatsBlocked;
        set => SetProperty(ref _threatsBlocked, value);
    }

    public string CurrentStatusText
    {
        get => _currentStatusText;
        set => SetProperty(ref _currentStatusText, value);
    }

    public string StatusColor
    {
        get => _statusColor;
        set => SetProperty(ref _statusColor, value);
    }

    public string ProtectionStatus
    {
        get => _protectionStatus;
        set => SetProperty(ref _protectionStatus, value);
    }

    public ObservableCollection<string> MonitoredPaths { get; } = new();
    public ObservableCollection<string> ActivityLogs { get; } = new();

    public ICommand ToggleProtectionCommand { get; }

    public ProtectorViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        ToggleProtectionCommand = new RelayCommand(_ => IsRunning = !IsRunning);

        // Load current state
        _isRunning = App.RealTimeMonitor.IsRunning;
        UpdateStatusUI();

        TotalScanned = App.RealTimeMonitor.TotalScanned;
        UpdateMonitoredPaths();

        // Subscribe to real-time events
        App.RealTimeMonitor.FileScanned += OnFileScanned;
        App.RealTimeMonitor.ThreatDetected += OnThreatDetected;

        LogActivity("Protector Service Initialized.");
        if (IsRunning)
        {
            LogActivity("System-wide Real-Time Protection Shield Active.");
        }
        else
        {
            LogActivity("System-wide Real-Time Protection Shield Offline.");
        }
    }

    private async Task StartSystemProtectionAsync()
    {
        await _dispatcher.InvokeAsync(() =>
        {
            ProtectionStatus = "running";
            CurrentStatusText = "Starting Real-Time Protection...";
            StatusColor = "#F9E2AF"; // Amber
            LogActivity("Starting Real-Time Protection Shield...");
        });
        
        var exclusionPatterns = App.Settings.Get("RealtimeExclusions", string.Empty)
            .Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();

        await App.RealTimeMonitor.StartSystemWideAsync(exclusionPatterns);
        
        await _dispatcher.InvokeAsync(() =>
        {
            UpdateStatusUI();
            UpdateMonitoredPaths();
            LogActivity("Real-Time Protection Shield enabled. Monitoring all fixed system drives.");
        });
    }

    private void StopSystemProtection()
    {
        ProtectionStatus = "warning";
        CurrentStatusText = "Stopping Real-Time Protection...";
        StatusColor = "#F9E2AF"; // Amber
        LogActivity("Disabling Real-Time Protection Shield...");
        App.RealTimeMonitor.Stop();
        UpdateStatusUI();
        UpdateMonitoredPaths();
        LogActivity("Real-Time Protection Shield disabled. System is unprotected.");
    }

    private void UpdateStatusUI()
    {
        if (IsRunning)
        {
            ProtectionStatus = "protected";
            CurrentStatusText = "System Protected";
            StatusColor = "#A6E3A1"; // Green/SuccessColor
        }
        else
        {
            ProtectionStatus = "disabled";
            CurrentStatusText = "Real-Time Protection Disabled";
            StatusColor = "#F38BA8"; // Red/ErrorColor
        }
        OnPropertyChanged(nameof(IsRunning));
    }

    private void UpdateMonitoredPaths()
    {
        MonitoredPaths.Clear();
        foreach (var path in App.RealTimeMonitor.ActiveMonitoredPaths)
        {
            MonitoredPaths.Add(path);
        }
    }

    private void OnFileScanned(string filePath)
    {
        _dispatcher.BeginInvoke(() =>
        {
            TotalScanned = App.RealTimeMonitor.TotalScanned;
            LogActivity($"Scanned: {filePath}");
        });
    }

    private void OnThreatDetected(string filePath, string threatName)
    {
        _dispatcher.BeginInvoke(() =>
        {
            ThreatsBlocked++;
            LogActivity($"[WARNING] Blocked threat '{threatName}' in {filePath}");
        });
    }

    private void LogActivity(string message)
    {
        _dispatcher.BeginInvoke(() =>
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            ActivityLogs.Insert(0, $"[{timestamp}] {message}");

            // Limit log view list size to prevent memory issues
            while (ActivityLogs.Count > 100)
            {
                ActivityLogs.RemoveAt(ActivityLogs.Count - 1);
            }
        });
    }
}
