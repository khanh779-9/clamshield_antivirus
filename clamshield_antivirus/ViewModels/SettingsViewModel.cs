using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Services;

namespace clamshield_antivirus.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private readonly ContextMenuService _contextMenu = new();
    private readonly ScheduleService _schedule = new();
    private readonly StartupService _startup = new();
    private bool _contextMenuEnabled;
    private bool _startupEnabled;
    private bool _scheduleEnabled;
    private string _scheduleTime;
    private bool _scheduleWeekly;
    private int _scheduleDay;
    private bool _realtimeEnabled;
    private string _newWatchPath;
    private string _newExclusion;
    private int _realtimeScanned;
    private int _maxFileSizeMB;

    public bool ContextMenuEnabled
    {
        get => _contextMenuEnabled;
        set
        {
            if (SetProperty(ref _contextMenuEnabled, value))
            {
                App.Settings.Set("ContextMenuEnabled", value);
                if (value) _contextMenu.Register();
                else _contextMenu.Unregister();
            }
        }
    }

    public bool StartupEnabled
    {
        get => _startupEnabled;
        set
        {
            if (SetProperty(ref _startupEnabled, value))
            {
                App.Settings.Set("StartupEnabled", value);
                if (value) _startup.Register();
                else _startup.Unregister();
            }
        }
    }

    public bool ScheduleEnabled
    {
        get => _scheduleEnabled;
        set
        {
            if (SetProperty(ref _scheduleEnabled, value))
            {
                App.Settings.Set("ScheduleEnabled", value);
                if (value) ApplySchedule();
                else _schedule.Unschedule();
            }
        }
    }

    public string ScheduleTime
    {
        get => _scheduleTime;
        set
        {
            if (SetProperty(ref _scheduleTime, value))
            {
                App.Settings.Set("ScheduleTime", value);
                if (_scheduleEnabled) ApplySchedule();
            }
        }
    }

    public bool ScheduleWeekly
    {
        get => _scheduleWeekly;
        set
        {
            if (SetProperty(ref _scheduleWeekly, value))
            {
                App.Settings.Set("ScheduleWeekly", value);
                if (_scheduleEnabled) ApplySchedule();
            }
        }
    }

    public int ScheduleDay
    {
        get => _scheduleDay;
        set
        {
            if (SetProperty(ref _scheduleDay, value))
            {
                App.Settings.Set("ScheduleDay", value);
                if (_scheduleEnabled) ApplySchedule();
            }
        }
    }

    public bool RealtimeEnabled
    {
        get => _realtimeEnabled;
        set
        {
            if (SetProperty(ref _realtimeEnabled, value))
            {
                App.Settings.Set("RealtimeEnabled", value);
                if (value) StartMonitor();
                else StopMonitor();
            }
        }
    }

    public ObservableCollection<string> WatchFolders { get; } = new();
    public ObservableCollection<string> ExclusionPatterns { get; } = new();

    public string NewWatchPath
    {
        get => _newWatchPath;
        set => SetProperty(ref _newWatchPath, value);
    }

    public string NewExclusion
    {
        get => _newExclusion;
        set => SetProperty(ref _newExclusion, value);
    }

    public int RealtimeScanned
    {
        get => _realtimeScanned;
        set => SetProperty(ref _realtimeScanned, value);
    }

    public int MaxFileSizeMB
    {
        get => _maxFileSizeMB;
        set
        {
            if (SetProperty(ref _maxFileSizeMB, value))
            {
                long bytes = (long)value * 1024 * 1024;
                App.Settings.Set("MaxFileSize", bytes);
            }
        }
    }

    public ICommand AddWatchFolderCommand { get; }
    public ICommand RemoveWatchFolderCommand { get; }
    public ICommand BrowseWatchFolderCommand { get; }
    public ICommand AddExclusionCommand { get; }
    public ICommand RemoveExclusionCommand { get; }

    public SettingsViewModel()
    {
        _contextMenuEnabled = App.Settings.Get("ContextMenuEnabled", false) && _contextMenu.IsRegistered();
        _startupEnabled = App.Settings.Get("StartupEnabled", false) && _startup.IsRegistered();
        _scheduleEnabled = App.Settings.Get("ScheduleEnabled", false) && _schedule.IsScheduled();
        _scheduleTime = App.Settings.Get("ScheduleTime", "20:00");
        _scheduleWeekly = App.Settings.Get("ScheduleWeekly", true);
        _scheduleDay = App.Settings.Get("ScheduleDay", 0);
        _realtimeEnabled = App.RealTimeMonitor.IsRunning;
        _newWatchPath = string.Empty;
        _newExclusion = string.Empty;

        long maxFileBytes = App.Settings.Get("MaxFileSize", 104857600L);
        _maxFileSizeMB = (int)(maxFileBytes / (1024 * 1024));

        AddWatchFolderCommand = new RelayCommand(_ => AddWatchFolder());
        RemoveWatchFolderCommand = new RelayCommand(RemoveWatchFolder);
        BrowseWatchFolderCommand = new RelayCommand(_ => BrowseWatchFolder());
        AddExclusionCommand = new RelayCommand(_ => AddExclusion());
        RemoveExclusionCommand = new RelayCommand(RemoveExclusion);

        var saved = App.Settings.Get("WatchFolders", string.Empty);
        if (!string.IsNullOrEmpty(saved))
        {
            foreach (var dir in saved.Split('|', StringSplitOptions.RemoveEmptyEntries))
            {
                if (Directory.Exists(dir)) WatchFolders.Add(dir);
            }
        }

        if (WatchFolders.Count == 0)
        {
            WatchFolders.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            WatchFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        }

        var exclSaved = App.Settings.Get("RealtimeExclusions", string.Empty);
        if (!string.IsNullOrEmpty(exclSaved))
        {
            foreach (var p in exclSaved.Split('|', StringSplitOptions.RemoveEmptyEntries))
                ExclusionPatterns.Add(p);
        }
    }

    private void StartMonitor()
    {
        var dirs = new System.Collections.Generic.List<string>(WatchFolders);
        var exclusions = new System.Collections.Generic.List<string>(ExclusionPatterns);
        if (dirs.Count == 0)
        {
            _ = App.RealTimeMonitor.StartSystemWideAsync(exclusions);
        }
        else
        {
            _ = App.RealTimeMonitor.StartAsync(dirs, includeSubdirectories: false, exclusionPatterns: exclusions);
        }
        RealtimeScanned = 0;
    }

    private void StopMonitor()
    {
        App.RealTimeMonitor.Stop();
    }

    private void AddWatchFolder()
    {
        if (string.IsNullOrEmpty(_newWatchPath) || !Directory.Exists(_newWatchPath)) return;
        if (WatchFolders.Contains(_newWatchPath)) return;
        WatchFolders.Add(_newWatchPath);
        SaveWatchFolders();
        NewWatchPath = string.Empty;
        if (_realtimeEnabled) RestartMonitor();
    }

    private void RemoveWatchFolder(object? param)
    {
        if (param is string dir)
        {
            WatchFolders.Remove(dir);
            SaveWatchFolders();
            if (_realtimeEnabled) RestartMonitor();
        }
    }

    private void BrowseWatchFolder()
    {
        using var dialog = new System.Windows.Forms.FolderBrowserDialog();
        dialog.Description = "Select folder to monitor";
        if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            NewWatchPath = dialog.SelectedPath;
        }
    }

    private void RestartMonitor()
    {
        App.RealTimeMonitor.Stop();
        StartMonitor();
    }

    private void AddExclusion()
    {
        if (string.IsNullOrEmpty(_newExclusion)) return;
        if (ExclusionPatterns.Contains(_newExclusion)) return;
        ExclusionPatterns.Add(_newExclusion);
        SaveExclusions();
        NewExclusion = string.Empty;
        if (_realtimeEnabled) RestartMonitor();
    }

    private void RemoveExclusion(object? param)
    {
        if (param is string p)
        {
            ExclusionPatterns.Remove(p);
            SaveExclusions();
            if (_realtimeEnabled) RestartMonitor();
        }
    }

    private void SaveExclusions()
    {
        App.Settings.Set("RealtimeExclusions", string.Join("|", ExclusionPatterns));
    }

    private void SaveWatchFolders()
    {
        App.Settings.Set("WatchFolders", string.Join("|", WatchFolders));
    }



    private void ApplySchedule()
    {
        if (_scheduleWeekly)
        {
            string[] days = { "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT" };
            int idx = _scheduleDay % 7;
            _schedule.ScheduleWeekly(days[idx], _scheduleTime);
        }
        else
        {
            _schedule.ScheduleDaily(_scheduleTime);
        }
    }
}
