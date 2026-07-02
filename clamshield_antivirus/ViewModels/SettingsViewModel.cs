using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using System.Windows;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Services;

namespace clamshield_antivirus.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    public string AppVersion => "v1.1.0";
    public string EngineVersion => "ClamAV C# Core Engine (Optimized)";
    public string CopyrightText => $"© {DateTime.Now.Year} ClamUI Project. Open Source under GPL v2.";
    public string DatabaseInfo => "CVD của ClamAV";
    public string Author => "Khanh Tran";
    public string GithubUrl => "https://github.com/khanh779-9";
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
    private bool _allMatchMode;
    private bool _heuristicAlerts;
    private bool _alertPua;
    private bool _alertPdf;
    private bool _alertMacros;
    private bool _alertSwf;
    private bool _parseArchives;
    private bool _parsePe;
    private bool _parsePdf;
    private bool _parseMail;
    private bool _parseOle2;
    private bool _parseHtml;
    private bool _parseElf;
    private bool _parseSwf;
    private bool _parseRtf;
    private bool _realtimeScanAll;
    private bool _realtimeScanOptimized;
    private string _realtimeCustomExtensions = string.Empty;

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

    public bool AllMatchMode
    {
        get => _allMatchMode;
        set
        {
            if (SetProperty(ref _allMatchMode, value))
                App.Settings.Set("AllMatchMode", value);
        }
    }

    public bool HeuristicAlerts
    {
        get => _heuristicAlerts;
        set
        {
            if (SetProperty(ref _heuristicAlerts, value))
                App.Settings.Set("HeuristicAlerts", value);
        }
    }

    public bool AlertPua
    {
        get => _alertPua;
        set
        {
            if (SetProperty(ref _alertPua, value))
                App.Settings.Set("AlertPua", value);
        }
    }

    public bool AlertPdf
    {
        get => _alertPdf;
        set
        {
            if (SetProperty(ref _alertPdf, value))
                App.Settings.Set("AlertPdf", value);
        }
    }

    public bool AlertMacros
    {
        get => _alertMacros;
        set
        {
            if (SetProperty(ref _alertMacros, value))
                App.Settings.Set("AlertMacros", value);
        }
    }

    public bool AlertSwf
    {
        get => _alertSwf;
        set
        {
            if (SetProperty(ref _alertSwf, value))
                App.Settings.Set("AlertSwf", value);
        }
    }

    public bool ParseArchives
    {
        get => _parseArchives;
        set
        {
            if (SetProperty(ref _parseArchives, value))
                App.Settings.Set("ParseArchives", value);
        }
    }

    public bool ParsePe
    {
        get => _parsePe;
        set
        {
            if (SetProperty(ref _parsePe, value))
                App.Settings.Set("ParsePe", value);
        }
    }

    public bool ParsePdf
    {
        get => _parsePdf;
        set
        {
            if (SetProperty(ref _parsePdf, value))
                App.Settings.Set("ParsePdf", value);
        }
    }

    public bool ParseMail
    {
        get => _parseMail;
        set
        {
            if (SetProperty(ref _parseMail, value))
                App.Settings.Set("ParseMail", value);
        }
    }

    public bool ParseOle2
    {
        get => _parseOle2;
        set
        {
            if (SetProperty(ref _parseOle2, value))
                App.Settings.Set("ParseOle2", value);
        }
    }

    public bool ParseHtml
    {
        get => _parseHtml;
        set
        {
            if (SetProperty(ref _parseHtml, value))
                App.Settings.Set("ParseHtml", value);
        }
    }

    public bool ParseElf
    {
        get => _parseElf;
        set
        {
            if (SetProperty(ref _parseElf, value))
                App.Settings.Set("ParseElf", value);
        }
    }

    public bool ParseSwf
    {
        get => _parseSwf;
        set
        {
            if (SetProperty(ref _parseSwf, value))
                App.Settings.Set("ParseSwf", value);
        }
    }

    public bool ParseRtf
    {
        get => _parseRtf;
        set
        {
            if (SetProperty(ref _parseRtf, value))
                App.Settings.Set("ParseRtf", value);
        }
    }

    public bool RealtimeScanAll
    {
        get => _realtimeScanAll;
        set
        {
            if (SetProperty(ref _realtimeScanAll, value))
            {
                App.Settings.Set("RealtimeScanAllExtensions", value);
                if (value)
                {
                    RealtimeScanOptimized = false;
                }
            }
        }
    }

    public bool RealtimeScanOptimized
    {
        get => _realtimeScanOptimized;
        set
        {
            if (SetProperty(ref _realtimeScanOptimized, value))
            {
                App.Settings.Set("RealtimeScanAllExtensions", !value);
                if (value)
                {
                    RealtimeScanAll = false;
                }
            }
        }
    }

    public string RealtimeCustomExtensions
    {
        get => _realtimeCustomExtensions;
        set
        {
            if (SetProperty(ref _realtimeCustomExtensions, value))
            {
                App.Settings.Set("RealtimeCustomExtensions", value);
                App.RealTimeMonitor.UpdateCustomExtensions(value);
            }
        }
    }

    private List<LocalizationService.LanguageInfo> _languages = new();
    private LocalizationService.LanguageInfo? _selectedLanguage;

    public List<LocalizationService.LanguageInfo> Languages
    {
        get => _languages;
        set => SetProperty(ref _languages, value);
    }

    public LocalizationService.LanguageInfo? SelectedLanguage
    {
        get => _selectedLanguage;
        set
        {
            if (SetProperty(ref _selectedLanguage, value) && value != null)
            {
                App.Settings.Set("Language", value.FileName);
                LocalizationService.Instance.ChangeLanguage(value.FileName);
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

        _allMatchMode = App.Settings.Get("AllMatchMode", false);
        _heuristicAlerts = App.Settings.Get("HeuristicAlerts", true);
        _alertPua = App.Settings.Get("AlertPua", false);
        _alertPdf = App.Settings.Get("AlertPdf", false);
        _alertMacros = App.Settings.Get("AlertMacros", false);
        _alertSwf = App.Settings.Get("AlertSwf", false);
        _parseArchives = App.Settings.Get("ParseArchives", true);
        _parsePe = App.Settings.Get("ParsePe", true);
        _parsePdf = App.Settings.Get("ParsePdf", true);
        _parseMail = App.Settings.Get("ParseMail", true);
        _parseOle2 = App.Settings.Get("ParseOle2", true);
        _parseHtml = App.Settings.Get("ParseHtml", true);
        _parseElf = App.Settings.Get("ParseElf", true);
        _parseSwf = App.Settings.Get("ParseSwf", true);
        _parseRtf = App.Settings.Get("ParseRtf", true);
        _realtimeScanAll = App.Settings.Get("RealtimeScanAllExtensions", false);
        _realtimeScanOptimized = !_realtimeScanAll;
        _realtimeCustomExtensions = App.Settings.Get("RealtimeCustomExtensions", string.Empty);
        App.RealTimeMonitor.UpdateCustomExtensions(_realtimeCustomExtensions);

        // Load dynamic languages
        _languages = LocalizationService.Instance.GetAvailableLanguages();
        string currentFile = LocalizationService.Instance.CurrentLanguageFile;
        _selectedLanguage = _languages.FirstOrDefault(l => l.FileName.Equals(currentFile, StringComparison.OrdinalIgnoreCase));
        if (_selectedLanguage == null && _languages.Count > 0)
        {
            _selectedLanguage = _languages[0];
        }

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

        // Subscribe to events to sync toggle status
        App.RealTimeMonitor.ProtectionStarted += () =>
        {
            App.Current.Dispatcher.BeginInvoke(() =>
            {
                _realtimeEnabled = true;
                OnPropertyChanged(nameof(RealtimeEnabled));
            });
        };
        App.RealTimeMonitor.ProtectionStopped += () =>
        {
            App.Current.Dispatcher.BeginInvoke(() =>
            {
                _realtimeEnabled = false;
                OnPropertyChanged(nameof(RealtimeEnabled));
            });
        };
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
        dialog.Description = LocalizationService.Instance["Settings.SelectFolderDescription"];
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
