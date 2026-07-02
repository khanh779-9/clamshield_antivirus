using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;
using clamshield_antivirus.Views;

namespace clamshield_antivirus.ViewModels;

public class EventsViewModel : ViewModelBase
{
    private const int MaxDisplayEntries = 100;

    private LogEntry? _selectedLog;
    private string _searchQuery = string.Empty;
    private string _logDetail = string.Empty;
    private List<LogEntry> _allLogs = new();
    private bool _hasMore;

    public ObservableCollection<LogEntry> Logs { get; } = new();

    public LogEntry? SelectedLog
    {
        get => _selectedLog;
        set
        {
            if (SetProperty(ref _selectedLog, value))
            {
                OnPropertyChanged(nameof(IsLogSelected));
                if (value != null)
                {
                    LogDetail = value.Details;
                }
                else
                {
                    LogDetail = LocalizationService.Instance["Events.SelectLogPrompt"];
                }
            }
        }
    }

    public bool IsLogSelected => SelectedLog != null;
    public bool HasMore { get => _hasMore; set => SetProperty(ref _hasMore, value); }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                FilterEvents();
            }
        }
    }

    public string LogDetail
    {
        get => _logDetail;
        set => SetProperty(ref _logDetail, value);
    }

    public ICommand RefreshCommand { get; }
    public ICommand ClearAllCommand { get; }
    public ICommand ExportLogCommand { get; }
    public ICommand CopyLogCommand { get; }
    public ICommand LoadMoreCommand { get; }

    public EventsViewModel()
    {
        _logDetail = LocalizationService.Instance["Events.SelectLogPrompt"];
        RefreshCommand = new AsyncRelayCommand(LoadEventsAsync);
        ClearAllCommand = new AsyncRelayCommand(ClearAllEventsAsync);
        ExportLogCommand = new AsyncRelayCommand(ExportLogAsync);
        CopyLogCommand = new RelayCommand(CopyLog);
        LoadMoreCommand = new RelayCommand(_ => LoadMore());

        _ = LoadEventsAsync();

        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                if (SelectedLog == null)
                {
                    LogDetail = LocalizationService.Instance["Events.SelectLogPrompt"];
                }
            }
        };
    }

    public async Task LoadEventsAsync()
    {
        SelectedLog = null;
        _allLogs = await App.Logs.GetLogsAsync();
        FilterEvents();
    }

    private void FilterEvents()
    {
        Logs.Clear();
        var query = SearchQuery.Trim().ToLowerInvariant();

        var filtered = string.IsNullOrEmpty(query)
            ? _allLogs
            : _allLogs.Where(l => l.Summary.ToLowerInvariant().Contains(query) || 
                                 l.Type.ToLowerInvariant().Contains(query) ||
                                 l.ScanPath.ToLowerInvariant().Contains(query));

        var limited = filtered.Take(MaxDisplayEntries).ToList();
        HasMore = filtered.Count() > MaxDisplayEntries;

        foreach (var log in limited)
        {
            Logs.Add(log);
        }
    }

    private void LoadMore()
    {
        var query = SearchQuery.Trim().ToLowerInvariant();

        var filtered = string.IsNullOrEmpty(query)
            ? _allLogs
            : _allLogs.Where(l => l.Summary.ToLowerInvariant().Contains(query) || 
                                 l.Type.ToLowerInvariant().Contains(query) ||
                                 l.ScanPath.ToLowerInvariant().Contains(query));

        var currentCount = Logs.Count;
        var nextBatch = filtered.Skip(currentCount).Take(MaxDisplayEntries).ToList();
        HasMore = filtered.Count() > currentCount + nextBatch.Count;

        foreach (var log in nextBatch)
        {
            Logs.Add(log);
        }
    }

    private async Task ClearAllEventsAsync()
    {
        if (_allLogs.Count == 0) return;

        var result = ModernMessageBox.Show(
            LocalizationService.Instance["Events.ConfirmClear"],
            LocalizationService.Instance["Events.ClearTitle"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            if (await App.Logs.ClearAllLogsAsync())
            {
                await LoadEventsAsync();
            }
        }
    }

    private async Task ExportLogAsync()
    {
        if (SelectedLog == null) return;

        var dialog = new SaveFileDialog
        {
            Title = LocalizationService.Instance["Events.ExportTitle"],
            Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
            FileName = $"clamui_{SelectedLog.Type.ToLower()}_{SelectedLog.Timestamp:yyyyMMdd_HHmmss}.log"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                string details = SelectedLog.Details;
                string fileName = dialog.FileName;
                await Task.Run(() => File.WriteAllText(fileName, details));
                ModernMessageBox.Show(LocalizationService.Instance["Events.ExportSuccess"], LocalizationService.Instance["Events.ExportSuccessTitle"], MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ModernMessageBox.Show(string.Format(LocalizationService.Instance["Events.ExportFailed"], ex.Message), LocalizationService.Instance["Events.ExportFailedTitle"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void CopyLog()
    {
        if (SelectedLog == null) return;

        try
        {
            Clipboard.SetText(SelectedLog.Details);
            ModernMessageBox.Show(LocalizationService.Instance["Events.Copied"], LocalizationService.Instance["Events.CopiedTitle"], MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            ModernMessageBox.Show(string.Format(LocalizationService.Instance["Events.CopyFailed"], ex.Message), LocalizationService.Instance["Events.CopyFailedTitle"], MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
