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

public class LogsViewModel : ViewModelBase
{
    private LogEntry? _selectedLog;
    private string _searchQuery = string.Empty;
    private string _logDetail = "Select a log entry to view details.";
    private List<LogEntry> _allLogs = new();

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
                    LogDetail = "Select a log entry to view details.";
                }
            }
        }
    }

    public bool IsLogSelected => SelectedLog != null;

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                FilterLogs();
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

    public LogsViewModel()
    {
        RefreshCommand = new AsyncRelayCommand(LoadLogsAsync);
        ClearAllCommand = new AsyncRelayCommand(ClearAllLogsAsync);
        ExportLogCommand = new AsyncRelayCommand(ExportLogAsync);
        CopyLogCommand = new RelayCommand(CopyLog);

        _ = LoadLogsAsync();
    }

    public async Task LoadLogsAsync()
    {
        SelectedLog = null;
        _allLogs = await App.Logs.GetLogsAsync();
        FilterLogs();
    }

    private void FilterLogs()
    {
        Logs.Clear();
        var query = SearchQuery.Trim().ToLowerInvariant();

        var filtered = string.IsNullOrEmpty(query)
            ? _allLogs
            : _allLogs.Where(l => l.Summary.ToLowerInvariant().Contains(query) || 
                                 l.Type.ToLowerInvariant().Contains(query) ||
                                 l.ScanPath.ToLowerInvariant().Contains(query));

        foreach (var log in filtered)
        {
            Logs.Add(log);
        }
    }

    private async Task ClearAllLogsAsync()
    {
        if (_allLogs.Count == 0) return;

        var result = ModernMessageBox.Show(
            "Are you sure you want to permanently delete all scan and update logs? This cannot be undone.",
            "Clear Logs",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            if (await App.Logs.ClearAllLogsAsync())
            {
                await LoadLogsAsync();
            }
        }
    }

    private async Task ExportLogAsync()
    {
        if (SelectedLog == null) return;

        var dialog = new SaveFileDialog
        {
            Title = "Export Log Details",
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
                ModernMessageBox.Show("Log exported successfully.", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ModernMessageBox.Show($"Failed to export log: {ex.Message}", "Export Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void CopyLog()
    {
        if (SelectedLog == null) return;

        try
        {
            Clipboard.SetText(SelectedLog.Details);
            ModernMessageBox.Show("Log details copied to clipboard.", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            ModernMessageBox.Show($"Failed to copy log: {ex.Message}", "Copy Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
