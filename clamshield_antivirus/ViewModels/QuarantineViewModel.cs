using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;
using clamshield_antivirus.Converters;

namespace clamshield_antivirus.ViewModels;

public class QuarantineViewModel : ViewModelBase
{
    private QuarantineEntry? _selectedEntry;
    private string _searchQuery = string.Empty;
    private string _totalSizeText = "0 B";
    private string _itemCountText = "0 items";
    private List<QuarantineEntry> _allEntries = new();

    public ObservableCollection<QuarantineEntry> Entries { get; } = new();

    public QuarantineEntry? SelectedEntry
    {
        get => _selectedEntry;
        set
        {
            if (SetProperty(ref _selectedEntry, value))
            {
                OnPropertyChanged(nameof(IsEntrySelected));
            }
        }
    }

    public bool IsEntrySelected => SelectedEntry != null;

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                FilterEntries();
            }
        }
    }

    public string TotalSizeText
    {
        get => _totalSizeText;
        set => SetProperty(ref _totalSizeText, value);
    }

    public string ItemCountText
    {
        get => _itemCountText;
        set => SetProperty(ref _itemCountText, value);
    }

    public ICommand RefreshCommand { get; }
    public ICommand RestoreCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand ClearOldCommand { get; }

    public QuarantineViewModel()
    {
        RefreshCommand = new AsyncRelayCommand(LoadEntriesAsync);
        RestoreCommand = new AsyncRelayCommand(RestoreSelectedAsync);
        DeleteCommand = new AsyncRelayCommand(DeleteSelectedAsync);
        ClearOldCommand = new AsyncRelayCommand(ClearOldEntriesAsync);

        _ = LoadEntriesAsync();
    }

    public async Task LoadEntriesAsync()
    {
        SelectedEntry = null;
        var list = await App.Quarantine.GetAllEntriesAsync();
        _allEntries = list.OrderByDescending(e => e.QuarantineDate).ToList();
        
        FilterEntries();
        CalculateStatistics();
    }

    private void FilterEntries()
    {
        Entries.Clear();
        var query = SearchQuery.Trim().ToLowerInvariant();

        var filtered = string.IsNullOrEmpty(query)
            ? _allEntries
            : _allEntries.Where(e => e.ThreatName.ToLowerInvariant().Contains(query) || 
                                     e.OriginalPath.ToLowerInvariant().Contains(query));

        foreach (var entry in filtered)
        {
            Entries.Add(entry);
        }
    }

    private void CalculateStatistics()
    {
        long totalBytes = _allEntries.Sum(e => e.FileSize);
        TotalSizeText = FileSizeConverter.FormatFileSize(totalBytes);
        
        int count = _allEntries.Count;
        ItemCountText = count == 1 ? "1 item" : $"{count} items";
    }

    private async Task RestoreSelectedAsync()
    {
        if (SelectedEntry == null) return;

        var entry = SelectedEntry;
        bool success = await App.Quarantine.RestoreFileAsync(entry);
        if (success)
        {
            _allEntries.Remove(entry);
            FilterEntries();
            CalculateStatistics();
            SelectedEntry = null;
            MessageBox.Show("File has been successfully restored to its original location.", "Restore Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show("Failed to restore file. The original directory might be write-protected or unavailable.", "Restore Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task DeleteSelectedAsync()
    {
        if (SelectedEntry == null) return;

        var result = MessageBox.Show(
            "Are you sure you want to permanently delete this quarantined file? This action cannot be undone.",
            "Confirm Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            var entry = SelectedEntry;
            bool success = await App.Quarantine.DeleteFileAsync(entry);
            if (success)
            {
                _allEntries.Remove(entry);
                FilterEntries();
                CalculateStatistics();
                SelectedEntry = null;
            }
            else
            {
                MessageBox.Show("Failed to delete the file.", "Delete Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private async Task ClearOldEntriesAsync()
    {
        var cutoff = DateTime.Now.AddDays(-30);
        var oldEntries = _allEntries.Where(e => e.QuarantineDate < cutoff).ToList();

        if (oldEntries.Count == 0)
        {
            MessageBox.Show("No items are older than 30 days.", "Cleanup", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = MessageBox.Show(
            $"Are you sure you want to permanently delete all {oldEntries.Count} quarantined files older than 30 days?",
            "Confirm Cleanup",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            int deletedCount = 0;
            foreach (var entry in oldEntries)
            {
                if (await App.Quarantine.DeleteFileAsync(entry))
                {
                    _allEntries.Remove(entry);
                    deletedCount++;
                }
            }

            FilterEntries();
            CalculateStatistics();
            SelectedEntry = null;
            MessageBox.Show($"Cleaned up {deletedCount} old entries.", "Cleanup Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
