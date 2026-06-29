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
using clamshield_antivirus.Views;

namespace clamshield_antivirus.ViewModels;

public class QuarantineViewModel : ViewModelBase
{
    private QuarantineEntry? _selectedEntry;
    private string _searchQuery = string.Empty;
    private string _totalSizeText = "0 B";
    private string _itemCountText = "0 items";
    private bool _hasEntries;
    private bool _selectAllChecked;
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

    public bool HasEntries
    {
        get => _hasEntries;
        set => SetProperty(ref _hasEntries, value);
    }

    public bool SelectAllChecked
    {
        get => _selectAllChecked;
        set
        {
            if (SetProperty(ref _selectAllChecked, value))
            {
                foreach (var entry in Entries)
                    entry.IsSelected = value;
            }
        }
    }

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
    public ICommand ClearAllCommand { get; }
    public ICommand DeleteSelectedCommand { get; }

    public QuarantineViewModel()
    {
        RefreshCommand = new AsyncRelayCommand(LoadEntriesAsync);
        RestoreCommand = new AsyncRelayCommand(RestoreSelectedAsync);
        DeleteCommand = new AsyncRelayCommand(DeleteSelectedAsync);
        ClearOldCommand = new AsyncRelayCommand(ClearOldEntriesAsync);
        ClearAllCommand = new AsyncRelayCommand(ClearAllEntriesAsync);
        DeleteSelectedCommand = new AsyncRelayCommand(DeleteCheckedEntriesAsync);

        _ = LoadEntriesAsync();
    }

    public async Task LoadEntriesAsync()
    {
        try
        {
            SelectedEntry = null;
            var list = await App.Quarantine.GetAllEntriesAsync();
            _allEntries = list.OrderByDescending(e => e.QuarantineDate).ToList();
            
            FilterEntries();
            CalculateStatistics();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to load quarantine entries: {ex.Message}");
            _allEntries.Clear();
            Entries.Clear();
            HasEntries = false;
        }
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
        HasEntries = Entries.Count > 0;
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
            ModernMessageBox.Show("File has been successfully restored to its original location.", "Restore Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            ModernMessageBox.Show("Failed to restore file. The original directory might be write-protected or unavailable.", "Restore Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task DeleteSelectedAsync()
    {
        if (SelectedEntry == null) return;

        var result = ModernMessageBox.Show(
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
                ModernMessageBox.Show("Failed to delete the file.", "Delete Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private async Task ClearOldEntriesAsync()
    {
        var cutoff = DateTime.Now.AddDays(-30);
        var oldEntries = _allEntries.Where(e => e.QuarantineDate < cutoff).ToList();

        if (oldEntries.Count == 0)
        {
            ModernMessageBox.Show("No items are older than 30 days.", "Cleanup", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = ModernMessageBox.Show(
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
            ModernMessageBox.Show($"Cleaned up {deletedCount} old entries.", "Cleanup Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async Task ClearAllEntriesAsync()
    {
        if (_allEntries.Count == 0) return;

        var result = ModernMessageBox.Show(
            $"Are you sure you want to permanently delete ALL {_allEntries.Count} quarantined files? This action cannot be undone.",
            "Confirm Delete All",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            int deletedCount = 0;
            foreach (var entry in _allEntries.ToList())
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
            ModernMessageBox.Show($"Deleted {deletedCount} entries. Quarantine is now empty.", "Clear Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async Task DeleteCheckedEntriesAsync()
    {
        var checkedEntries = Entries.Where(e => e.IsSelected).ToList();
        if (checkedEntries.Count == 0)
        {
            ModernMessageBox.Show("No items selected. Check the box next to items you want to delete.", "Nothing Selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = ModernMessageBox.Show(
            $"Delete {checkedEntries.Count} selected quarantined file(s)? This action cannot be undone.",
            "Confirm Delete Selected",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            int deletedCount = 0;
            foreach (var entry in checkedEntries)
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
            SelectAllChecked = false;
            ModernMessageBox.Show($"Deleted {deletedCount} selected file(s).", "Delete Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
