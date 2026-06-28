using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.ViewModels;

public class StatisticsViewModel : ViewModelBase
{
    private int _totalScans;
    private int _filesScanned;
    private int _threatsDetected;
    private string _avgDurationText = "00:00";
    private string _protectionStatusText = "Checking...";
    private string _protectionStatus = "unknown"; // clean, infected, warning, unknown
    private string _selectedTimeframe = "Weekly";
    private bool _isLoading;

    public int TotalScans
    {
        get => _totalScans;
        set => SetProperty(ref _totalScans, value);
    }

    public int FilesScanned
    {
        get => _filesScanned;
        set => SetProperty(ref _filesScanned, value);
    }

    public int ThreatsDetected
    {
        get => _threatsDetected;
        set => SetProperty(ref _threatsDetected, value);
    }

    public string AvgDurationText
    {
        get => _avgDurationText;
        set => SetProperty(ref _avgDurationText, value);
    }

    public string ProtectionStatusText
    {
        get => _protectionStatusText;
        set => SetProperty(ref _protectionStatusText, value);
    }

    public string ProtectionStatus
    {
        get => _protectionStatus;
        set => SetProperty(ref _protectionStatus, value);
    }

    public string SelectedTimeframe
    {
        get => _selectedTimeframe;
        set
        {
            if (SetProperty(ref _selectedTimeframe, value))
            {
                _ = LoadStatisticsAsync();
            }
        }
    }

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public ICommand RefreshCommand { get; }

    public StatisticsViewModel()
    {
        RefreshCommand = new AsyncRelayCommand(LoadStatisticsAsync);

        _ = LoadStatisticsAsync();
    }

    public async Task LoadStatisticsAsync()
    {
        IsLoading = true;

        try
        {
            var logs = await App.Logs.GetLogsAsync();
            var scanLogs = logs.Where(l => l.Type == "Scan").ToList();

            // Filter by timeframe
            DateTime cutoff = DateTime.MinValue;
            if (SelectedTimeframe == "Daily") cutoff = DateTime.Now.AddDays(-1);
            else if (SelectedTimeframe == "Weekly") cutoff = DateTime.Now.AddDays(-7);
            else if (SelectedTimeframe == "Monthly") cutoff = DateTime.Now.AddMonths(-1);

            var filteredLogs = cutoff == DateTime.MinValue
                ? scanLogs
                : scanLogs.Where(l => l.Timestamp >= cutoff).ToList();

            TotalScans = filteredLogs.Count;
            
            // On Windows we parse files/threats from Details log or summarize from results.
            // Let's parse details string: "Scanned files: X", "Infected files: Y"
            int totalFiles = 0;
            int totalThreats = 0;
            double totalSeconds = 0;
            int secondsCount = 0;

            foreach (var log in filteredLogs)
            {
                // Parse files scanned
                var fileMatch = System.Text.RegularExpressions.Regex.Match(log.Details, @"Scanned files:\s+(\d+)");
                if (fileMatch.Success) totalFiles += int.Parse(fileMatch.Groups[1].Value);

                // Parse threats found
                var threatMatch = System.Text.RegularExpressions.Regex.Match(log.Details, @"Infected files:\s+(\d+)");
                if (threatMatch.Success) totalThreats += int.Parse(threatMatch.Groups[1].Value);

                // Parse duration: "Time: 12.345 sec"
                var timeMatch = System.Text.RegularExpressions.Regex.Match(log.Details, @"Time:\s+([\d\.]+)\s+sec");
                if (timeMatch.Success)
                {
                    totalSeconds += double.Parse(timeMatch.Groups[1].Value);
                    secondsCount++;
                }
            }

            FilesScanned = totalFiles;
            ThreatsDetected = totalThreats;

            if (secondsCount > 0)
            {
                var avg = TimeSpan.FromSeconds(totalSeconds / secondsCount);
                AvgDurationText = avg.ToString(@"mm\:ss");
            }
            else
            {
                AvgDurationText = "00:00";
            }

            // Calculate protection status
            var lastScan = scanLogs.FirstOrDefault();
            if (lastScan == null)
            {
                ProtectionStatus = "warning";
                ProtectionStatusText = "System has never been scanned";
            }
            else if (lastScan.Timestamp < DateTime.Now.AddDays(-7))
            {
                ProtectionStatus = "warning";
                ProtectionStatusText = "Last scan was more than a week ago";
            }
            else if (lastScan.Status == "Fail" && totalThreats > 0)
            {
                // Check if threats are still in quarantine
                var quarantine = await App.Quarantine.GetAllEntriesAsync();
                if (quarantine.Count > 0)
                {
                    ProtectionStatus = "infected";
                    ProtectionStatusText = $"{quarantine.Count} threat(s) quarantined. Action required.";
                }
                else
                {
                    ProtectionStatus = "clean";
                    ProtectionStatusText = "System is protected. Last scan clean.";
                }
            }
            else
            {
                ProtectionStatus = "clean";
                ProtectionStatusText = "System is protected. Last scan clean.";
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed loading stats: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }
}
