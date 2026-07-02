using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Collections.ObjectModel;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;
using clamshield_antivirus.Services;
using clamshield_antivirus.Services.UpdateSvc;

namespace clamshield_antivirus.ViewModels;

public class EngineViewModel : ViewModelBase
{
    private bool _isUpdating;
    private string _progressLog = string.Empty;
    private string _statusText = string.Empty;
    private string _lastUpdateTime = string.Empty;
    private string _dbVersionSummary = string.Empty;
    private CancellationTokenSource? _cts;
    private readonly ObservableCollection<DbVersionInfo> _dbVersions = new();
    private bool _isChecking;

    public bool IsUpdating
    {
        get => _isUpdating;
        set
        {
            if (SetProperty(ref _isUpdating, value))
                OnPropertyChanged(nameof(CanUpdate));
        }
    }

    public bool CanUpdate => !IsUpdating;

    public string ProgressLog
    {
        get => _progressLog;
        set => SetProperty(ref _progressLog, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string LastUpdateTime
    {
        get => _lastUpdateTime;
        set => SetProperty(ref _lastUpdateTime, value);
    }

    public string DbVersionSummary
    {
        get => _dbVersionSummary;
        set => SetProperty(ref _dbVersionSummary, value);
    }

    public ObservableCollection<DbVersionInfo> DbVersions => _dbVersions;

    public ObservableCollection<ComponentStatus> Components { get; } = new();

    public bool IsChecking
    {
        get => _isChecking;
        set => SetProperty(ref _isChecking, value);
    }

    public bool FreshclamAvailable => true;

    public ICommand UpdateCommand { get; }
    public ICommand CancelUpdateCommand { get; }
    public ICommand RefreshCommand { get; }

    public EngineViewModel()
    {
        _statusText = LocalizationService.Instance["Database.StatusReady"];
        UpdateCommand = new AsyncRelayCommand(UpdateDatabaseAsync);
        CancelUpdateCommand = new RelayCommand(CancelUpdate);
        RefreshCommand = new AsyncRelayCommand(RefreshStatusAsync);
        CheckFreshclamStatus();
        _ = RefreshStatusAsync();

        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                if (!IsUpdating)
                {
                    StatusText = LocalizationService.Instance["Database.StatusReady"];
                }
                UpdateLastUpdateTime();
                RefreshDbVersions();
                _ = RefreshStatusAsync();
            }
        };
    }

    private void CheckFreshclamStatus()
    {
        UpdateLastUpdateTime();
        RefreshDbVersions();
    }

    private void RefreshDbVersions()
    {
        _dbVersions.Clear();
        var versions = App.ComponentDetection.GetDatabaseVersions();
        foreach (var v in versions)
            _dbVersions.Add(v);

        if (versions.Count > 0)
        {
            DbVersionSummary = string.Join(", ", versions.Select(v => $"{v.DatabaseName} v{v.Version}"));
        }
        else
        {
            DbVersionSummary = LocalizationService.Instance["Database.NoDbsInstalled"];
        }
    }

    private void UpdateLastUpdateTime()
    {
        string localDbDir = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "database"
        );

        var cvdInfos = new System.Collections.Generic.Dictionary<string, CvdInfo>(StringComparer.OrdinalIgnoreCase);
        CvdReader.TryGetCvdInfoFromDbDir(localDbDir, out cvdInfos);

        if (cvdInfos.Count > 0)
        {
            var latest = cvdInfos.Values.OrderByDescending(v => v.BuildTime).FirstOrDefault();
            if (latest != null && latest.BuildTime > DateTime.MinValue)
            {
                LastUpdateTime = latest.BuildTime.ToString("yyyy-MM-dd HH:mm:ss");
                return;
            }
        }

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
                var writeTime = File.GetLastWriteTime(path);
                LastUpdateTime = writeTime.ToString("yyyy-MM-dd HH:mm:ss");
                return;
            }
        }

        string updateTime = App.Settings.Get("LastDatabaseUpdateTime", string.Empty);
        LastUpdateTime = string.IsNullOrEmpty(updateTime) ? LocalizationService.Instance["Database.NeverUpdated"] : updateTime;
    }

    private async Task UpdateDatabaseAsync()
    {
        IsUpdating = true;
        ProgressLog = LocalizationService.Instance["Database.LogStarting"] + "\n";
        StatusText = LocalizationService.Instance["Database.StatusDownloading"];
        _cts = new CancellationTokenSource();

        var progressReporter = new Progress<string>(line =>
        {
            ProgressLog += line + "\n";
        });

        try
        {
            var logEntry = await Task.Run(() => App.Freshclam.UpdateDatabaseAsync(progressReporter, _cts.Token));
            await App.Logs.SaveLogAsync(logEntry);

            StatusText = logEntry.Summary;
            if (logEntry.Status == "Success")
            {
                var updateTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                App.Settings.Set("LastDatabaseUpdateTime", updateTime);
                LastUpdateTime = updateTime;

                await App.ClamAv.ReloadSignaturesAsync();
            }
        }
        catch (Exception ex)
        {
            StatusText = LocalizationService.Instance["Database.StatusFailed"];
            ProgressLog += $"\n[{LocalizationService.Instance["Common.Error"]}] {ex.Message}\n";
        }
        finally
        {
            IsUpdating = false;
            _cts = null;
            RefreshDbVersions();
        }
    }

    private void CancelUpdate()
    {
        _cts?.Cancel();
        StatusText = LocalizationService.Instance["Database.StatusCancelling"];
        ProgressLog += $"\n[{LocalizationService.Instance["Database.LogCancelled"]}]\n";
    }

    public async Task RefreshStatusAsync()
    {
        IsChecking = true;
        Components.Clear();

        try
        {
            await Task.Run(() =>
            {
                var list = App.ComponentDetection.GetAllComponentsStatus();

                App.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var item in list)
                    {
                        Components.Add(item);
                    }
                });
            });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed checking components status: {ex.Message}");
        }
        finally
        {
            IsChecking = false;
        }
    }
}