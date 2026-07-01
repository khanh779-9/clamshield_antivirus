using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;
using clamshield_antivirus.Views;
using clamshield_antivirus.Services.ScanSvc;

namespace clamshield_antivirus.ViewModels;

public class ScanViewModel : ViewModelBase
{
    private bool _isScanning;
    private ScanProgress _progress = new();
    private ScanResult? _result;
    private ScanProfile? _selectedProfile;
    private string _backendText = "Backend: clamscan (standalone)";
    private CancellationTokenSource? _cts;
    private volatile bool _cancelRequested;

    public ObservableCollection<string> Targets { get; } = new();
    public ObservableCollection<ScanProfile> Profiles { get; } = new();

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (SetProperty(ref _isScanning, value))
            {
                OnPropertyChanged(nameof(CanStartScan));
                OnPropertyChanged(nameof(IsControlPanelVisible));
            }
        }
    }

    public bool CanStartScan => !IsScanning && Targets.Count > 0;
    public bool HasTargets => Targets.Count > 0;
    public bool IsControlPanelVisible => !IsScanning && !IsResultAvailable;

    public ScanProgress Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    public ScanResult? Result
    {
        get => _result;
        set
        {
            if (SetProperty(ref _result, value))
            {
                OnPropertyChanged(nameof(IsResultAvailable));
                OnPropertyChanged(nameof(IsControlPanelVisible));
            }
        }
    }

    public bool IsResultAvailable => Result != null;

    public ScanProfile? SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            if (SetProperty(ref _selectedProfile, value) && value != null)
            {
                Targets.Clear();
                foreach (var path in value.TargetPaths)
                {
                    Targets.Add(path);
                }
                OnPropertyChanged(nameof(CanStartScan));
            }
        }
    }

    public string BackendText
    {
        get => _backendText;
        set => SetProperty(ref _backendText, value);
    }

    public ICommand AddFileCommand { get; }
    public ICommand AddFolderCommand { get; }
    public ICommand RemoveTargetCommand { get; }
    public ICommand ClearTargetsCommand { get; }
    public ICommand StartScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand EicarTestCommand { get; }
    public ICommand QuarantineAllCommand { get; }
    public ICommand ExcludePathCommand { get; }
    public ICommand DismissResultCommand { get; }

    public ScanViewModel()
    {
        Targets.CollectionChanged += (s, e) =>
        {
            OnPropertyChanged(nameof(CanStartScan));
            OnPropertyChanged(nameof(HasTargets));
        };

        AddFileCommand = new RelayCommand(AddFile);
        AddFolderCommand = new RelayCommand(AddFolder);
        RemoveTargetCommand = new RelayCommand(param =>
        {
            if (param is string target)
            {
                Targets.Remove(target);
                OnPropertyChanged(nameof(CanStartScan));
            }
        });
        ClearTargetsCommand = new RelayCommand(() =>
        {
            Targets.Clear();
            OnPropertyChanged(nameof(CanStartScan));
        });
        StartScanCommand = new AsyncRelayCommand(StartScanAsync);
        CancelScanCommand = new RelayCommand(CancelScan, () => !_cancelRequested);
        EicarTestCommand = new AsyncRelayCommand(RunEicarTestAsync);
        QuarantineAllCommand = new AsyncRelayCommand(QuarantineAllAsync);
        ExcludePathCommand = new RelayCommand(param =>
        {
            if (param is ThreatDetail threat)
            {
                ExcludePath(threat.FilePath);
            }
        });
        DismissResultCommand = new RelayCommand(() =>
        {
            Result = null;
        });

        LoadProfiles();
        UpdateBackendText();

        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                LoadProfiles();
            }
        };
    }

    private void UpdateBackendText()
    {
        BackendText = "Backend: Built-in C# Engine";
    }

    private void LoadProfiles()
    {
        Profiles.Clear();
        // Add manual scan profile
        Profiles.Add(new ScanProfile { 
            Id = "manual", 
            Name = LocalizationService.Instance["Scan.ProfileManualName"], 
            Description = LocalizationService.Instance["Scan.ProfileManualDesc"] 
        });
        Profiles.Add(new ScanProfile
        {
            Id = "quick",
            Name = LocalizationService.Instance["Scan.ProfileQuickName"],
            Description = LocalizationService.Instance["Scan.ProfileQuickDesc"],
            TargetPaths = new() {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
            }
        });
        Profiles.Add(new ScanProfile
        {
            Id = "smart",
            Name = LocalizationService.Instance["Scan.ProfileSmartName"],
            Description = LocalizationService.Instance["Scan.ProfileSmartDesc"],
            TargetPaths = new string[] {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\Tasks"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\drivers"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\drivers\\etc")
            }.Where(Directory.Exists).ToList()
        });
        Profiles.Add(new ScanProfile
        {
            Id = "full",
            Name = LocalizationService.Instance["Scan.ProfileFullName"],
            Description = LocalizationService.Instance["Scan.ProfileFullDesc"],
            TargetPaths = new() { Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\" }
        });

        string selectedId = _selectedProfile?.Id ?? "manual";
        SelectedProfile = Profiles.FirstOrDefault(p => p.Id == selectedId) ?? Profiles[0];
    }

    private void AddFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = LocalizationService.Instance["Scan.SelectFileTitle"],
            Multiselect = true
        };

        if (dialog.ShowDialog() == true)
        {
            foreach (var filename in dialog.FileNames)
            {
                if (!Targets.Contains(filename))
                {
                    Targets.Add(filename);
                }
            }
            OnPropertyChanged(nameof(CanStartScan));
        }
    }

    private void AddFolder()
    {
        var dialog = new OpenFolderDialog
        {
            Title = LocalizationService.Instance["Scan.SelectFolderTitle"],
            Multiselect = true
        };

        if (dialog.ShowDialog() == true)
        {
            foreach (var foldername in dialog.FolderNames)
            {
                if (!Targets.Contains(foldername))
                {
                    Targets.Add(foldername);
                }
            }
            OnPropertyChanged(nameof(CanStartScan));
        }
    }

    private async Task StartScanAsync()
    {
        if (Targets.Count == 0) return;

        _cancelRequested = false;
        IsScanning = true;
        Result = null;
        Progress = new ScanProgress { StatusText = LocalizationService.Instance["Scan.StatusInitializing"] };
        _cts = new CancellationTokenSource();
        UpdateBackendText();

        var progressReporter = new Progress<ScanProgress>(p =>
        {
            if (!_cancelRequested)
                Progress = p;
        });

        try
        {
            var scanTargets = Targets.ToList();
            var scanResult = await App.ClamAv.ScanAsync(scanTargets, SelectedProfile, progressReporter, _cts.Token);
            if (_cancelRequested) return;

            Result = scanResult;

            // Log to historical database
            var logEntry = new LogEntry
            {
                Type = "Scan",
                Summary = $"Scanned {scanResult.FilesScanned} files. Found {scanResult.ThreatsFound} threats.",
                Status = scanResult.Status == "Clean" ? "Success" : (scanResult.Status == "Cancelled" ? "Warning" : "Fail"),
                Details = scanResult.RawLog,
                ScanPath = scanResult.ScanPath
            };
            await App.Logs.SaveLogAsync(logEntry);

            if (_selectedProfile?.AutoQuarantine == true || App.Settings.Get("AutoQuarantine", false))
            {
                await QuarantineAllAsync();
            }
        }
        catch (Exception ex)
        {
            if (!_cancelRequested)
                Progress = new ScanProgress { StatusText = LocalizationService.Instance["Common.Error"] + ": " + ex.Message };
        }
        finally
        {
            if (!_cancelRequested)
            {
                IsScanning = false;
                _cts = null;
            }
        }
    }

    private void CancelScan()
    {
        if (_cts == null || _cancelRequested) return;
        _cancelRequested = true;
        _cts.Cancel();

        IsScanning = false;
        _cts = null;

        Result = new ScanResult
        {
            Status = "Cancelled",
            ScanTime = DateTime.Now,
            Duration = TimeSpan.Zero,
            ScanPath = string.Join(", ", Targets)
        };

        Progress = new ScanProgress { StatusText = LocalizationService.Instance["Scan.StatusCancelled"] };
    }

    private async Task RunEicarTestAsync()
    {
        // 1. Create a safe temporary EICAR file
        string tempPath = Path.Combine(Path.GetTempPath(), $"eicar_test_{Guid.NewGuid().ToString().Substring(0, 8)}.txt");
        string eicarString = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        try
        {
            await File.WriteAllTextAsync(tempPath, eicarString);
            
            Targets.Clear();
            Targets.Add(tempPath);
            OnPropertyChanged(nameof(CanStartScan));

            await StartScanAsync();
        }
        catch (Exception ex)
        {
            ModernMessageBox.Show(string.Format(LocalizationService.Instance["Scan.EicarErrorDesc"], ex.Message), LocalizationService.Instance["Scan.EicarErrorTitle"], MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            // Subprocess might lock file temporarily; attempt deletion, or wait
            _ = Task.Run(async () =>
            {
                await Task.Delay(2000);
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch { }
            });
        }
    }

    private async Task QuarantineAllAsync()
    {
        if (Result == null || Result.Threats.Count == 0) return;

        Progress = new ScanProgress { StatusText = LocalizationService.Instance["Scan.StatusQuarantining"] };
        IsScanning = true;

        var threats = Result.Threats.ToList();
        int quarantinedCount = 0;

        foreach (var threat in threats)
        {
            if (threat.Status == "Detected")
            {
                var entry = await App.Quarantine.QuarantineFileAsync(threat.FilePath, threat.ThreatName);
                if (entry != null)
                {
                    threat.Status = "Quarantined";
                    quarantinedCount++;
                }
                else
                {
                    threat.Status = "Quarantine Failed";
                }
            }
        }

        IsScanning = false;
        Progress = new ScanProgress { StatusText = string.Format(LocalizationService.Instance["Scan.StatusQuarantinedCount"], quarantinedCount) };
        OnPropertyChanged(nameof(Result)); // Notify binding updates
    }

    private void ExcludePath(string path)
    {
        var exclusions = App.Settings.Get("ExclusionPatterns", new List<string>());
        if (!exclusions.Contains(path))
        {
            exclusions.Add(path);
            App.Settings.Set("ExclusionPatterns", exclusions);
            ModernMessageBox.Show(string.Format(LocalizationService.Instance["Scan.ExcludedDesc"], path), LocalizationService.Instance["Scan.ExcludedTitle"], MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
