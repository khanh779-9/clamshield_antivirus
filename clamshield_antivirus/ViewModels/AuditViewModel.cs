using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Windows.Input;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class AuditItem : ViewModelBase
{
    public string TitleKey { get; set; } = string.Empty;
    public string DescriptionKey { get; set; } = string.Empty;
    public object[] DescriptionArgs { get; set; } = Array.Empty<object>();
    public string Status { get; set; } = "unknown"; // pass, warning, fail
    public string SuggestionKey { get; set; } = string.Empty;
    public string FixCommandKey { get; set; } = string.Empty;

    public string Title => LocalizationService.Instance[TitleKey];
    public string Description => DescriptionArgs != null && DescriptionArgs.Length > 0 
        ? string.Format(LocalizationService.Instance[DescriptionKey], DescriptionArgs)
        : LocalizationService.Instance[DescriptionKey];
    public string Suggestion => LocalizationService.Instance[SuggestionKey];
    public string FixCommand => LocalizationService.Instance[FixCommandKey];

    public void Refresh()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Description));
        OnPropertyChanged(nameof(Suggestion));
        OnPropertyChanged(nameof(FixCommand));
    }
}

public class AuditViewModel : ViewModelBase
{
    private bool _isAuditing;
    private string _summaryText = string.Empty;
    private int _issuesCount;

    public ObservableCollection<AuditItem> AuditItems { get; } = new();

    public bool IsAuditing
    {
        get => _isAuditing;
        set => SetProperty(ref _isAuditing, value);
    }

    public string SummaryText
    {
        get => _summaryText;
        set => SetProperty(ref _summaryText, value);
    }

    public int IssuesCount
    {
        get => _issuesCount;
        set
        {
            if (SetProperty(ref _issuesCount, value))
            {
                OnPropertyChanged(nameof(HasIssues));
            }
        }
    }

    public bool HasIssues => IssuesCount > 0;

    public ICommand RunAuditCommand { get; }

    public AuditViewModel()
    {
        _summaryText = LocalizationService.Instance["Audit.CheckingPosture"];
        RunAuditCommand = new AsyncRelayCommand(RunAuditAsync);

        _ = RunAuditAsync();

        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                foreach (var item in AuditItems)
                {
                    item.Refresh();
                }
                UpdateSummaryText();
            }
        };
    }

    private void UpdateSummaryText()
    {
        if (IsAuditing)
        {
            SummaryText = LocalizationService.Instance["Audit.RunningChecks"];
            return;
        }

        SummaryText = IssuesCount == 0 
            ? LocalizationService.Instance["Audit.AllPassed"] 
            : string.Format(LocalizationService.Instance["Audit.IssuesFound"], IssuesCount);
    }

    public async Task RunAuditAsync()
    {
        IsAuditing = true;
        SummaryText = LocalizationService.Instance["Audit.RunningChecks"];
        AuditItems.Clear();
        int issues = 0;

        try
        {
            await Task.Run(() =>
            {
                // Check 1: C# Engine Status
                bool engineReady = App.Engine != null;
                var clamItem = new AuditItem
                {
                    TitleKey = "Audit.EngineTitle",
                    DescriptionKey = engineReady ? "Audit.EngineReady" : "Audit.EngineFailed",
                    Status = engineReady ? "pass" : "fail",
                    SuggestionKey = engineReady ? "Audit.EngineReadySuggestion" : "Audit.EngineFailedSuggestion",
                    FixCommandKey = "Audit.EngineFix"
                };
                if (!engineReady) issues++;

                // Check 2: ClamAV Database Definitions Health
                bool definitionsActive = false;
                string dbDescKey = "Audit.DbMissing";
                object[] dbArgs = Array.Empty<object>();
                string localDbDir = Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    "database"
                );

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
                        var lastWrite = File.GetLastWriteTime(path);
                        if (lastWrite > DateTime.Now.AddDays(-7))
                        {
                            definitionsActive = true;
                            dbDescKey = "Audit.DbActive";
                        }
                        else
                        {
                            definitionsActive = false;
                            dbDescKey = "Audit.DbOutdated";
                        }
                        dbArgs = new object[] { lastWrite.ToString("yyyy-MM-dd HH:mm") };
                        break;
                    }
                }

                var dbItem = new AuditItem
                {
                    TitleKey = "Audit.DbTitle",
                    DescriptionKey = dbDescKey,
                    DescriptionArgs = dbArgs,
                    Status = definitionsActive ? "pass" : "warning",
                    SuggestionKey = definitionsActive ? "Audit.DbActiveSuggestion" : "Audit.DbOutdatedSuggestion",
                    FixCommandKey = "Audit.DbFix"
                };
                if (!definitionsActive) issues++;

                // Check 3: Windows Defender Security Service
                bool defenderRunning = IsServiceRunning("WinDefend");
                var defenderItem = new AuditItem
                {
                    TitleKey = "Audit.DefenderTitle",
                    DescriptionKey = defenderRunning ? "Audit.DefenderActive" : "Audit.DefenderInactive",
                    Status = defenderRunning ? "pass" : "warning",
                    SuggestionKey = defenderRunning ? "Audit.DefenderActiveSuggestion" : "Audit.DefenderInactiveSuggestion",
                    FixCommandKey = "powershell Start-Service WinDefend"
                };
                if (!defenderRunning) issues++;

                // Check 4: Windows Firewall Active State
                bool firewallRunning = IsServiceRunning("MpsSvc");
                var firewallItem = new AuditItem
                {
                    TitleKey = "Audit.FirewallTitle",
                    DescriptionKey = firewallRunning ? "Audit.FirewallActive" : "Audit.FirewallInactive",
                    Status = firewallRunning ? "pass" : "fail",
                    SuggestionKey = firewallRunning ? "Audit.FirewallActiveSuggestion" : "Audit.FirewallInactiveSuggestion",
                    FixCommandKey = "powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
                };
                if (!firewallRunning) issues++;

                // Invoke UI thread to add items
                App.Current.Dispatcher.Invoke(() =>
                {
                    AuditItems.Add(clamItem);
                    AuditItems.Add(dbItem);
                    AuditItems.Add(defenderItem);
                    AuditItems.Add(firewallItem);
                });
            });

            IssuesCount = issues;
            UpdateSummaryText();
        }
        catch (Exception ex)
        {
            SummaryText = LocalizationService.Instance["Audit.AbortedError"];
            System.Diagnostics.Debug.WriteLine($"Failed executing system audit: {ex.Message}");
        }
        finally
        {
            IsAuditing = false;
        }
    }

    private bool IsServiceRunning(string serviceName)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {serviceName}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output.Contains("RUNNING");
            }
        }
        catch { }
        return false;
    }
}
