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
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Status { get; set; } = "unknown"; // pass, warning, fail
    public string Suggestion { get; set; } = string.Empty;
    public string FixCommand { get; set; } = string.Empty;
}

public class AuditViewModel : ViewModelBase
{
    private bool _isAuditing;
    private string _summaryText = "Checking system security posture...";
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
        RunAuditCommand = new AsyncRelayCommand(RunAuditAsync);

        _ = RunAuditAsync();
    }

    public async Task RunAuditAsync()
    {
        IsAuditing = true;
        SummaryText = "Running security checks...";
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
                    Title = "C# Antivirus Engine Status",
                    Description = engineReady ? "C# Standalone Antivirus scan engine is initialized and active." : "C# Antivirus scan engine failed to initialize.",
                    Status = engineReady ? "pass" : "fail",
                    Suggestion = engineReady ? "Excellent. The scan engine is ready to scan files." : "Restart the application to reinitialize the engine.",
                    FixCommand = "Restart ClamUI"
                };
                if (!engineReady) issues++;

                // Check 2: ClamAV Database Definitions Health
                bool definitionsActive = false;
                string dbStatus = "Definitions missing.";
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
                            dbStatus = $"Definitions are active (Last updated: {lastWrite:yyyy-MM-dd HH:mm})";
                        }
                        else
                        {
                            definitionsActive = false;
                            dbStatus = $"Definitions are outdated (Last updated: {lastWrite:yyyy-MM-dd HH:mm})";
                        }
                        break;
                    }
                }

                var dbItem = new AuditItem
                {
                    Title = "Virus Definitions Status",
                    Description = dbStatus,
                    Status = definitionsActive ? "pass" : "warning",
                    Suggestion = definitionsActive ? "Virus signatures are up-to-date." : "Go to the Database tab and click 'Update Definitions' to download threat signatures.",
                    FixCommand = "Database tab -> Update Definitions"
                };
                if (!definitionsActive) issues++;

                // Check 3: Windows Defender Security Service
                bool defenderRunning = IsServiceRunning("WinDefend");
                var defenderItem = new AuditItem
                {
                    Title = "Windows Defender Security",
                    Description = defenderRunning ? "Windows Defender Antivirus service is active." : "Windows Defender Antivirus service is stopped or disabled.",
                    Status = defenderRunning ? "pass" : "warning",
                    Suggestion = defenderRunning ? "System antivirus shield is active." : "Enable Windows Defender real-time protection to maintain active defense.",
                    FixCommand = "powershell Start-Service WinDefend"
                };
                if (!defenderRunning) issues++;

                // Check 4: Windows Firewall Active State
                bool firewallRunning = IsServiceRunning("MpsSvc");
                var firewallItem = new AuditItem
                {
                    Title = "Windows Firewall Status",
                    Description = firewallRunning ? "Windows Firewall Service is active and managing traffic." : "Windows Firewall Service is stopped or inactive.",
                    Status = firewallRunning ? "pass" : "fail",
                    Suggestion = firewallRunning ? "Network boundary protection is active." : "Enable Windows Firewall to protect system ports from unauthorized connections.",
                    FixCommand = "powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
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
            SummaryText = issues == 0 
                ? "All security checks passed. System is protected." 
                : $"{issues} security issues need attention.";
        }
        catch (Exception ex)
        {
            SummaryText = "Audit check aborted due to error.";
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
