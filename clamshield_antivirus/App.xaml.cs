using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Windows;
using clamshield_antivirus.Services;
using clamshield_antivirus.Models;
using clamshield_antivirus.Views;

namespace clamshield_antivirus;

public partial class App : Application
{
    public static SettingsService Settings { get; private set; } = null!;
    public static ComponentDetectionService ComponentDetection { get; private set; } = null!;
    public static ClamAvEngine Engine { get; private set; } = null!;
    public static ClamAvService ClamAv { get; private set; } = null!;
    public static QuarantineService Quarantine { get; private set; } = null!;
    public static LogService Logs { get; private set; } = null!;
    public static FreshclamService Freshclam { get; private set; } = null!;
    public static SystemTrayService TrayService { get; private set; } = null!;
    public static SingleInstanceService SingleInstance { get; private set; } = null!;
    public static RealTimeMonitor RealTimeMonitor { get; private set; } = null!;

    public static List<string> PendingScanTargets { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        SingleInstance = new SingleInstanceService();
        if (!SingleInstance.TryRun(e.Args))
        {
            Shutdown();
            return;
        }

        SingleInstance.ScanPathReceived += path =>
        {
            lock (PendingScanTargets)
            {
                PendingScanTargets.Add(path);
            }
            Dispatcher.BeginInvoke(() =>
            {
                if (MainWindow != null)
                {
                    if (MainWindow.WindowState == WindowState.Minimized)
                    {
                        MainWindow.WindowState = WindowState.Normal;
                    }
                    MainWindow.Show();
                    MainWindow.Activate();

                    if (MainWindow.DataContext is ViewModels.MainViewModel mainVm)
                    {
                        lock (PendingScanTargets)
                        {
                            PendingScanTargets.Clear();
                        }
                        mainVm.HandleScanRequest(path);
                    }
                }
            });
        };

        Settings = new SettingsService();
        ComponentDetection = new ComponentDetectionService(Settings);
        Engine = new ClamAvEngine();
        ClamAv = new ClamAvService(ComponentDetection, Settings);
        Quarantine = new QuarantineService();
        Logs = new LogService();
        Freshclam = new FreshclamService(ComponentDetection);
        RealTimeMonitor = new RealTimeMonitor();

        // Load database signatures in background immediately on startup
        _ = Task.Run(async () =>
        {
            try
            {
                await ClamAv.ReloadSignaturesAsync();
                System.Diagnostics.Debug.WriteLine($"Initial database signatures loaded successfully. Count: {Engine.TotalSignatures}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load database signatures on startup: {ex.Message}");
            }
        });

        RealTimeMonitor.ThreatDetected += (filePath, threatName) =>
        {
            PopupAlert.ShowAlert(filePath, threatName);
            _ = Task.Run(async () =>
            {
                try
                {
                    var logEntry = new LogEntry
                    {
                        Type = "Shield",
                        Timestamp = DateTime.Now,
                        Summary = $"Blocked {Path.GetFileName(filePath)}",
                        Status = "Infected",
                        Details = $"Path: {filePath}\nThreat: {threatName}\nAction: Quarantined automatically by Real-Time Shield."
                    };
                    await Logs.SaveLogAsync(logEntry);
                }
                catch { }
            });
        };

        RealTimeMonitor.ProtectionStarted += () =>
        {
            PopupAlert.ShowInfoAlert(
                "Real-Time Protection Enabled",
                "System-wide real-time antivirus shield is now active.",
                "All file system changes will be monitored.",
                AlertType.Success);
        };

        RealTimeMonitor.ProtectionStopped += () =>
        {
            PopupAlert.ShowInfoAlert(
                "Real-Time Protection Disabled",
                "System-wide real-time antivirus shield has been turned off.",
                "Your system may be vulnerable to real-time threats.",
                AlertType.Warning);
        };

        // Periodic database outdated check (every 6 hours)
        _ = Task.Run(async () =>
        {
            try
            {
                // Initial check after a short delay
                await Task.Delay(TimeSpan.FromSeconds(30));
                if (await Freshclam.IsDatabaseOutdatedAsync())
                {
                    PopupAlert.ShowInfoAlert(
                        "Virus Database Outdated",
                        "Your virus definitions are out of date.",
                        "Go to Database tab and update to stay protected.",
                        AlertType.Warning);
                }

                // Periodic checks
                using var periodicTimer = new PeriodicTimer(TimeSpan.FromHours(6));
                while (await periodicTimer.WaitForNextTickAsync())
                {
                    if (await Freshclam.IsDatabaseOutdatedAsync())
                    {
                        PopupAlert.ShowInfoAlert(
                            "Virus Database Outdated",
                            "Your virus definitions are out of date.",
                            "Go to Database tab and update to stay protected.",
                            AlertType.Warning);
                    }
                }
            }
            catch { }
        });

        if (Settings.Get("RealtimeEnabled", false))
        {
            var savedDirs = Settings.Get("WatchFolders", string.Empty);
            var watchDirs = new List<string>();
            if (!string.IsNullOrEmpty(savedDirs))
            {
                watchDirs.AddRange(savedDirs.Split('|', StringSplitOptions.RemoveEmptyEntries).Where(Directory.Exists));
            }
            
            var exclusionPatterns = Settings.Get("RealtimeExclusions", string.Empty)
                .Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();

            if (watchDirs.Count > 0)
            {
                _ = RealTimeMonitor.StartAsync(watchDirs, includeSubdirectories: false, exclusionPatterns: exclusionPatterns);
            }
            else
            {
                _ = RealTimeMonitor.StartSystemWideAsync(exclusionPatterns);
            }
        }

        var args = e.Args;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--scan", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                PendingScanTargets.Add(args[i + 1]);
                i++;
            }
        }

        var mainWindow = new MainWindow();
        TrayService = new SystemTrayService(mainWindow);
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SingleInstance?.Dispose();
        TrayService?.Dispose();
        RealTimeMonitor?.Dispose();
        base.OnExit(e);
    }
}
