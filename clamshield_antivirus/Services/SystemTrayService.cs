using System;
using System.Drawing;
using System.Windows;
using System.Windows.Forms;
using clamshield_antivirus.ViewModels;
using clamshield_antivirus.Views;

namespace clamshield_antivirus.Services;

public class SystemTrayService : IDisposable
{
    private NotifyIcon? _trayIcon;
    private Window _mainWindow;
    private bool _disposed;

    public bool MinimizeToTray
    {
        get => App.Settings.Get("MinimizeToTray", true);
        set => App.Settings.Set("MinimizeToTray", value);
    }

    public bool StartMinimized
    {
        get => App.Settings.Get("StartMinimized", false);
        set => App.Settings.Set("StartMinimized", value);
    }

    public SystemTrayService(Window mainWindow)
    {
        _mainWindow = mainWindow;
        InitializeTrayIcon();
    }

    private void InitializeTrayIcon()
    {
        _trayIcon = new NotifyIcon
        {
            Icon = GetAppIcon(),
            Text = "ClamUI - Antivirus Protection",
            Visible = true
        };

        _trayIcon.DoubleClick += (_, _) => ShowWindow();

        var contextMenu = new ContextMenuStrip();

        var openItem = new ToolStripMenuItem("Open ClamUI", null, (_, _) => ShowWindow());
        var scanItem = new ToolStripMenuItem("Scan Now", null, async (_, _) => await QuickScanAsync());
        var separator = new ToolStripSeparator();
        var exitItem = new ToolStripMenuItem("Exit", null, (_, _) => ExitApp());

        contextMenu.Items.Add(openItem);
        contextMenu.Items.Add(scanItem);
        contextMenu.Items.Add(separator);
        contextMenu.Items.Add(exitItem);

        _trayIcon.ContextMenuStrip = contextMenu;
    }

    private void ShowWindow()
    {
        _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized)
            _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
        _mainWindow.Topmost = true;
        _mainWindow.Topmost = false;
    }

    private async Task QuickScanAsync()
    {
        try
        {
            string[] drives = Environment.GetLogicalDrives();
            var targets = new System.Collections.Generic.List<string>();
            foreach (string drive in drives)
            {
                try
                {
                    var di = new System.IO.DirectoryInfo(drive);
                    if (di.Exists) targets.Add(drive);
                }
                catch { }
            }

            if (targets.Count == 0) return;

            var progress = new Progress<Models.ScanProgress>(p => { });
            var result = await App.ClamAv.ScanAsync(targets, null, progress, default);

            _ = System.Threading.Tasks.Task.Run(() =>
            {
                System.Threading.Thread.Sleep(100);
                _trayIcon?.ShowBalloonTip(
                    5000,
                    "Scan Complete",
                    $"{result.FilesScanned} files scanned. {result.ThreatsFound} threats found.",
                    result.ThreatsFound > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info);
            });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Quick scan failed: {ex.Message}");
        }
    }

    private static void ExitApp()
    {
        var result = ModernMessageBox.Show(
            "Are you sure you want to exit ClamUI? Real-time antivirus protection will be disabled.",
            "Confirm Exit",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            System.Windows.Application.Current.Shutdown();
        }
    }

    public void SetStatus(string status)
    {
        _trayIcon!.Text = $"ClamUI - {status}";
    }

    public void SetProtected(bool isProtected)
    {
        _trayIcon!.Icon = isProtected ? GetAppIcon() : GetWarningIcon();
    }

    public void ShowThreatNotification(string filePath, string threatName)
    {
        _trayIcon?.ShowBalloonTip(
            5000,
            "Real-Time Threat Blocked",
            $"File: {System.IO.Path.GetFileName(filePath)}\nThreat: {threatName}\nAction: Quarantined",
            ToolTipIcon.Warning);
    }

    private static Icon GetAppIcon()
    {
        try
        {
            using var stream = System.Reflection.Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("clamshield_antivirus.Resources.shield.ico");
            if (stream != null)
                return new Icon(stream);
        }
        catch { }
        return Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location)
               ?? SystemIcons.Shield;
    }

    private static Icon GetWarningIcon()
    {
        return SystemIcons.Warning;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _trayIcon?.Dispose();
            _trayIcon = null;
            _disposed = true;
        }
    }
}
