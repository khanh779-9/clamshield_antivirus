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

        // Update initial tray icon based on current security status
        if (_mainWindow.DataContext is MainViewModel mainVm && 
            mainVm.NavigationItems.Count > 0 && 
            mainVm.NavigationItems[0].ViewModel is SecurityStatusViewModel statusVm)
        {
            UpdateIconByState(statusVm.StatusState);
        }
        else
        {
            UpdateIconByState("safe");
        }

        // Listen to language changes
        clamshield_antivirus.Helpers.LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                UpdateTrayLanguage();
            }
        };
    }

    private void UpdateTrayLanguage()
    {
        if (_trayIcon == null) return;
        _trayIcon.Text = clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Text"];
        
        if (_trayIcon.ContextMenuStrip != null)
        {
            var menu = _trayIcon.ContextMenuStrip;
            if (menu.Items.Count >= 4)
            {
                menu.Items[0].Text = clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Open"];
                menu.Items[1].Text = clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ScanNow"];
                // Index 2 is separator
                menu.Items[3].Text = clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Exit"];
            }
        }
    }

    private void InitializeTrayIcon()
    {
        _trayIcon = new NotifyIcon
        {
            Icon = GetAppIcon(),
            Text = clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Text"],
            Visible = true
        };

        _trayIcon.DoubleClick += (_, _) => ShowWindow();

        var contextMenu = new ContextMenuStrip();

        var openItem = new ToolStripMenuItem(clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Open"], null, (_, _) => ShowWindow());
        var scanItem = new ToolStripMenuItem(clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ScanNow"], null, async (_, _) => await QuickScanAsync());
        var separator = new ToolStripSeparator();
        var exitItem = new ToolStripMenuItem(clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Exit"], null, (_, _) => ExitApp());

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

    private async System.Threading.Tasks.Task QuickScanAsync()
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
                    clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ScanComplete"],
                    string.Format(clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ScanCompleteDesc"], result.FilesScanned, result.ThreatsFound),
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
            clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ConfirmExit"],
            clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ConfirmExitTitle"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            System.Windows.Application.Current.Shutdown();
        }
    }

    public void SetStatus(string status)
    {
        string fullText = $"{clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Text"]} - {status}";
        if (fullText.Length > 63)
        {
            fullText = fullText.Substring(0, 60) + "...";
        }
        _trayIcon!.Text = fullText;
    }

    public void SetProtected(bool isProtected)
    {
        UpdateIconByState(isProtected ? "safe" : "warning");
    }

    public void UpdateIconByState(string state)
    {
        if (_trayIcon == null) return;

        Icon? icon = null;
        string statusText = string.Empty;

        try
        {
            switch (state?.ToLowerInvariant())
            {
                case "safe":
                    icon = GetManifestIcon("clam_ok.ico");
                    statusText = clamshield_antivirus.Helpers.LocalizationService.Instance["SecurityStatus.SafeStatus"];
                    break;
                case "warning":
                    icon = GetManifestIcon("clam_warning.ico");
                    statusText = clamshield_antivirus.Helpers.LocalizationService.Instance["SecurityStatus.WarningStatus"];
                    break;
                case "danger":
                    icon = GetManifestIcon("clam_error.ico");
                    statusText = clamshield_antivirus.Helpers.LocalizationService.Instance["SecurityStatus.DangerStatus"];
                    break;
                case "loading":
                    icon = GetManifestIcon("clam_info.ico");
                    statusText = clamshield_antivirus.Helpers.LocalizationService.Instance["SecurityStatus.TitleLoading"];
                    break;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to load state icon {state}: {ex.Message}");
        }

        if (icon != null)
        {
            _trayIcon.Icon = icon;
        }
        else
        {
            _trayIcon.Icon = GetAppIcon();
        }

        if (!string.IsNullOrEmpty(statusText))
        {
            string fullText = $"{clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.Text"]} - {statusText}";
            if (fullText.Length > 63)
            {
                fullText = fullText.Substring(0, 60) + "...";
            }
            _trayIcon.Text = fullText;
        }
    }

    private static Icon? GetManifestIcon(string fileName)
    {
        try
        {
            using var stream = System.Reflection.Assembly.GetExecutingAssembly()
                .GetManifestResourceStream($"clamshield_antivirus.Resources.{fileName}");
            if (stream != null)
                return new Icon(stream);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error loading manifest icon {fileName}: {ex.Message}");
        }
        return null;
    }

    public void ShowThreatNotification(string filePath, string threatName)
    {
        _trayIcon?.ShowBalloonTip(
            5000,
            clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ThreatTitle"],
            string.Format(clamshield_antivirus.Helpers.LocalizationService.Instance["Tray.ThreatDesc"], System.IO.Path.GetFileName(filePath), threatName),
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
