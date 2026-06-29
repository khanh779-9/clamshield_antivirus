using System;
using System.Windows;
using clamshield_antivirus.Services;

namespace clamshield_antivirus
{
    public partial class MainWindow : Window
    {
        private SystemTrayService? _trayService;

        public MainWindow()
        {
            InitializeComponent();
            StateChanged += MainWindow_StateChanged;
            Closing += MainWindow_Closing;
            Loaded += MainWindow_Loaded;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _trayService = App.TrayService;

            if (App.Settings.Get("StartMinimized", false) && App.PendingScanTargets.Count == 0)
            {
                WindowState = WindowState.Minimized;
                Hide();
            }

            lock (App.PendingScanTargets)
            {
                if (App.PendingScanTargets.Count > 0)
                {
                    string target = App.PendingScanTargets[0];
                    App.PendingScanTargets.Clear();

                    if (DataContext is ViewModels.MainViewModel mainVm)
                    {
                        mainVm.HandleScanRequest(target);
                    }
                }
            }
        }

        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            if (BtnMaximize != null)
            {
                BtnMaximize.Content = WindowState == WindowState.Maximized ? "❐" : "▢";
            }

            if (WindowState == WindowState.Minimized && App.Settings.Get("MinimizeToTray", true))
            {
                Hide();
                WindowState = WindowState.Normal;
            }
        }

        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            if (App.Settings.Get("MinimizeToTrayOnClose", true))
            {
                e.Cancel = true;
                WindowState = WindowState.Minimized;
                Hide();
            }
            else
            {
                _trayService?.Dispose();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            SystemCommands.MinimizeWindow(this);
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (WindowState == WindowState.Maximized)
                SystemCommands.RestoreWindow(this);
            else
                SystemCommands.MaximizeWindow(this);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
