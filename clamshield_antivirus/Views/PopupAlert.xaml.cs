using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Threading;

namespace clamshield_antivirus.Views
{
    public partial class PopupAlert : Window
    {
        private static readonly List<PopupAlert> _activeAlerts = new();
        private static readonly Queue<(string filePath, string threatName)> _alertQueue = new();
        private readonly DispatcherTimer _timer;

        public PopupAlert(string filePath, string threatName)
        {
            InitializeComponent();

            TxtFileName.Text = $"File: {Path.GetFileName(filePath)}";
            TxtFileName.ToolTip = filePath;
            TxtThreatName.Text = $"Threat: {threatName}";

            // Auto close after 10 seconds
            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(10)
            };
            _timer.Tick += (s, e) =>
            {
                _timer.Stop();
                Close();
            };
            _timer.Start();

            // Hook window events for dynamic positioning and sizing
            this.Loaded += (s, e) => RepositionAlerts();
            this.SizeChanged += (s, e) => RepositionAlerts();
        }

        public static void ShowAlert(string filePath, string threatName)
        {
            Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                lock (_alertQueue)
                {
                    _alertQueue.Enqueue((filePath, threatName));
                }
                ShowNextAlertIfNeeded();
            }));
        }

        private static void ShowNextAlertIfNeeded()
        {
            Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                lock (_activeAlerts)
                {
                    // If an alert is already active, wait for it to close
                    if (_activeAlerts.Count > 0)
                    {
                        return;
                    }
                }

                (string filePath, string threatName) nextAlert;
                lock (_alertQueue)
                {
                    if (_alertQueue.Count == 0)
                    {
                        return;
                    }
                    nextAlert = _alertQueue.Dequeue();
                }

                var alert = new PopupAlert(nextAlert.filePath, nextAlert.threatName);
                lock (_activeAlerts)
                {
                    _activeAlerts.Add(alert);
                }
                alert.Show();
            }));
        }

        private static void RepositionAlerts()
        {
            lock (_activeAlerts)
            {
                double workAreaRight = SystemParameters.WorkArea.Right;
                double workAreaBottom = SystemParameters.WorkArea.Bottom;
                double margin = 10;
                double windowWidth = 360;

                double currentY = workAreaBottom;

                // Position from bottom to top
                for (int i = 0; i < _activeAlerts.Count; i++)
                {
                    var alert = _activeAlerts[i];
                    double height = alert.ActualHeight;
                    if (height <= 0 || double.IsNaN(height))
                    {
                        height = 140; // Default estimate fallback
                    }

                    double newLeft = workAreaRight - windowWidth - margin;
                    double newTop = currentY - (height + margin);

                    // Set coordinates if they actually changed to minimize layout thrashing
                    if (Math.Abs(alert.Left - newLeft) > 0.1)
                    {
                        alert.Left = newLeft;
                    }
                    if (Math.Abs(alert.Top - newTop) > 0.1)
                    {
                        alert.Top = newTop;
                    }

                    currentY = newTop;
                }
            }
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void BtnCloseAll_Click(object sender, RoutedEventArgs e)
        {
            lock (_alertQueue)
            {
                _alertQueue.Clear();
            }
            lock (_activeAlerts)
            {
                var copy = _activeAlerts.ToList();
                foreach (var alert in copy)
                {
                    try
                    {
                        alert.Close();
                    }
                    catch { }
                }
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _timer.Stop();
            lock (_activeAlerts)
            {
                if (_activeAlerts.Contains(this))
                {
                    _activeAlerts.Remove(this);
                }
                RepositionAlerts();
            }
            ShowNextAlertIfNeeded();
        }
    }
}
