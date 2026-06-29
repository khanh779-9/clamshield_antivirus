using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace clamshield_antivirus.Views
{
    public enum AlertType { Threat, Warning, Info, Success }

    public partial class PopupAlert : Window
    {
        private static readonly List<PopupAlert> _activeAlerts = new();
        private static readonly Queue<(string? filePath, string? threatName, string title, string line1, string line2, string? line3, AlertType type)> _alertQueue = new();
        private readonly DispatcherTimer _timer;

        private PopupAlert(string? filePath, string? threatName, string title, string line1, string line2, string? line3, AlertType type)
        {
            InitializeComponent();

            TxtTitle.Text = title;
            TxtLine1.Text = line1;
            TxtLine1.ToolTip = line1;
            TxtLine2.Text = line2;
            TxtLine2.ToolTip = line2;

            if (line3 != null)
            {
                TxtLine3.Text = line3;
                TxtLine3.Visibility = Visibility.Visible;
            }
            else
            {
                TxtLine3.Visibility = Visibility.Collapsed;
            }

            ApplyAlertStyle(type);

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

            this.Loaded += (s, e) => RepositionAlerts();
            this.SizeChanged += (s, e) => RepositionAlerts();
        }

        private void ApplyAlertStyle(AlertType type)
        {
            System.Windows.Media.Brush accentBrush;
            System.Windows.Media.Brush? line3Brush = null;
            string iconData;

            switch (type)
            {
                case AlertType.Threat:
                    accentBrush = (System.Windows.Media.Brush)FindResource("ErrorBrush");
                    line3Brush = (System.Windows.Media.Brush)FindResource("SuccessBrush");
                    iconData = "M 10,1 L 18,4 L 18,10 C 18,15 14,18.5 10,19.5 C 6,18.5 2,15 2,10 L 2,4 Z M 7,7 L 13,13 M 13,7 L 7,13";
                    break;
                case AlertType.Warning:
                    accentBrush = (System.Windows.Media.Brush)FindResource("WarningBrush");
                    iconData = "M 12,2 L 22,20 L 2,20 Z M 12,8 L 12,14 M 12,16 L 12,17";
                    break;
                case AlertType.Info:
                    accentBrush = (System.Windows.Media.Brush)FindResource("InfoBrush");
                    iconData = "M 12,2 A 10,10 0 1,0 12,22 A 10,10 0 1,0 12,2 Z M 12,11 L 12,17 M 12,7 L 12,8";
                    break;
                default:
                    accentBrush = (System.Windows.Media.Brush)FindResource("SuccessBrush");
                    iconData = "M 12,2 A 10,10 0 1,0 12,22 A 10,10 0 1,0 12,2 Z M 7,12 L 10,15 L 17,8";
                    break;
            }

            AlertBorder.BorderBrush = accentBrush;
            AlertIcon.Stroke = accentBrush;
            TxtTitle.Foreground = accentBrush;

            if (line3Brush is not null)
                TxtLine3.Foreground = line3Brush;

            AlertIcon.Data = Geometry.Parse(iconData);
        }

        public static void ShowAlert(string filePath, string threatName)
        {
            Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                string title = "Real-Time Threat Blocked";
                string line1 = $"File: {Path.GetFileName(filePath)}";
                string line2 = $"Threat: {threatName}";
                string line3 = "Action: Quarantined";

                lock (_alertQueue)
                {
                    _alertQueue.Enqueue((filePath, threatName, title, line1, line2, line3, AlertType.Threat));
                }
                ShowNextAlertIfNeeded();
            }));
        }

        public static void ShowInfoAlert(string title, string message, AlertType type = AlertType.Info)
        {
            Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                lock (_alertQueue)
                {
                    _alertQueue.Enqueue((null, null, title, message, string.Empty, null, type));
                }
                ShowNextAlertIfNeeded();
            }));
        }

        public static void ShowInfoAlert(string title, string line1, string line2, AlertType type = AlertType.Info)
        {
            Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                lock (_alertQueue)
                {
                    _alertQueue.Enqueue((null, null, title, line1, line2, null, type));
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
                    if (_activeAlerts.Count > 0)
                        return;
                }

                (string? filePath, string? threatName, string title, string line1, string line2, string? line3, AlertType type) next;
                lock (_alertQueue)
                {
                    if (_alertQueue.Count == 0)
                        return;
                    next = _alertQueue.Dequeue();
                }

                var alert = new PopupAlert(next.filePath, next.threatName, next.title, next.line1, next.line2, next.line3, next.type);
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

                for (int i = 0; i < _activeAlerts.Count; i++)
                {
                    var alert = _activeAlerts[i];
                    double height = alert.ActualHeight;
                    if (height <= 0 || double.IsNaN(height))
                    {
                        height = 140;
                    }

                    double newLeft = workAreaRight - windowWidth - margin;
                    double newTop = currentY - (height + margin);

                    if (Math.Abs(alert.Left - newLeft) > 0.1)
                        alert.Left = newLeft;
                    if (Math.Abs(alert.Top - newTop) > 0.1)
                        alert.Top = newTop;

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
                    try { alert.Close(); } catch { }
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
                    _activeAlerts.Remove(this);
                RepositionAlerts();
            }
            ShowNextAlertIfNeeded();
        }
    }
}
