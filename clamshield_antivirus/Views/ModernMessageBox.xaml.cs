using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace clamshield_antivirus.Views
{
    public partial class ModernMessageBox : Window
    {
        public MessageBoxResult Result { get; private set; } = MessageBoxResult.None;

        public ModernMessageBox(string messageBoxText, string caption, MessageBoxButton button, MessageBoxImage icon)
        {
            InitializeComponent();
            
            // Set Text
            MessageText.Text = messageBoxText;
            TitleText.Text = string.IsNullOrEmpty(caption) ? "Notification" : caption;

            // Set Icon
            SetupIcon(icon);

            // Set Buttons
            SetupButtons(button);

            // Enable dragging window by clicking and dragging anywhere on the dialog container
            MouseDown += (s, e) =>
            {
                if (e.ChangedButton == MouseButton.Left)
                {
                    DragMove();
                }
            };
        }

        private void SetupIcon(MessageBoxImage icon)
        {
            switch (icon)
            {
                case MessageBoxImage.Information:
                    IconPath.Data = Geometry.Parse("M 16,2 A 14,14 0 1,1 15.99,2 Z M 16,9 L 16,9.1 M 16,13 L 16,21");
                    IconPath.Stroke = (System.Windows.Media.Brush)FindResource("InfoBrush");
                    break;
                case MessageBoxImage.Warning:
                    IconPath.Data = Geometry.Parse("M 16,2 A 14,14 0 1,1 15.99,2 Z M 16,9 L 16,17 M 16,21.5 L 16,21.6");
                    IconPath.Stroke = (System.Windows.Media.Brush)FindResource("WarningBrush");
                    break;
                case MessageBoxImage.Error:
                    IconPath.Data = Geometry.Parse("M 16,2 A 14,14 0 1,1 15.99,2 Z M 11,11 L 21,21 M 21,11 L 11,21");
                    IconPath.Stroke = (System.Windows.Media.Brush)FindResource("ErrorBrush");
                    break;
                case MessageBoxImage.Question:
                    IconPath.Data = Geometry.Parse("M 16,2 A 14,14 0 1,1 15.99,2 Z M 12,11 C 12,6 20,6 20,11 C 20,14 16,14 16,17 M 16,21.5 L 16,21.6");
                    IconPath.Stroke = (System.Windows.Media.Brush)FindResource("InfoBrush");
                    break;
                default:
                    IconPath.Visibility = Visibility.Collapsed;
                    break;
            }
        }

        private void SetupButtons(MessageBoxButton button)
        {
            switch (button)
            {
                case MessageBoxButton.OK:
                    BtnOk.Visibility = Visibility.Visible;
                    BtnOk.IsDefault = true;
                    break;
                case MessageBoxButton.OKCancel:
                    BtnOk.Visibility = Visibility.Visible;
                    BtnOk.Margin = new Thickness(0, 0, 8, 0);
                    BtnCancel.Visibility = Visibility.Visible;
                    BtnOk.IsDefault = true;
                    BtnCancel.IsCancel = true;
                    break;
                case MessageBoxButton.YesNo:
                    BtnYes.Visibility = Visibility.Visible;
                    BtnNo.Visibility = Visibility.Visible;
                    BtnYes.IsDefault = true;
                    BtnNo.IsCancel = true;
                    break;
                case MessageBoxButton.YesNoCancel:
                    BtnYes.Visibility = Visibility.Visible;
                    BtnNo.Visibility = Visibility.Visible;
                    BtnCancel.Visibility = Visibility.Visible;
                    BtnYes.IsDefault = true;
                    BtnCancel.IsCancel = true;
                    break;
            }
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e)
        {
            Result = MessageBoxResult.OK;
            DialogResult = true;
            Close();
        }

        private void BtnYes_Click(object sender, RoutedEventArgs e)
        {
            Result = MessageBoxResult.Yes;
            DialogResult = true;
            Close();
        }

        private void BtnNo_Click(object sender, RoutedEventArgs e)
        {
            Result = MessageBoxResult.No;
            DialogResult = false;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            Result = MessageBoxResult.Cancel;
            DialogResult = false;
            Close();
        }

        public static MessageBoxResult Show(string messageBoxText, string caption = "", MessageBoxButton button = MessageBoxButton.OK, MessageBoxImage icon = MessageBoxImage.None)
        {
            return Show(null, messageBoxText, caption, button, icon);
        }

        public static MessageBoxResult Show(Window? owner, string messageBoxText, string caption = "", MessageBoxButton button = MessageBoxButton.OK, MessageBoxImage icon = MessageBoxImage.None)
        {
            MessageBoxResult result = MessageBoxResult.None;
            
            // Execute on the UI thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                var msgBox = new ModernMessageBox(messageBoxText, caption, button, icon);
                if (owner != null)
                {
                    msgBox.Owner = owner;
                }
                else if (Application.Current.MainWindow != null && Application.Current.MainWindow.IsVisible)
                {
                    msgBox.Owner = Application.Current.MainWindow;
                }
                msgBox.ShowDialog();
                result = msgBox.Result;
            });

            return result;
        }
    }
}
