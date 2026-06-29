using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Color = System.Windows.Media.Color;

namespace clamshield_antivirus.Views;

public partial class AuditView : UserControl
{
    public AuditView()
    {
        InitializeComponent();
    }

    private void CopyCommand_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.CommandParameter is string commandText)
        {
            try
            {
                Clipboard.SetText(commandText);
                ModernMessageBox.Show("Command copied to clipboard.", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ModernMessageBox.Show($"Failed to copy command: {ex.Message}", "Copy Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}

public class IssuesToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool hasIssues)
        {
            return hasIssues 
                ? new SolidColorBrush(Color.FromRgb(0xF9, 0xE2, 0xAF)) // Amber/Warning
                : new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1)); // Green/Pass
        }
        return new SolidColorBrush(Color.FromRgb(0xA6, 0xAD, 0xC8)); // Gray
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class IssuesToIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool hasIssues)
        {
            return hasIssues ? "⚠️" : "🛡️";
        }
        return "?";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class AuditWarningToVisConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var status = value?.ToString()?.ToLowerInvariant();
        if (status == "warning" || status == "fail" || status == "error")
        {
            return Visibility.Visible;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
