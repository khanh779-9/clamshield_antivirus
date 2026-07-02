using System;
using System.Windows;
using System.Windows.Controls;

namespace clamshield_antivirus.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
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