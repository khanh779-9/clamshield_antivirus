using System.Windows;
using System.Windows.Controls;
using clamshield_antivirus.ViewModels;

namespace clamshield_antivirus.Views;

public partial class ScanView : UserControl
{
    public ScanView()
    {
        InitializeComponent();
    }

    private void UserControl_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            string[]? files = (string[]?)e.Data.GetData(DataFormats.FileDrop);
            if (files != null && DataContext is ScanViewModel viewModel)
            {
                foreach (string file in files)
                {
                    if (!viewModel.Targets.Contains(file))
                    {
                        viewModel.Targets.Add(file);
                    }
                }
            }
        }
    }
}
