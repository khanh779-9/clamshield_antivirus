using System.Windows.Controls;

namespace clamshield_antivirus.Views;

public partial class EngineView : UserControl
{
    public EngineView()
    {
        InitializeComponent();
    }

    private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (sender is TextBox textBox)
        {
            textBox.ScrollToEnd();
        }
    }
}