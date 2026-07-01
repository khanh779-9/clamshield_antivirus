using System;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Windows.Input;
using clamshield_antivirus.Helpers;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.ViewModels;

public class ComponentsViewModel : ViewModelBase
{
    private bool _isChecking;

    public ObservableCollection<ComponentStatus> Components { get; } = new();

    public bool IsChecking
    {
        get => _isChecking;
        set => SetProperty(ref _isChecking, value);
    }

    public ICommand RefreshCommand { get; }

    public ComponentsViewModel()
    {
        RefreshCommand = new AsyncRelayCommand(RefreshStatusAsync);
        
        // Initial load
        _ = RefreshStatusAsync();

        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                _ = RefreshStatusAsync();
            }
        };
    }

    public async Task RefreshStatusAsync()
    {
        IsChecking = true;
        Components.Clear();

        try
        {
            await Task.Run(() =>
            {
                var list = App.ComponentDetection.GetAllComponentsStatus();
                
                // Invoke on UI Thread
                App.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var item in list)
                    {
                        Components.Add(item);
                    }
                });
            });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed checking components status: {ex.Message}");
        }
        finally
        {
            IsChecking = false;
        }
    }
}
