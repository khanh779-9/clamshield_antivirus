using System.Collections.ObjectModel;
using System.Windows.Input;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class NavigationItem : ViewModelBase
{
    public string Title { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty;
    public ViewModelBase ViewModel { get; set; }

    public NavigationItem(string title, string icon, ViewModelBase viewModel)
    {
        Title = title;
        Icon = icon;
        ViewModel = viewModel;
    }
}

public class MainViewModel : ViewModelBase
{
    private ViewModelBase? _currentViewModel;
    private NavigationItem? _selectedNavigationItem;

    public ObservableCollection<NavigationItem> NavigationItems { get; } = new();

    public ViewModelBase? CurrentViewModel
    {
        get => _currentViewModel;
        set => SetProperty(ref _currentViewModel, value);
    }

    public NavigationItem? SelectedNavigationItem
    {
        get => _selectedNavigationItem;
        set
        {
            if (SetProperty(ref _selectedNavigationItem, value) && value != null)
            {
                CurrentViewModel = value.ViewModel;
            }
        }
    }

    public ICommand NavigateCommand { get; }

    public MainViewModel()
    {
        // Khởi tạo các ViewModels con
        var scanVm = new ScanViewModel();
        var protectorVm = new ProtectorViewModel();
        var dbVm = new DatabaseViewModel();
        var logsVm = new LogsViewModel();
        var compVm = new ComponentsViewModel();
        var quarVm = new QuarantineViewModel();
        var statsVm = new StatisticsViewModel();
        var auditVm = new AuditViewModel();

        // Tạo danh sách Navigation Items tương tự ClamUI trên Linux
        NavigationItems.Add(new NavigationItem("Scan", "🔍", scanVm));
        NavigationItems.Add(new NavigationItem("Protector", "🛡️", protectorVm));
        NavigationItems.Add(new NavigationItem("Database", "📦", dbVm));
        NavigationItems.Add(new NavigationItem("Logs", "📋", logsVm));
        NavigationItems.Add(new NavigationItem("Components", "⚙️", compVm));
        NavigationItems.Add(new NavigationItem("Quarantine", "☣️", quarVm));
        NavigationItems.Add(new NavigationItem("Statistics", "📊", statsVm));
        NavigationItems.Add(new NavigationItem("Audit", "🔒", auditVm));

        var settingsVm = new SettingsViewModel();
        NavigationItems.Add(new NavigationItem("Settings", "⚡", settingsVm));

        // Mặc định chọn Scan
        SelectedNavigationItem = NavigationItems[0];

        NavigateCommand = new RelayCommand(param =>
        {
            if (param is string target)
            {
                foreach (var item in NavigationItems)
                {
                    if (item.Title.Equals(target, StringComparison.OrdinalIgnoreCase))
                    {
                        SelectedNavigationItem = item;
                        break;
                    }
                }
            }
        });
    }
}
