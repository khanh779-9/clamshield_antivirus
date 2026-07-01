using System;
using System.Linq;
using System.Collections.ObjectModel;
using System.Windows.Input;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class NavigationItem : ViewModelBase
{
    private string _title = string.Empty;
    private string _icon = string.Empty;

    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value);
    }

    public string Icon
    {
        get => _icon;
        set => SetProperty(ref _icon, value);
    }

    public ViewModelBase ViewModel { get; set; }

    public NavigationItem(string title, string icon, ViewModelBase viewModel)
    {
        _title = title;
        _icon = icon;
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
        var statusVm = new SecurityStatusViewModel(this);
        var scanVm = new ScanViewModel();
        var protectorVm = new ProtectorViewModel();
        var dbVm = new DatabaseViewModel();
        var logsVm = new LogsViewModel();
        var compVm = new ComponentsViewModel();
        var quarVm = new QuarantineViewModel();
        var statsVm = new StatisticsViewModel();
        var auditVm = new AuditViewModel();

        // Tạo danh sách Navigation Items tương tự ClamUI trên Linux
        NavigationItems.Add(new NavigationItem("Security Status", "💻", statusVm));
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

        var aboutVm = new AboutViewModel();
        NavigationItems.Add(new NavigationItem("About", "ℹ️", aboutVm));

        // Mặc định chọn Security Status làm trang chủ
        SelectedNavigationItem = NavigationItems[0];

        // Listen for language changes and apply dynamically
        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                UpdateLanguage();
            }
        };
        UpdateLanguage();

        NavigateCommand = new RelayCommand(param =>
        {
            if (param is string target)
            {
                foreach (var item in NavigationItems)
                {
                    if (item.ViewModel.GetType().Name.Replace("ViewModel", "").Equals(target, StringComparison.OrdinalIgnoreCase) ||
                        item.Title.Equals(target, StringComparison.OrdinalIgnoreCase))
                    {
                        SelectedNavigationItem = item;
                        break;
                    }
                }
            }
        });
    }

    private void UpdateLanguage()
    {
        var statusItem = NavigationItems.FirstOrDefault(i => i.ViewModel is SecurityStatusViewModel);
        if (statusItem != null) statusItem.Title = LocalizationService.Instance["MainWindow.SecurityStatus"];

        var scanItem = NavigationItems.FirstOrDefault(i => i.ViewModel is ScanViewModel);
        if (scanItem != null) scanItem.Title = LocalizationService.Instance["MainWindow.Scan"];

        var protectorItem = NavigationItems.FirstOrDefault(i => i.ViewModel is ProtectorViewModel);
        if (protectorItem != null) protectorItem.Title = LocalizationService.Instance["MainWindow.Protector"];

        var dbItem = NavigationItems.FirstOrDefault(i => i.ViewModel is DatabaseViewModel);
        if (dbItem != null) dbItem.Title = LocalizationService.Instance["MainWindow.Database"];

        var logsItem = NavigationItems.FirstOrDefault(i => i.ViewModel is LogsViewModel);
        if (logsItem != null) logsItem.Title = LocalizationService.Instance["MainWindow.Logs"];

        var compItem = NavigationItems.FirstOrDefault(i => i.ViewModel is ComponentsViewModel);
        if (compItem != null) compItem.Title = LocalizationService.Instance["MainWindow.Components"];

        var quarItem = NavigationItems.FirstOrDefault(i => i.ViewModel is QuarantineViewModel);
        if (quarItem != null) quarItem.Title = LocalizationService.Instance["MainWindow.Quarantine"];

        var statsItem = NavigationItems.FirstOrDefault(i => i.ViewModel is StatisticsViewModel);
        if (statsItem != null) statsItem.Title = LocalizationService.Instance["MainWindow.Statistics"];

        var auditItem = NavigationItems.FirstOrDefault(i => i.ViewModel is AuditViewModel);
        if (auditItem != null) auditItem.Title = LocalizationService.Instance["MainWindow.Audit"];

        var settingsItem = NavigationItems.FirstOrDefault(i => i.ViewModel is SettingsViewModel);
        if (settingsItem != null) settingsItem.Title = LocalizationService.Instance["MainWindow.Settings"];

        var aboutItem = NavigationItems.FirstOrDefault(i => i.ViewModel is AboutViewModel);
        if (aboutItem != null) aboutItem.Title = LocalizationService.Instance["MainWindow.About"];
    }

    public void HandleScanRequest(string path)
    {
        if (string.IsNullOrEmpty(path)) return;

        var scanItem = NavigationItems.FirstOrDefault(item => item.ViewModel is ScanViewModel);
        if (scanItem != null)
        {
            SelectedNavigationItem = scanItem;
        }

        if (scanItem?.ViewModel is ScanViewModel scanVm)
        {
            if (scanVm.IsScanning)
            {
                try { scanVm.CancelScanCommand.Execute(null); } catch { }
            }

            scanVm.Targets.Clear();
            scanVm.Targets.Add(path);

            if (scanVm.StartScanCommand.CanExecute(null))
            {
                scanVm.StartScanCommand.Execute(null);
            }
        }
    }

    public void HandleProfileScanRequest(string profileId)
    {
        if (string.IsNullOrEmpty(profileId)) return;

        var scanItem = NavigationItems.FirstOrDefault(item => item.ViewModel is ScanViewModel);
        if (scanItem != null)
        {
            SelectedNavigationItem = scanItem;
        }

        if (scanItem?.ViewModel is ScanViewModel scanVm)
        {
            if (scanVm.IsScanning)
            {
                try { scanVm.CancelScanCommand.Execute(null); } catch { }
            }

            var profile = scanVm.Profiles.FirstOrDefault(p => p.Id == profileId);
            if (profile != null)
            {
                scanVm.SelectedProfile = profile;
                if (scanVm.StartScanCommand.CanExecute(null))
                {
                    scanVm.StartScanCommand.Execute(null);
                }
            }
        }
    }
}
