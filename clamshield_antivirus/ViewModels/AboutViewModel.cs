using System;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class AboutViewModel : ViewModelBase
{
    public string AppVersion => "v1.1.0";
    public string Author => "Khanh Tran";
    public string GithubUrl => "https://github.com/khanh779-9";

    public AboutViewModel()
    {
        LocalizationService.Instance.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == "Item[]")
            {
                OnPropertyChanged(string.Empty);
            }
        };
    }
}
