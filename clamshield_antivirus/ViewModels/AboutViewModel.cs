using System;
using clamshield_antivirus.Helpers;

namespace clamshield_antivirus.ViewModels;

public class AboutViewModel : ViewModelBase
{
    public string AppVersion => "v1.1.0";
    public string EngineVersion => "ClamAV C# Core Engine (Optimized)";
    public string CopyrightText => $"© {DateTime.Now.Year} ClamUI Project. Open Source under GPL v2.";
    public string DatabaseInfo => "CVD của ClamAV";
    public string Author => "Khanh Tran";
    public string GithubUrl => "https://github.com/khanh779-9";
}
