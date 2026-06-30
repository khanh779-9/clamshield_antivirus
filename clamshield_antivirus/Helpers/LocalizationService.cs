using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;

namespace clamshield_antivirus.Helpers
{
    public class LocalizationService : INotifyPropertyChanged
    {
        private static LocalizationService? _instance;
        public static LocalizationService Instance => _instance ??= new LocalizationService();

        private readonly Dictionary<string, string> _translations = new(StringComparer.OrdinalIgnoreCase);
        private string _currentLanguageFile = "en.lng";
        private readonly string _languageDir;

        public event PropertyChangedEventHandler? PropertyChanged;

        public string CurrentLanguageFile => _currentLanguageFile;

        public class LanguageInfo
        {
            public string FileName { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
        }

        private LocalizationService()
        {
            _languageDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "language");
            EnsureLanguageDirectory();
        }

        public string this[string key]
        {
            get
            {
                if (_translations.TryGetValue(key, out var val))
                {
                    return val;
                }
                return key;
            }
        }

        private void EnsureLanguageDirectory()
        {
            if (!Directory.Exists(_languageDir))
            {
                Directory.CreateDirectory(_languageDir);
            }
        }

        public List<LanguageInfo> GetAvailableLanguages()
        {
            EnsureLanguageDirectory();
            var languages = new List<LanguageInfo>();
            var files = Directory.GetFiles(_languageDir, "*.lng");
            foreach (var file in files)
            {
                string filename = Path.GetFileName(file);
                string displayName = GetLanguageDisplayName(file) ?? Path.GetFileNameWithoutExtension(file);
                languages.Add(new LanguageInfo
                {
                    FileName = filename,
                    DisplayName = displayName
                });
            }
            return languages;
        }

        private string? GetLanguageDisplayName(string filePath)
        {
            try
            {
                foreach (var line in File.ReadLines(filePath))
                {
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("LanguageName", StringComparison.OrdinalIgnoreCase))
                    {
                        int eqIdx = trimmed.IndexOf('=');
                        if (eqIdx > 0)
                        {
                            return trimmed.Substring(eqIdx + 1).Trim();
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        public void Initialize(string defaultLanguageFile)
        {
            _currentLanguageFile = defaultLanguageFile;
            LoadLanguage(_currentLanguageFile);
        }

        public void ChangeLanguage(string filename)
        {
            if (string.IsNullOrEmpty(filename)) return;
            _currentLanguageFile = filename;
            LoadLanguage(_currentLanguageFile);
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        }

        private void LoadLanguage(string filename)
        {
            _translations.Clear();
            string filePath = Path.Combine(_languageDir, filename);
            if (!File.Exists(filePath))
            {
                if (filename.Equals("en.lng", StringComparison.OrdinalIgnoreCase))
                {
                    CreateDefaultEnglishFile(filePath);
                }
                else if (filename.Equals("vi.lng", StringComparison.OrdinalIgnoreCase))
                {
                    CreateDefaultVietnameseFile(filePath);
                }
            }

            if (File.Exists(filePath))
            {
                ParseIni(filePath);
            }
        }

        private void ParseIni(string filePath)
        {
            try
            {
                string currentSection = "Default";
                foreach (var line in File.ReadLines(filePath))
                {
                    string trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith(";") || trimmed.StartsWith("#"))
                        continue;

                    if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                    {
                        currentSection = trimmed.Substring(1, trimmed.Length - 2).Trim();
                        continue;
                    }

                    int eqIdx = trimmed.IndexOf('=');
                    if (eqIdx > 0)
                    {
                        string key = trimmed.Substring(0, eqIdx).Trim();
                        string val = trimmed.Substring(eqIdx + 1).Trim();
                        string fullKey = $"{currentSection}.{key}";
                        _translations[fullKey] = val;
                    }
                }
            }
            catch { }
        }

        public void CreateDefaultEnglishFile(string filePath)
        {
            string content = @"[Metadata]
LanguageName=English

[MainWindow]
Title=ClamUI - Windows Protection
Scan=Scan
Protector=Protector
Database=Database
Logs=Logs
Components=Components
Quarantine=Quarantine
Statistics=Statistics
Audit=Audit
Settings=Settings
About=About
Version=ClamUI v1.1.0
PoweredBy=Powered by ClamAV

[Settings]
Title=Settings
AppTheme=Application Theme
LangTitle=Language
LangDesc=Select system language (dynamic updates)
ScanOptions=Scan Options & Features
RealtimeTitle=Real-time Protection
WatchedFolders=Watched Folders
AddFolder=Add Folder
RemoveFolder=Remove
Exclusions=Exclusions
AddExclusion=Add Exclusion
GeneralSettings=General Settings
LogSettings=Log Settings
RealtimeScope=File Extension Filtering
ScanAllExt=Scan All Extensions
ScanAllExtDesc=Scans every file modified or created. May decrease system performance on heavy disk write operations.
ScanOptExt=Scan Optimized Extensions (Recommended)
ScanOptExtDesc=Only scans file types most vulnerable to malware, skipping safe media/data files (.png, .mp3, .txt).
ScanOptExtList=Default monitored extensions: .exe, .dll, .sys, .scr, .bat, .cmd, .ps1, .js, .msi, .pdf, .docx, .xlsx, .zip, .rar, .7z, .html, .lnk
CustomExt=Custom Extensions:
CustomExtToolTip=Enter extensions separated by commas or spaces. Example: .abc, .xyz

[About]
Title=About ClamUI
Subtitle=App information and system specifications
AppTitle=ClamUI for Windows
AppDesc=Modern Graphical User Interface for ClamAV Antivirus
SystemSpecs=System Specifications
AppVersionLabel=App Version:
CoreEngineLabel=Core Engine:
DbSourceLabel=Database Source:
DbSourceVal=CVD của ClamAV
LegalTitle=Legal & Developers
LegalDesc=ClamUI is a free and open-source project aimed at bringing the power of the ClamAV scanning engine to Windows desktop users with a smooth, native experience.
LeadDevLabel=Lead Developer:
Copyright=© 2026 ClamUI Project. Open Source under GPL v2.
";
            try
            {
                File.WriteAllText(filePath, content, System.Text.Encoding.UTF8);
            }
            catch { }
        }

        public void CreateDefaultVietnameseFile(string filePath)
        {
            string content = @"[Metadata]
LanguageName=Tiếng Việt

[MainWindow]
Title=ClamUI - Trình Diệt Virus Windows
Scan=Quét Virus
Protector=Bảo vệ
Database=Cơ sở dữ liệu
Logs=Nhật ký
Components=Thành phần
Quarantine=Khu cách ly
Statistics=Thống kê
Audit=Kiểm toán
Settings=Cài đặt
About=Giới thiệu
Version=ClamUI v1.1.0
PoweredBy=Phát triển trên nền tảng ClamAV

[Settings]
Title=Cài đặt
AppTheme=Giao diện ứng dụng
LangTitle=Ngôn ngữ
LangDesc=Chọn ngôn ngữ hệ thống (cập nhật tức thì)
ScanOptions=Tùy chọn Quét & Tính năng
RealtimeTitle=Bảo vệ Thời gian thực
WatchedFolders=Thư mục Giám sát
AddFolder=Thêm Thư mục
RemoveFolder=Xóa bỏ
Exclusions=Danh sách loại trừ
AddExclusion=Thêm loại trừ
GeneralSettings=Thiết lập chung
LogSettings=Cấu hình ghi nhật ký
RealtimeScope=Lọc phần mở rộng tệp tin
ScanAllExt=Quét tất cả các phần mở rộng
ScanAllExtDesc=Quét mọi tệp được sửa đổi hoặc tạo mới. Có thể làm giảm hiệu năng hệ thống khi ghi đĩa nặng.
ScanOptExt=Quét phần mở rộng tối ưu (Khuyên dùng)
ScanOptExtDesc=Chỉ quét các loại tệp có nguy cơ nhiễm độc cao, bỏ qua các tệp đa phương tiện/dữ liệu an toàn (.png, .mp3, .txt).
ScanOptExtList=Các phần mở rộng mặc định: .exe, .dll, .sys, .scr, .bat, .cmd, .ps1, .js, .msi, .pdf, .docx, .xlsx, .zip, .rar, .7z, .html, .lnk
CustomExt=Phần mở rộng tùy chọn:
CustomExtToolTip=Nhập các phần mở rộng phân tách bằng dấu phẩy hoặc dấu cách. Ví dụ: .abc, .xyz

[About]
Title=Giới thiệu ClamUI
Subtitle=Thông tin ứng dụng và thông số hệ thống
AppTitle=ClamUI cho Windows
AppDesc=Giao diện đồ họa hiện đại cho Trình diệt Virus ClamAV
SystemSpecs=Thông số hệ thống
AppVersionLabel=Phiên bản ứng dụng:
CoreEngineLabel=Nhân diệt virus:
DbSourceLabel=Nguồn cơ sở dữ liệu:
DbSourceVal=CVD của ClamAV
LegalTitle=Pháp lý & Nhà phát triển
LegalDesc=ClamUI là một dự án mã nguồn mở và miễn phí nhằm mang lại sức mạnh của nhân quét ClamAV cho người dùng Windows Desktop với giao diện mượt mà và trực quan.
LeadDevLabel=Nhà phát triển chính:
Copyright=© 2026 Dự án ClamUI. Mã nguồn mở phát hành theo giấy phép GPL v2.
";
            try
            {
                File.WriteAllText(filePath, content, System.Text.Encoding.UTF8);
            }
            catch { }
        }
    }
}
