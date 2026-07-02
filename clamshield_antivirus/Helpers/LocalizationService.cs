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
            else
            {
                try
                {
                    string existing = File.ReadAllText(filePath);
                    if (!existing.Contains("MessageBox") || !existing.Contains("MessageBox.Ok") || !existing.Contains("Events.Title") || !existing.Contains("MainWindow.About"))
                    {
                        if (filename.Equals("en.lng", StringComparison.OrdinalIgnoreCase))
                            CreateDefaultEnglishFile(filePath);
                        else if (filename.Equals("vi.lng", StringComparison.OrdinalIgnoreCase))
                            CreateDefaultVietnameseFile(filePath);
                    }
                }
                catch { }
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
SecurityStatus=Security Status
Scan=Scan
Protector=Protector
Engine=Engine
Logs=Logs
Events=Events
Quarantine=Quarantine
Reports=Reports
Settings=Settings
About=About
Version=ClamUI v1.1.0
PoweredBy=Powered by ClamAV

[SecurityStatus]
Title=Security Status
Subtitle=Overall system health and protection status
SmartScan=Smart Scan
SmartScanDesc=Quickly check critical areas, active tasks, startup entries and downloads
SafeStatus=Your PC is protected
WarningStatus=Action recommended
DangerStatus=Threats detected!
NoThreatsText=No threats active on your system
ThreatsDetectedText={0} threat(s) detected!
RealtimeShieldText=Real-time Protection: {0}
DbVersionText=Virus Definitions: {0}
LastScanLabel=Last Scan: {0}
LastScanHeader=Last Scan
StatusActive=Active
StatusDisabled=Disabled
NeverScanned=Never scanned
TitleLoading=Loading Database...
MessageLoading=Loading virus signatures and compiling scan engine. Please wait.

[Settings]
Title=Settings
Subtitle=Configure ClamUI behavior and integrations
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
ExplorerIntegration=Explorer Integration
ExplorerIntegrationDesc=Add or remove the 'Scan with ClamUI' option from the Windows Explorer right-click context menu for files, folders, and drives.
ContextMenu=Context Menu
ContextMenuDesc=Right-click files/folders and scan instantly
Startup=Startup
StartupDesc=Automatically launch ClamUI when you sign in to Windows.
LaunchAtStartup=Launch at Startup
LaunchAtStartupDesc=Start ClamUI automatically when you log in
ScheduledScanning=Scheduled Scanning
ScheduledScanningDesc=Schedule automatic scans via Windows Task Scheduler. The app will scan all drives at the configured time.
EnableScheduledScan=Enable Scheduled Scan
EnableScheduledScanDesc=Run scans automatically on a schedule
Time=Time:
Weekly=Weekly
Sunday=Sunday
Monday=Monday
Tuesday=Tuesday
Wednesday=Wednesday
Thursday=Thursday
Friday=Friday
Saturday=Saturday
ScanOptionsTitle=Scan Options
ScanOptionsDesc=Configure limits, engines, and file types for scanning.
MaxFileSizeLimit=Maximum File Size Limit
MaxFileSizeLimitDesc=Skip scanning files exceeding this size limit
Mb= MB
ScanEngines=Scan Engines & Features
DeepScan=Deep Scan (All-Match Mode)
Heuristic=Heuristic Analysis
DetectPua=Detect PUA (Potentially Unwanted)
ScanArchives=Scan Compressed Archives
ScanPe=Scan PE Executables
ScanPdf=Scan PDF Documents
ScanOle2=Scan MS Office Documents
ScanHtml=Scan HTML Documents
ScanMail=Scan Mail Files
ScanElf=Scan Linux ELF Binaries
ScanSwf=Scan Adobe Flash Files
ScanRtf=Scan RTF Documents
AlertPdf=Alert Suspicious PDFs
AlertMacros=Alert Macro Documents
RealtimeProtection=Real-time Protection
RealtimeProtectionDesc=Monitor folders for new or modified files and scan them automatically for threats.
EnableRealtime=Enable Real-time Monitoring
EnableRealtimeDesc=Automatically scan new and modified files
FilesScannedLabel=Files scanned:
Browse=Browse
Add=Add
SelectFolderDescription=Select folder to monitor
AboutTitle=About ClamUI
AboutVersionLabel=Application Version:

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
LegalDesc=ClamUI is a free and open-source project aimed at bringing the power of the ClamAV scanning engine to Windows desktop users with a native experience.
LeadDevLabel=Lead Developer:
Copyright=© 2026 ClamUI Project. Open Source under GPL v2.
EngineVersionVal=ClamAV C# Core Engine (Optimized)

[Scan]
Title=Scan Targets
Subtitle=Select files or directories to scan for viruses
ProfileLabel=Scan Profile:
NoTargets=No targets added
NoTargetsDesc=Drag and drop files here, or use the buttons below
AddFiles=＋ Add Files
AddFolder=＋ Add Folder
ClearAll=🗑 Clear All
EicarTest=EICAR Test
StartScan=Start Scan
Cancel=Cancel
FilesScanned=Files Scanned
Directories=Directories
ThreatsFound=Threats Found
DetectedThreats=Detected Threats
QuarantineAll=Quarantine All
SearchTag=Search by threat name or path...
NewScan=New Scan
ProfileManualName=No Profile (Manual Scan)
ProfileManualDesc=Configure targets manually
ProfileQuickName=Quick Scan
ProfileQuickDesc=Scan system directories and user documents
ProfileFullName=Full Scan
ProfileFullDesc=Scan entire system
ProfileSmartName=Smart Scan
ProfileSmartDesc=Scan startup items, temporary folders and user downloads
StatusInitializing=Initializing scan...
StatusCancelled=Scan cancelled.
StatusQuarantining=Quarantining detected threats...
StatusQuarantinedCount=Quarantined {0} threats.
SelectFileTitle=Select File to Scan
SelectFolderTitle=Select Folder to Scan
EicarErrorTitle=EICAR Test Error
EicarErrorDesc=Failed to generate EICAR test file: {0}
ExcludedTitle=Path Excluded
ExcludedDesc=Added to exclusions:\n{0}

[Audit]
Title=System Security Audit
Subtitle=Check your Windows system security posture and get recommendations
Rerun=⟳ Re-run Audit
Copy=Copy
RunningChecks=Running security checks...
CheckingPosture=Checking system security posture...
AbortedError=Audit check aborted due to error.
AllPassed=All security checks passed. System is protected.
IssuesFound={0} security issues need attention.
EngineTitle=C# Antivirus Engine Status
EngineReady=C# Standalone Antivirus scan engine is initialized and active.
EngineFailed=C# Antivirus scan engine failed to initialize.
EngineReadySuggestion=Excellent. The scan engine is ready to scan files.
EngineFailedSuggestion=Restart the application to reinitialize the engine.
EngineFix=Restart ClamUI
DbTitle=Virus Definitions Status
DbActive=Definitions are active (Last updated: {0})
DbOutdated=Definitions are outdated (Last updated: {0})
DbMissing=Definitions missing.
DbActiveSuggestion=Virus signatures are up-to-date.
DbOutdatedSuggestion=Go to the Engine tab and click 'Update Definitions' to download threat signatures.
DbFix=Engine tab -> Update Definitions
DefenderTitle=Windows Defender Security
DefenderActive=Windows Defender Antivirus service is active.
DefenderInactive=Windows Defender Antivirus service is stopped or disabled.
DefenderActiveSuggestion=System antivirus shield is active.
DefenderInactiveSuggestion=Enable Windows Defender real-time protection to maintain active defense.
FirewallTitle=Windows Firewall Status
FirewallActive=Windows Firewall Service is active and managing traffic.
FirewallInactive=Windows Firewall Service is stopped or inactive.
FirewallActiveSuggestion=Network boundary protection is active.
FirewallInactiveSuggestion=Enable Windows Firewall to protect system ports from unauthorized connections.

[Components]
Title=ClamAV Components
Subtitle=Check the installation status of ClamAV core components
Refresh=⟳ Refresh
GuideTitle=Signature Database Update Guide
GuideStep1=1. Navigate to the 'Engine' tab in the left sidebar menu.
GuideStep2=2. Click the 'Update Definitions' button to download the latest ClamAV signatures.
GuideStep3=3. The C# Engine will automatically compile, decompress, and load signatures into memory.
GuideNote=Note: An offline backup signature containing standard EICAR test patterns is built-in by default.
csharp_engine.Name=C# Antivirus Scan Engine
csharp_engine.Desc=Built-in high-performance file signature search engine (Aho-Corasick + Boyer-Moore).
clamav_db.Name=ClamAV Signature Database
clamav_db.Desc=Local virus signature definitions. Required to identify threats.
quarantine_service.Name=Quarantine Storage Service
quarantine_service.Desc=Isolates infected files in secure encrypted storage.
log_manager.Name=Log History Manager
log_manager.Desc=Persists operational scan metrics and results.
VersionCSharpEngine=ClamUI Engine v1.1
VersionActive=Active
VersionNotDownloaded=Not downloaded
VersionInstalled=Installed
VersionUpdated=Updated: {0}

[Database]
Title=Database Update
Subtitle=Update ClamAV virus definitions to detect the latest threats
UpdaterStatus=Updater Status
EngineActive=C# Update Engine Active
LastUpdate=Last Database Update
DefinitionsActive=Definitions are active
ConsoleLog=Console Log Output
InfoTitle=ℹ️ Database Info
InstalledDbs=Installed Databases
CvdFormatTitle=CVD / CLD Database Format
CvdFormatDesc=Official ClamAV databases are compressed containers containing signature definitions (.ndb, .hdb, .ldb, etc.) along with verification files.
InfoFileFormatTitle=The .info File Format
InfoFileFormatDesc=Specifies information about the database files unpacked from a CVD or CLD archive. Used to validate container correctness and parse offline signature metadata.
FormatLabel=Format: name:size:sha256
FormatName=• name: The database file name.
FormatSize=• size: The size in bytes.
FormatHash=• sha256: SHA256 verification hash.
UpdateGuidelines=Update Guidelines
Guideline1=1. Click 'Update Definitions' to fetch the latest databases online.
Guideline2=2. The built-in C# engine will automatically decompress and load patterns into memory, bypassing the need for clamd/freshclam binaries.
ProgressText=Downloading & parsing database definitions. Please wait...
CancelUpdate=Cancel Update
UpdateDefinitions=Update Definitions
StatusReady=Ready to update definitions
StatusDownloading=Downloading virus definitions...
StatusFailed=Update failed
StatusCancelling=Cancelling update...
NoDbsInstalled=No databases installed
NeverUpdated=Never updated
LogStarting=Starting database update...
LogCancelled=Cancellation Requested

[Engine]
Title=ClamAV Engine & Database
Subtitle=Manage antivirus components and virus definition updates
SectionDbTitle=Database Management
SectionCompTitle=Component Status
GuideTitle=Signature Database Setup Guide
GuideStep1=1. The C# engine uses CVD/CLD signature databases stored in the 'database' folder.
GuideStep2=2. Click 'Update Definitions' above to download the latest ClamAV signatures.
GuideStep3=3. The C# Engine will automatically compile, decompress, and load signatures into memory.
GuideNote=Note: An offline backup signature containing standard EICAR test patterns is built-in by default.

[Reports]
Title=Reports & Audit
Subtitle=View scan statistics and security posture audit results
SectionStatsTitle=Scan Statistics
SectionAuditTitle=Security Audit

[Logs]
Title=Historical Logs
Subtitle=Previous scan and update operations log history
ClearAll=Clear All Logs
Copy=Copy
Export=Export
NoHistory=No log history
SearchTag=Search logs by keyword...
DetailTitle=Log Output Detail
TargetsLabel=Targets:
SelectLogPrompt=Select a log entry to view details.
ConfirmClear=Are you sure you want to permanently delete all scan and update logs? This cannot be undone.
ClearTitle=Clear Logs
ExportTitle=Export Log Details
ExportSuccess=Log exported successfully.
ExportSuccessTitle=Export Complete
ExportFailed=Failed to export log: {0}
ExportFailedTitle=Export Failed
Copied=Log details copied to clipboard.
CopiedTitle=Copied
CopyFailed=Failed to copy log: {0}
CopyFailedTitle=Copy Failed

[Events]
Title=Event History
Subtitle=Real-time system protection and scanning events log
ClearAll=Clear All Events
Copy=Copy Event
Export=Export Event
NoHistory=No event history recorded
SearchTag=Search events by keyword...
DetailTitle=Event Output Detail
TargetsLabel=Targets:
SelectLogPrompt=Select an event entry to view details.
ConfirmClear=Are you sure you want to permanently delete all events? This cannot be undone.
ClearTitle=Clear Events
ExportTitle=Export Event Details
ExportSuccess=Event details exported successfully.
ExportSuccessTitle=Export Complete
ExportFailed=Failed to export event: {0}
ExportFailedTitle=Export Failed
Copied=Event details copied to clipboard.
CopiedTitle=Copied
CopyFailed=Failed to copy event: {0}
CopyFailedTitle=Copy Failed
LoadMore=Load More Events

[Protector]
Title=Real-Time Protector
Subtitle=Continuous system-wide filesystem protection running with Administrator privileges
ShieldStatus=Real-Time Shield Status
AdminShield=Active System Shield (Admin)
FilesChecked=Files Checked
ThreatsBlocked=Threats Blocked
MonitoredAreas=Monitored Areas
ActivityLog=Recent Activity Log
ShieldOffline=Shield Offline
ShieldOfflineDesc=Enable Real-Time Protection to begin monitoring system drives.
SystemDrive=System Drive (Full Access)
StatusDisabled=Real-Time Protection Disabled
StatusRunning=Starting Real-Time Protection...
StatusProtected=System Protected
LogInitialized=Protector Service Initialized.
LogActive=System-wide Real-Time Protection Shield Active.
LogOffline=System-wide Real-Time Protection Shield Offline.
LogStarting=Starting Real-Time Protection Shield...
LogStopping=Disabling Real-Time Protection Shield...
LogStarted=Real-Time Protection Shield enabled. Monitoring all fixed system drives.
LogStopped=Real-Time Protection Shield disabled. System is unprotected.
LogScanned=Scanned: {0}
LogThreatBlocked=[WARNING] Blocked threat '{0}' in {1}

[Quarantine]
Title=Quarantine Storage
Subtitle=Secure storage for isolated threats
ClearAll=Clear All
ClearOld=Clear Old (30d+)
DeleteSelected=Delete Selected
Restore=Restore
Delete=Delete
RestoreFile=Restore File
DeletePermanently=Delete Permanently
NoFiles=No quarantined files
NoFilesDesc=Your system is secure and clean of isolated threats
ColFileName=File Name
ColOriginalPath=Original Location
ColThreatName=Threat Name
ColDateIsolated=Date Isolated
ColSize=Size
SearchTag=Search by threat name or path...
ItemCountOne=1 item
ItemCountMany={0} items
RestoreSuccess=File has been successfully restored to its original location.
RestoreSuccessTitle=Restore Complete
RestoreFailed=Failed to restore file. The original directory might be write-protected or unavailable.
RestoreFailedTitle=Restore Failed
ConfirmDelete=Are you sure you want to permanently delete this quarantined file? This action cannot be undone.
ConfirmDeleteTitle=Confirm Delete
DeleteFailed=Failed to delete the file.
DeleteFailedTitle=Delete Failed
NoItemsOld=No items are older than 30 days.
CleanupTitle=Cleanup
ConfirmCleanup=Are you sure you want to permanently delete all {0} quarantined files older than 30 days?
ConfirmCleanupTitle=Confirm Cleanup
CleanupSuccess=Cleaned up {0} old entries.
CleanupSuccessTitle=Cleanup Complete
ConfirmDeleteAll=Are you sure you want to permanently delete ALL {0} quarantined files? This action cannot be undone.
ConfirmDeleteAllTitle=Confirm Delete All
ClearSuccess=Deleted {0} entries. Quarantine is now empty.
ClearSuccessTitle=Clear Complete
NoItemsSelected=No items selected. Check the box next to items you want to delete.
NothingSelectedTitle=Nothing Selected
ConfirmDeleteSelected=Delete {0} selected quarantined file(s)? This action cannot be undone.
ConfirmDeleteSelectedTitle=Confirm Delete Selected
DeleteSelectedSuccess=Deleted {0} selected file(s).
DeleteSelectedSuccessTitle=Delete Complete
SelectedLabel=Selected:

[Statistics]
Title=Statistics Dashboard
Subtitle=Monitor scanning activity and system threat metrics
StatusLabel=SYSTEM PROTECTION STATUS
StatusDesc=Real-time status based on ClamAV logs and quarantined files database.
Overview=Protection Overview
TabDaily=Daily
TabWeekly=Weekly
TabMonthly=Monthly
TabAllTime=All Time
TotalScans=🔍 TOTAL SCANS RUN
ScansCompleted=Operations completed successfully
FilesScanned=📄 FILES SCANNED
ItemsInspected=Individual items inspected
ThreatsDetected=⚠️ THREATS DETECTED
ThreatsIsolated=Identified malware threats isolated
AvgScanTime=⏱️ AVERAGE SCAN TIME
TimePerScan=Minutes & seconds per operation
StatusChecking=Checking...
StatusNeverScanned=System has never been scanned
StatusOutdatedScan=Last scan was more than a week ago
StatusThreatsQuarantined={0} threat(s) quarantined. Action required.
StatusSystemProtected=System is protected. Last scan clean.

[Alert]
Title=Real-Time Threat Blocked
CloseAll=Close All
Close=Close
FileLabel=File:
ThreatLabel=Threat:
ActionLabel=Action: Quarantined
RealtimeEnabledTitle=Real-Time Protection Enabled
RealtimeEnabledDesc1=System-wide real-time antivirus shield is now active.
RealtimeEnabledDesc2=All file system changes will be monitored.
RealtimeDisabledTitle=Real-Time Protection Disabled
RealtimeDisabledDesc1=System-wide real-time antivirus shield has been turned off.
RealtimeDisabledDesc2=Your system may be vulnerable to real-time threats.
DbOutdatedTitle=Virus Database Outdated
DbOutdatedDesc1=Your virus definitions are out of date.
DbOutdatedDesc2=Go to the Engine tab and update to stay protected.

[MessageBox]
Info=Information
Warning=Warning
Error=Error
Question=Question
Ok=OK
Yes=Yes
No=No
Cancel=Cancel

[Tray]
Text=ClamUI - Antivirus Protection
Open=Open ClamUI
ScanNow=Scan Now
Exit=Exit
ScanComplete=Scan Complete
ScanCompleteDesc={0} files scanned. {1} threats found.
ConfirmExit=Are you sure you want to exit ClamUI? Real-time antivirus protection will be disabled.
ConfirmExitTitle=Confirm Exit
ThreatTitle=Real-Time Threat Blocked
ThreatDesc=File: {0}\nThreat: {1}\nAction: Quarantined

[Common]
Error=Error
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
SecurityStatus=Trạng thái an ninh
Scan=Quét Virus
Protector=Bảo vệ
Engine=Hệ thống
Logs=Nhật ký
Events=Sự kiện
Quarantine=Khu cách ly
Reports=Báo cáo
Settings=Cài đặt
About=Giới thiệu
Version=ClamUI v1.1.0
PoweredBy=Phát triển trên nền tảng ClamAV

[SecurityStatus]
Title=Trạng thái an ninh
Subtitle=Tình trạng bảo vệ toàn diện và phòng thủ hệ thống
SmartScan=Quét thông minh
SmartScanDesc=Kiểm tra nhanh các thư mục quan trọng, tiến trình đang hoạt động, mục khởi động và tải về
SafeStatus=Máy tính của bạn đang được bảo vệ
WarningStatus=Khuyến nghị cần xử lý
DangerStatus=Phát hiện mối đe dọa!
NoThreatsText=Không có mối đe dọa nào đang hoạt động trên hệ thống
ThreatsDetectedText=Phát hiện {0} mối đe dọa!
RealtimeShieldText=Bảo vệ thời gian thực: {0}
DbVersionText=Mẫu định nghĩa virus: {0}
LastScanLabel=Lần quét cuối: {0}
LastScanHeader=Lần quét cuối
StatusActive=Đang hoạt động
StatusDisabled=Đã tắt
NeverScanned=Chưa quét lần nào
TitleLoading=Đang nạp cơ sở dữ liệu...
MessageLoading=Đang nạp các định nghĩa virus và biên dịch nhân quét. Vui lòng đợi.

[Settings]
Title=Cài đặt
Subtitle=Cấu hình hành vi và tích hợp ClamUI
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
ScanOptExtDesc=Chỉ quét các loại tệp có nguy cơ nhiễm độc cao, bỏ qua các tệp đa phương tiện/dữ liệu an sau (.png, .mp3, .txt).
ScanOptExtList=Các phần mở rộng mặc định: .exe, .dll, .sys, .scr, .bat, .cmd, .ps1, .js, .msi, .pdf, .docx, .xlsx, .zip, .rar, .7z, .html, .lnk
CustomExt=Phần mở rộng tùy chọn:
CustomExtToolTip=Nhập các phần mở rộng phân tách bằng dấu phẩy hoặc dấu cách. Ví dụ: .abc, .xyz
ExplorerIntegration=Tích hợp Explorer
ExplorerIntegrationDesc=Thêm hoặc xóa tùy chọn 'Quét bằng ClamUI' khỏi menu ngữ cảnh chuột phải của Windows Explorer cho tệp, thư mục và ổ đĩa.
ContextMenu=Menu ngữ cảnh
ContextMenuDesc=Nhấp chuột phải vào tệp/thư mục và quét ngay lập tức
Startup=Khởi động
StartupDesc=Tự động khởi chạy ClamUI khi bạn đăng nhập vào Windows.
LaunchAtStartup=Khởi động cùng hệ thống
LaunchAtStartupDesc=Khởi động ClamUI tự động khi bạn đăng nhập
ScheduledScanning=Lập lịch Quét
ScheduledScanningDesc=Lập lịch quét tự động qua Windows Task Scheduler. Ứng dụng sẽ quét tất cả các ổ đĩa vào thời gian đã cấu hình.
EnableScheduledScan=Bật quét theo lịch
EnableScheduledScanDesc=Chạy quét tự động theo lịch trình
Time=Thời gian:
Weekly=Hàng tuần
Sunday=Chủ nhật
Monday=Thứ hai
Tuesday=Thứ ba
Wednesday=Thứ tư
Thursday=Thứ năm
Friday=Thứ sáu
Saturday=Thứ bảy
ScanOptionsTitle=Tùy chọn quét
ScanOptionsDesc=Cấu hình giới hạn, nhân quét và loại tệp để quét.
MaxFileSizeLimit=Giới hạn dung lượng tệp tối đa
MaxFileSizeLimitDesc=Bỏ qua quét các tệp vượt quá giới hạn dung lượng này
Mb= MB
ScanEngines=Công cụ quét & Tính năng
DeepScan=Quét sâu (Chế độ All-Match)
Heuristic=Phân tích Heuristic
DetectPua=Phát hiện ứng dụng không mong muốn (PUA)
ScanArchives=Quét các tệp lưu trữ nén
ScanPe=Quét các tệp thực thi PE
ScanPdf=Quét tài liệu PDF
ScanOle2=Quét tài liệu MS Office
ScanHtml=Quét tài liệu HTML
ScanMail=Quét các tệp thư điện tử
ScanElf=Quét tệp nhị phân Linux ELF
ScanSwf=Quét tệp Adobe Flash
ScanRtf=Quét tài liệu RTF
AlertPdf=Cảnh báo tệp PDF nghi ngờ
AlertMacros=Cảnh báo tài liệu chứa Macro
RealtimeProtection=Bảo vệ thời gian thực
RealtimeProtectionDesc=Giám sát các thư mục để tìm các tệp mới hoặc sửa đổi và tự động quét chúng.
EnableRealtime=Bật giám sát thời gian thực
EnableRealtimeDesc=Tự động quét các tệp mới tạo hoặc sửa đổi
FilesScannedLabel=Số tệp đã quét:
Browse=Duyệt...
Add=Thêm
SelectFolderDescription=Chọn thư mục để giám sát
AboutTitle=Giới thiệu ClamUI
AboutVersionLabel=Phiên bản ứng dụng:

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
EngineVersionVal=Nhân diệt virus ClamAV C# (Tối ưu hóa)

[Scan]
Title=Đối tượng Quét
Subtitle=Chọn tệp hoặc thư mục để quét virus
ProfileLabel=Hồ sơ quét:
NoTargets=Chưa thêm đối tượng quét nào
NoTargetsDesc=Kéo thả tệp vào đây, hoặc sử dụng các nút bên dưới
AddFiles=＋ Thêm tệp
AddFolder=＋ Thêm thư mục
ClearAll=Xóa danh sách
EicarTest=Mẫu EICAR
StartScan=Bắt đầu quét
Cancel=Hủy bỏ
FilesScanned=Tệp đã quét
Directories=Thư mục
ThreatsFound=Mối đe dọa tìm thấy
DetectedThreats=Mối đe dọa phát hiện
QuarantineAll=Cách ly tất cả
SearchTag=Tìm kiếm theo tên mối đe dọa hoặc đường dẫn...
NewScan=Quét mới
ProfileManualName=Không dùng hồ sơ (Quét thủ công)
ProfileManualDesc=Cấu hình đối tượng quét thủ công
ProfileQuickName=Quét nhanh
ProfileQuickDesc=Quét các thư mục hệ thống và tài liệu người dùng
ProfileFullName=Quét toàn bộ
ProfileFullDesc=Quét toàn bộ hệ thống
ProfileSmartName=Quét thông minh
ProfileSmartDesc=Quét các thư mục nguy cơ cao, mục khởi động và tệp tạm thời
StatusInitializing=Đang khởi tạo quét...
StatusCancelled=Quét bị hủy.
StatusQuarantining=Đang cách ly mối đe dọa đã phát hiện...
StatusQuarantinedCount=Đã cách ly {0} mối đe dọa.
SelectFileTitle=Chọn tệp để quét
SelectFolderTitle=Chọn thư mục để quét
EicarErrorTitle=Lỗi thử EICAR
EicarErrorDesc=Không tạo được tệp thử EICAR: {0}
ExcludedTitle=Đường dẫn đã loại trừ
ExcludedDesc=Đã thêm vào danh sách loại trừ:\n{0}

[Audit]
Title=Kiểm toán Bảo mật Hệ thống
Subtitle=Kiểm tra tình trạng bảo mật hệ thống Windows và nhận các khuyến nghị
Rerun=⟳ Chạy lại Kiểm toán
Copy=Sao chép
RunningChecks=Đang chạy kiểm tra bảo mật...
CheckingPosture=Đang kiểm tra trạng thái bảo mật hệ thống...
AbortedError=Hủy kiểm tra do có lỗi.
AllPassed=Tất cả các kiểm tra bảo mật đã qua. Hệ thống được bảo vệ.
IssuesFound=Có {0} vấn đề bảo mật cần chú ý.
EngineTitle=Trạng thái Nhân diệt virus C#
EngineReady=Nhân quét virus độc lập C# đã khởi tạo và đang hoạt động.
EngineFailed=Khởi tạo nhân quét virus C# thất bại.
EngineReadySuggestion=Tuyệt vời. Nhân quét đã sẵn sàng để quét tệp.
EngineFailedSuggestion=Khởi động lại ứng dụng để khởi tạo lại nhân quét.
EngineFix=Khởi động lại ClamUI
DbTitle=Trạng thái định nghĩa virus
DbActive=Định nghĩa đang hoạt động (Cập nhật cuối: {0})
DbOutdated=Định nghĩa đã cũ (Cập nhật cuối: {0})
DbMissing=Thiếu định nghĩa.
DbActiveSuggestion=Các mẫu nhận diện virus đã được cập nhật.
DbOutdatedSuggestion=Đi đến tab Hệ thống và nhấp 'Cập nhật mẫu' để tải về các mẫu nhận diện.
DbFix=Tab Hệ thống -> Cập nhật mẫu
DefenderTitle=Bảo mật Windows Defender
DefenderActive=Dịch vụ diệt virus Windows Defender đang hoạt động.
DefenderInactive=Dịch vụ diệt virus Windows Defender bị dừng hoặc tắt.
DefenderActiveSuggestion=Lá chắn diệt virus của hệ thống đang hoạt động.
DefenderInactiveSuggestion=Bật bảo vệ thời gian thực Windows Defender để duy trì phòng thủ tích cực.
FirewallTitle=Trạng thái Tường lửa Windows
FirewallActive=Dịch vụ Tường lửa Windows đang hoạt động và quản lý lưu lượng.
FirewallInactive=Dịch vụ Tường lửa Windows bị dừng hoặc không hoạt động.
FirewallActiveSuggestion=Bảo vệ ranh giới mạng đang hoạt động.
FirewallInactiveSuggestion=Bật Tường lửa Windows để bảo vệ các cổng hệ thống khỏi kết nối trái phép.

[Components]
Title=Thành phần ClamAV
Subtitle=Kiểm tra tình trạng cài đặt của các thành phần cốt lõi ClamAV
Refresh=⟳ Làm mới
GuideTitle=Hướng dẫn cập nhật Cơ sở dữ liệu Mẫu
GuideStep1=1. Di chuyển đến tab 'Hệ thống' trên menu thanh bên trái.
GuideStep2=2. Nhấp vào nút 'Cập nhật mẫu' để tải về các mẫu nhận diện ClamAV mới nhất.
GuideStep3=3. Trình quét C# sẽ tự động biên dịch, giải nén và tải các mẫu nhận diện vào bộ nhớ.
GuideNote=Lưu ý: Mẫu cơ sở dữ liệu ngoại tuyến sao lưu chứa các mẫu thử EICAR tiêu chuẩn đã được tích hợp sẵn theo mặc định.
csharp_engine.Name=Nhân Quét Virus C#
csharp_engine.Desc=Nhân tìm kiếm mẫu nhận diện tệp hiệu năng cao (Aho-Corasick + Boyer-Moore) tích hợp sẵn.
clamav_db.Name=Cơ sở dữ liệu mẫu ClamAV
clamav_db.Desc=Định nghĩa mẫu virus cục bộ. Yêu cầu để nhận diện các mối đe dọa.
quarantine_service.Name=Dịch vụ lưu trữ cách ly
quarantine_service.Desc=Cô lập các tệp bị nhiễm trong kho lưu trữ mã hóa an toàn.
log_manager.Name=Trình Quản lý Lịch sử Nhật ký
log_manager.Desc=Lưu trữ các chỉ số và kết quả quét hoạt động.
VersionCSharpEngine=Nhân ClamUI v1.1
VersionActive=Đang hoạt động
VersionNotDownloaded=Chưa tải xuống
VersionInstalled=Đã cài đặt
VersionUpdated=Đã cập nhật: {0}

[Database]
Title=Cập nhật Cơ sở dữ liệu
Subtitle=Cập nhật các định nghĩa mẫu virus ClamAV để phát hiện các mối đe dọa mới nhất
UpdaterStatus=Trạng thái Trình cập nhật
EngineActive=Trình cập nhật C# đang hoạt động
LastUpdate=Lần cập nhật cuối
DefinitionsActive=Mẫu nhận diện đang hoạt động
ConsoleLog=Kết quả Nhật ký Console
InfoTitle=ℹ️ Thông tin Cơ sở dữ liệu
InstalledDbs=Cơ sở dữ liệu đã cài đặt
CvdFormatTitle=Định dạng Cơ sở dữ liệu CVD / CLD
CvdFormatDesc=Cơ sở dữ liệu ClamAV chính thức là các tệp nén chứa các định nghĩa mẫu nhận diện (.ndb, .hdb, .ldb, v.v.) cùng với các tệp xác thực.
InfoFileFormatTitle=Định dạng Tệp .info
InfoFileFormatDesc=Cung cấp thông tin về các tệp cơ sở dữ liệu được giải nén từ kho lưu trữ CVD hoặc CLD. Dùng để xác thực tính toàn vẹn của container và phân tích siêu dữ liệu chữ ký ngoại tuyến.
FormatLabel=Định dạng: name:size:sha256
FormatName=• name: Tên tệp cơ sở dữ liệu.
FormatSize=• size: Kích thước tính theo byte.
FormatHash=• sha256: Mã băm xác thực SHA256.
UpdateGuidelines=Hướng dẫn Cập nhật
Guideline1=1. Nhấp vào 'Cập nhật mẫu' để tải về cơ sở dữ liệu mới nhất trực tuyến.
Guideline2=2. Nhân C# tích hợp sẽ tự động giải nén và nạp các mẫu vào bộ nhớ, không cần đến các tệp nhị phân clamd/freshclam.
ProgressText=Đang tải xuống và phân tích các định nghĩa cơ sở dữ liệu. Vui lòng đợi...
CancelUpdate=Hủy cập nhật
UpdateDefinitions=Cập nhật mẫu
StatusReady=Sẵn sàng cập nhật định nghĩa
StatusDownloading=Đang tải về định nghĩa virus...
StatusFailed=Cập nhật thất bại
StatusCancelling=Đang hủy cập nhật...
NoDbsInstalled=Chưa cài đặt cơ sở dữ liệu nào
NeverUpdated=Chưa bao giờ cập nhật
LogStarting=Bắt đầu cập nhật cơ sở dữ liệu...
LogCancelled=Yêu cầu hủy bỏ đã được gửi

[Engine]
Title=Nhân ClamAV & Cơ sở dữ liệu
Subtitle=Quản lý các thành phần diệt virus và cập nhật định nghĩa mẫu
SectionDbTitle=Quản lý Cơ sở dữ liệu
SectionCompTitle=Trạng thái Thành phần
GuideTitle=Hướng dẫn thiết lập Cơ sở dữ liệu Mẫu
GuideStep1=1. Nhân C# sử dụng cơ sở dữ liệu mẫu CVD/CLD được lưu trong thư mục 'database'.
GuideStep2=2. Nhấp 'Cập nhật mẫu' ở trên để tải về các mẫu nhận diện ClamAV mới nhất.
GuideStep3=3. Nhân C# sẽ tự động biên dịch, giải nén và nạp các mẫu nhận diện vào bộ nhớ.
GuideNote=Lưu ý: Mẫu cơ sở dữ liệu ngoại tuyến sao lưu chứa các mẫu thử EICAR tiêu chuẩn đã được tích hợp sẵn theo mặc định.

[Reports]
Title=Báo cáo & Kiểm toán
Subtitle=Xem thống kê quét và kết quả kiểm toán bảo mật hệ thống
SectionStatsTitle=Thống kê Quét
SectionAuditTitle=Kiểm toán Bảo mật

[Logs]
Title=Lịch sử Nhật ký
Subtitle=Lịch sử nhật ký của các hoạt động quét và cập nhật trước đó
ClearAll=Xóa tất cả nhật ký
Copy=Sao chép
Export=Xuất file
NoHistory=Không có lịch sử nhật ký
SearchTag=Tìm kiếm nhật ký bằng từ khóa...
DetailTitle=Chi tiết kết quả nhật ký
TargetsLabel=Đối tượng:
SelectLogPrompt=Chọn một nhật ký để xem chi tiết.
ConfirmClear=Bạn có chắc chắn muốn xóa vĩnh viễn tất cả các nhật ký quét và cập nhật? Hành động này không thể hoàn tác.
ClearTitle=Xóa nhật ký
MakeOld=Chọn tệp
ExportSuccess=Xuất nhật ký thành công.
ExportSuccessTitle=Xuất thành công
ExportFailed=Không thể xuất nhật ký: {0}
ExportFailedTitle=Xuất thất bại
Copied=Đã sao chép chi tiết nhật ký vào clipboard.
CopiedTitle=Đã sao chép
CopyFailed=Không thể sao chép nhật ký: {0}
CopyFailedTitle=Sao chép thất bại

[Events]
Title=Lịch sử Sự kiện
Subtitle=Nhật ký sự kiện quét virus và bảo vệ thời gian thực của hệ thống
ClearAll=Xóa toàn bộ Sự kiện
Copy=Sao chép Sự kiện
Export=Xuất Sự kiện
NoHistory=Không có lịch sử sự kiện nào được ghi nhận
SearchTag=Tìm kiếm sự kiện theo từ khóa...
DetailTitle=Chi tiết Nhật ký Sự kiện
TargetsLabel=Đối tượng:
SelectLogPrompt=Chọn một sự kiện để xem chi tiết.
ConfirmClear=Bạn có chắc chắn muốn xóa vĩnh viễn toàn bộ các sự kiện? Hành động này không thể hoàn tác.
ClearTitle=Xóa Sự kiện
ExportTitle=Xuất Chi tiết Sự kiện
ExportSuccess=Xuất chi tiết sự kiện thành công.
ExportSuccessTitle=Xuất thành công
ExportFailed=Không thể xuất sự kiện: {0}
ExportFailedTitle=Xuất thất bại
Copied=Đã sao chép chi tiết sự kiện vào clipboard.
CopiedTitle=Đã sao chép
CopyFailed=Không thể sao chép sự kiện: {0}
CopyFailedTitle=Sao chép thất bại
LoadMore=Tải thêm Sự kiện

[Protector]
Title=Bảo vệ Thời gian thực
Subtitle=Bảo vệ hệ thống tệp liên tục trên toàn hệ thống chạy với quyền Quản trị viên
ShieldStatus=Trạng thái Lá chắn Thời gian thực
AdminShield=Lá chắn hệ thống đang hoạt động (Admin)
FilesChecked=Tệp đã kiểm tra
ThreatsBlocked=Mối đe dọa đã chặn
MonitoredAreas=Khu vực Giám sát
ActivityLog=Nhật ký Hoạt động Gần đây
ShieldOffline=Lá chắn đang Ngoại tuyến
ShieldOfflineDesc=Bật Bảo vệ Thời gian thực để bắt đầu giám sát các ổ đĩa hệ thống.
SystemDrive=Ổ đĩa hệ thống (Toàn quyền)
StatusDisabled=Bảo vệ thời gian thực đã tắt
StatusRunning=Đang khởi động bảo vệ thời gian thực...
StatusProtected=Hệ thống được bảo vệ
LogInitialized=Dịch vụ bảo vệ đã khởi tạo.
LogActive=Lá chắn bảo vệ thời gian thực toàn hệ thống đang hoạt động.
LogOffline=Lá chắn bảo vệ thời gian thực toàn hệ thống đã ngoại tuyến.
LogStarting=Đang khởi động lá chắn bảo vệ thời gian thực...
LogStopping=Đang tắt lá chắn bảo vệ thời gian thực...
LogStarted=Đã bật lá chắn bảo vệ thời gian thực. Đang giám sát tất cả các ổ đĩa hệ thống cố định.
LogStopped=Đã tắt lá chắn bảo vệ thời gian thực. Hệ thống không được bảo vệ.
LogScanned=Đã quét: {0}
LogThreatBlocked=[CẢNH BÁO] Đã chặn mối đe dọa '{0}' tại {1}

[Quarantine]
Title=Khu vực Cách ly
Subtitle=Lưu trữ an toàn cho các mối đe dọa được cô lập
ClearAll=Xóa tất cả
ClearOld=Xóa file cũ (30 ngày+)
DeleteSelected=Xóa mục chọn
Restore=Khôi phục
Delete=Xóa
RestoreFile=Khôi phục tệp
DeletePermanently=Xóa vĩnh viễn
NoFiles=Không có tệp bị cách ly
NoFilesDesc=Hệ thống của bạn an toàn và sạch bóng các mối đe dọa
ColFileName=Tên tệp
ColOriginalPath=Vị trí ban đầu
ColThreatName=Tên mối đe dọa
ColDateIsolated=Ngày cách ly
ColSize=Kích thước
SearchTag=Tìm kiếm theo tên mối đe dọa hoặc đường dẫn...
ItemCountOne=1 mục
ItemCountMany={0} mục
RestoreSuccess=Tệp đã được khôi phục thành công về vị trí ban đầu.
RestoreSuccessTitle=Khôi phục hoàn tất
RestoreFailed=Khôi phục tệp thất bại. Thư mục ban đầu có thể bị ghi đè bảo vệ hoặc không khả dụng.
RestoreFailedTitle=Khôi phục thất bại
ConfirmDelete=Bạn có chắc chắn muốn xóa vĩnh viễn tệp cách ly này không? Hành động này không thể hoàn tác.
ConfirmDeleteTitle=Xác nhận xóa
DeleteFailed=Xóa tệp thất bại.
DeleteFailedTitle=Xóa thất bại
NoItemsOld=Không có mục nào cũ hơn 30 ngày.
CleanupTitle=Dọn dẹp
ConfirmCleanup=Bạn có chắc chắn muốn xóa vĩnh viễn tất cả {0} tệp cách ly cũ hơn 30 ngày không?
ConfirmCleanupTitle=Xác nhận dọn dẹp
CleanupSuccess=Đã dọn dẹp {0} mục cũ.
CleanupSuccessTitle=Dọn dẹp hoàn tất
ConfirmDeleteAll=Bạn có chắc chắn muốn xóa vĩnh viễn TẤT CẢ {0} tệp cách ly? Hành động này không thể hoàn tác.
ConfirmDeleteAllTitle=Xác nhận xóa tất cả
ClearSuccess=Đã xóa {0} mục. Khu cách ly hiện trống.
ClearSuccessTitle=Xóa sạch hoàn tất
NoItemsSelected=Chưa chọn mục nào. Đánh dấu vào ô bên cạnh mục bạn muốn xóa.
NothingSelectedTitle=Chưa chọn mục
ConfirmDeleteSelected=Xóa {0} tệp cách ly đã chọn? Hành động này không thể hoàn tác.
ConfirmDeleteSelectedTitle=Xác nhận xóa mục chọn
DeleteSelectedSuccess=Đã xóa {0} tệp được chọn.
DeleteSelectedSuccessTitle=Xóa hoàn tất
SelectedLabel=Đã chọn:

[Statistics]
Title=Bảng Thống kê
Subtitle=Giám sát hoạt động quét và các chỉ số mối đe dọa hệ thống
StatusLabel=TRẠNG THÁI BẢO VỆ HỆ THỐNG
StatusDesc=Trạng thái thời gian thực dựa trên nhật ký ClamAV và cơ sở dữ liệu tệp cách ly.
Overview=Tổng quan Bảo vệ
TabDaily=Hàng ngày
TabWeekly=Hàng tuần
TabMonthly=Hàng tháng
TabAllTime=Tất cả
TotalScans=🔍 TỔNG SỐ LƯỢT QUÉT
ScansCompleted=Hoạt động hoàn thành thành công
FilesScanned=📄 TỆP ĐÃ QUÉT
ItemsInspected=Các mục riêng lẻ được kiểm tra
ThreatsDetected=⚠️ MỐI ĐE DỌA PHÁT HIỆN
ThreatsIsolated=Các mối đe dọa phần mềm độc hại cô lập
AvgScanTime=⏱️ THỜI GIAN QUÉT TRUNG BÌNH
TimePerScan=Phút & giây mỗi hoạt động
StatusChecking=Đang kiểm tra...
StatusNeverScanned=Hệ thống chưa bao giờ được quét
StatusOutdatedScan=Lần quét cuối cùng là hơn một tuần trước
StatusThreatsQuarantined=Đã cách ly {0} mối đe dọa. Yêu cầu xử lý.
StatusSystemProtected=Hệ thống được bảo vệ. Lần quét cuối sạch sẽ.

[Alert]
Title=Đã ngăn chặn mối đe dọa thời gian thực
CloseAll=Đóng tất cả
Close=Đóng
FileLabel=Tệp:
ThreatLabel=Mối đe dọa:
ActionLabel=Hành động: Đã cách ly
RealtimeEnabledTitle=Bảo vệ thời gian thực đã bật
RealtimeEnabledDesc1=Lá chắn diệt virus thời gian thực trên toàn hệ thống hiện đã hoạt động.
RealtimeEnabledDesc2=Mọi thay đổi trên hệ thống tệp sẽ được giám sát.
RealtimeDisabledTitle=Bảo vệ thời gian thực đã tắt
RealtimeDisabledDesc1=Lá chắn diệt virus thời gian thực trên toàn hệ thống đã bị tắt.
RealtimeDisabledDesc2=Hệ thống của bạn có thể dễ bị tổn thương bởi các mối đe dọa thời gian thực.
DbOutdatedTitle=Cơ sở dữ liệu mẫu virus đã cũ
DbOutdatedDesc1=Các định nghĩa mẫu virus của bạn đã lỗi thời.
DbOutdatedDesc2=Đi đến tab Hệ thống và cập nhật để luôn được bảo vệ.

[MessageBox]
Info=Thông tin
Warning=Cảnh báo
Error=Lỗi
Question=Câu hỏi
Ok=Đồng ý
Yes=Có
No=Không
Cancel=Hủy

[Tray]
Text=ClamUI - Bảo vệ Máy tính
Open=Mở ClamUI
ScanNow=Quét ngay
Exit=Thoát
ScanComplete=Quét hoàn thành
ScanCompleteDesc=Đã quét {0} tệp. Phát hiện {1} mối đe dọa.
ConfirmExit=Bạn có chắc chắn muốn thoát ClamUI? Tính năng bảo vệ thời gian thực sẽ bị tắt.
ConfirmExitTitle=Xác nhận thoát
ThreatTitle=Đã chặn mối đe dọa thời gian thực
ThreatDesc=Tệp: {0}\nMối đe dọa: {1}\nHành động: Đã cách ly

[Common]
Error=Lỗi
";
            try
            {
                File.WriteAllText(filePath, content, System.Text.Encoding.UTF8);
            }
            catch { }
        }
    }
}
