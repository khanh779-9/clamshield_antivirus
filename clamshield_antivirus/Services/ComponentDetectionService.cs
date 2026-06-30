using System;
using System.IO;
using System.Collections.Generic;
using clamshield_antivirus.Models;
using clamshield_antivirus.Services.UpdateSvc;

namespace clamshield_antivirus.Services;

public class ComponentDetectionService
{
    private readonly SettingsService _settingsService;
    private static readonly string DbDir = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "database"
    );

    public ComponentDetectionService(SettingsService settingsService)
    {
        _settingsService = settingsService;
    }

    public string FindExecutable(string exeName)
    {
        try
        {
            string? pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathEnv))
            {
                foreach (string dir in pathEnv.Split(Path.PathSeparator))
                {
                    if (string.IsNullOrEmpty(dir)) continue;
                    try
                    {
                        string fullPath = Path.Combine(dir.Trim('"'), exeName);
                        if (File.Exists(fullPath))
                            return fullPath;
                        if (File.Exists(fullPath + ".exe"))
                            return fullPath + ".exe";
                    }
                    catch { }
                }
            }

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string[] commonPaths = new[]
            {
                Path.Combine(programFiles, "ClamAV", exeName),
                Path.Combine(programFiles, "ClamAV", exeName + ".exe"),
                Path.Combine(programFiles, "clamav", exeName),
                Path.Combine(programFiles, "clamav", exeName + ".exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", exeName),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", exeName + ".exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exeName),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exeName + ".exe"),
            };
            foreach (string path in commonPaths)
            {
                if (File.Exists(path))
                    return path;
            }
        }
        catch { }

        return "Built-in Engine";
    }

    public List<DbVersionInfo> GetDatabaseVersions()
    {
        var versions = new List<DbVersionInfo>();

        if (!Directory.Exists(DbDir))
            return versions;

        var cvdInfos = new Dictionary<string, CvdInfo>(StringComparer.OrdinalIgnoreCase);
        CvdReader.TryGetCvdInfoFromDbDir(DbDir, out cvdInfos);

        foreach (var kvp in cvdInfos)
        {
            string filePath = Path.Combine(DbDir, kvp.Key) ;
            string cvdPath = Path.ChangeExtension(filePath, ".cvd");
            string cldPath = Path.ChangeExtension(filePath, ".cld");

            string actualPath = File.Exists(cvdPath) ? cvdPath : (File.Exists(cldPath) ? cldPath : filePath);

            long fileSize = 0;
            try
            {
                if (File.Exists(actualPath))
                    fileSize = new FileInfo(actualPath).Length;
            }
            catch { }

            versions.Add(new DbVersionInfo
            {
                DatabaseName = kvp.Key,
                Version = kvp.Value.Version,
                SignatureCount = kvp.Value.SignatureCount,
                BuildTime = kvp.Value.BuildTime,
                Builder = kvp.Value.Builder,
                FilePath = actualPath,
                FileSize = fileSize
            });
        }

        string[] flatExts = { "*.hdb", "*.hsb", "*.ndb", "*.ldb", "*.mdb", "*.fp", "*.ign", "*.db" };
        foreach (var ext in flatExts)
        {
            foreach (var file in Directory.GetFiles(DbDir, ext))
            {
                string name = Path.GetFileNameWithoutExtension(file);
                if (versions.Exists(v => v.DatabaseName.Equals(name, StringComparison.OrdinalIgnoreCase)))
                    continue;

                long sz = 0;
                try { sz = new FileInfo(file).Length; } catch { }

                versions.Add(new DbVersionInfo
                {
                    DatabaseName = name,
                    Version = 0,
                    SignatureCount = 0,
                    BuildTime = DateTime.MinValue,
                    FilePath = file,
                    FileSize = sz
                });
            }
        }

        return versions;
    }

    public List<ComponentStatus> GetAllComponentsStatus()
    {
        bool dbInstalled = Directory.Exists(DbDir) &&
                           (Directory.GetFiles(DbDir, "*.c*d").Length > 0 ||
                            Directory.GetFiles(DbDir, "*.*db").Length > 0);

        string dbVersion = "Not downloaded";
        if (dbInstalled)
        {
            var cvdInfos = new Dictionary<string, CvdInfo>(StringComparer.OrdinalIgnoreCase);
            CvdReader.TryGetCvdInfoFromDbDir(DbDir, out cvdInfos);

            if (cvdInfos.Count > 0)
            {
                var parts = new List<string>();
                foreach (var kvp in cvdInfos)
                {
                    parts.Add($"{kvp.Key} v{kvp.Value.Version}");
                }
                dbVersion = string.Join(", ", parts);
            }
            else
            {
                var updateTime = _settingsService.Get("LastDatabaseUpdateTime", string.Empty);
                dbVersion = string.IsNullOrEmpty(updateTime) ? "Installed" : $"Updated: {updateTime}";
            }
        }

        return new List<ComponentStatus>
        {
            new ComponentStatus
            {
                ComponentId = "csharp_engine",
                Name = "C# Antivirus Scan Engine",
                Description = "Built-in high-performance file signature search engine (Aho-Corasick + Boyer-Moore).",
                IsInstalled = true,
                Version = "ClamUI Engine v1.1"
            },
            new ComponentStatus
            {
                ComponentId = "clamav_db",
                Name = "ClamAV Signature Database",
                Description = "Local virus signature definitions. Required to identify threats.",
                IsInstalled = dbInstalled,
                Version = dbVersion
            },
            new ComponentStatus
            {
                ComponentId = "quarantine_service",
                Name = "Quarantine Storage Service",
                Description = "Isolates infected files in secure encrypted storage.",
                IsInstalled = true,
                Version = "Active"
            },
            new ComponentStatus
            {
                ComponentId = "log_manager",
                Name = "Log History Manager",
                Description = "Persists operational scan metrics and results.",
                IsInstalled = true,
                Version = "Active"
            }
        };
    }
}
