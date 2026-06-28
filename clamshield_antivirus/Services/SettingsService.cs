using System;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;

namespace clamshield_antivirus.Services;

public class SettingsService
{
    private static readonly string AppDataDir = AppDomain.CurrentDomain.BaseDirectory;
    private static readonly string SettingsFile = Path.Combine(AppDataDir, "settings.json");

    private Dictionary<string, object> _settings = new();
    private static readonly object _lock = new();

    public SettingsService()
    {
        Load();
    }

    public void Load()
    {
        lock (_lock)
        {
            try
            {
                if (!Directory.Exists(AppDataDir))
                {
                    Directory.CreateDirectory(AppDataDir);
                }

                if (File.Exists(SettingsFile))
                {
                    string json = File.ReadAllText(SettingsFile);
                    var deserialized = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    if (deserialized != null)
                    {
                        _settings = deserialized;
                    }
                }
                else
                {
                    // Default settings
                    _settings = new Dictionary<string, object>
                    {
                        { "ClamAvPath", string.Empty },
                        { "AutoQuarantine", false },
                        { "ExclusionPatterns", new List<string>() },
                        { "ScanBackend", "native" },
                        { "DatabaseCustomUrls", new List<string>() },
                        { "DatabaseCustomNames", new List<string>() },
                        { "DatabaseMirrorUrls", new List<string>() },
                        { "DownloadMaxRetries", 3 },
                        { "AllMatchMode", false },
                        { "MaxFileSize", 104857600L },
                        { "MaxScanSize", 524288000L },
                        { "MaxRecursion", 16 },
                        { "MaxFiles", 10000 },
                        { "HeuristicAlerts", true },
                        { "ParseArchives", true },
                        { "ParsePe", true },
                        { "ParsePdf", true },
                        { "ParseMail", true },
                        { "ParseOle2", true },
                        { "ParseHtml", true },
                        { "ParseElf", true },
                        { "ParseSwf", true },
                        { "ParseRtf", true },
                        { "ForceOffline", false },
                        { "ContextMenuEnabled", false },
                        { "StartupEnabled", false },
                        { "ScheduleEnabled", false },
                        { "ScheduleTime", "20:00" },
                        { "ScheduleWeekly", true },
                        { "ScheduleDay", 0 },
                        { "RealtimeEnabled", false },
                        { "WatchFolders", string.Empty },
                        { "RealtimeExclusions", string.Empty }
                    };
                    Save();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load settings: {ex.Message}");
            }
        }
    }

    public void Save()
    {
        lock (_lock)
        {
            try
            {
                if (!Directory.Exists(AppDataDir))
                {
                    Directory.CreateDirectory(AppDataDir);
                }

                string json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SettingsFile, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to save settings: {ex.Message}");
            }
        }
    }

    public T Get<T>(string key, T defaultValue)
    {
        lock (_lock)
        {
            if (_settings.TryGetValue(key, out var value))
            {
                try
                {
                    if (value is JsonElement element)
                    {
                        return element.Deserialize<T>() ?? defaultValue;
                    }
                    return (T)Convert.ChangeType(value, typeof(T));
                }
                catch
                {
                    return defaultValue;
                }
            }
            return defaultValue;
        }
    }

    public void Set<T>(string key, T value)
    {
        lock (_lock)
        {
            if (value == null) return;
            _settings[key] = value;
            Save();
        }
    }
}
