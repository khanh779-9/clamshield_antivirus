using System;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.Services;

public class LogService
{
    private static readonly string LogsDir = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "logs"
    );

    public LogService()
    {
        EnsureDirectoryExists();
    }

    private void EnsureDirectoryExists()
    {
        if (!Directory.Exists(LogsDir))
        {
            Directory.CreateDirectory(LogsDir);
        }
    }

    public async Task<LogEntry?> SaveLogAsync(LogEntry entry)
    {
        return await Task.Run(() =>
        {
            try
            {
                EnsureDirectoryExists();
                string filePath = Path.Combine(LogsDir, $"{entry.Id}.json");
                string json = JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(filePath, json);
                return entry;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to save log: {ex.Message}");
                return null;
            }
        });
    }

    public async Task<List<LogEntry>> GetLogsAsync()
    {
        return await Task.Run(() =>
        {
            var logs = new List<LogEntry>();
            try
            {
                EnsureDirectoryExists();
                var files = Directory.GetFiles(LogsDir, "*.json");
                foreach (var file in files)
                {
                    try
                    {
                        string json = File.ReadAllText(file);
                        var entry = JsonSerializer.Deserialize<LogEntry>(json);
                        if (entry != null)
                        {
                            logs.Add(entry);
                        }
                    }
                    catch
                    {
                        // Ignore corrupt logs
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to read logs: {ex.Message}");
            }

            return logs.OrderByDescending(l => l.Timestamp).ToList();
        });
    }

    public async Task<bool> ClearAllLogsAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                EnsureDirectoryExists();
                var files = Directory.GetFiles(LogsDir, "*.json");
                foreach (var file in files)
                {
                    File.Delete(file);
                }
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to clear logs: {ex.Message}");
                return false;
            }
        });
    }
}
