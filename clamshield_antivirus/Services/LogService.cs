using System;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading;
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

    private static readonly string EventsFile = Path.Combine(LogsDir, "events.jsonl");
    private const int MaxCachedEntries = 500;

    private List<LogEntry>? _cache;
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    public LogService()
    {
        EnsureDirectoryExists();
        _ = Task.Run(() => MigrateLegacyLogs());
    }

    private void EnsureDirectoryExists()
    {
        if (!Directory.Exists(LogsDir))
        {
            Directory.CreateDirectory(LogsDir);
        }
    }

    /// <summary>
    /// Migrate old per-file JSON logs into the single JSONL file.
    /// Runs once on startup if legacy .json files are found.
    /// </summary>
    private void MigrateLegacyLogs()
    {
        try
        {
            EnsureDirectoryExists();
            var jsonFiles = Directory.GetFiles(LogsDir, "*.json");
            if (jsonFiles.Length == 0) return;

            var migrated = new List<LogEntry>();
            foreach (var file in jsonFiles)
            {
                try
                {
                    string json = File.ReadAllText(file);
                    var entry = JsonSerializer.Deserialize<LogEntry>(json);
                    if (entry != null)
                    {
                        migrated.Add(entry);
                    }
                }
                catch { }
            }

            if (migrated.Count > 0)
            {
                // Sort by timestamp and append to JSONL
                migrated.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
                using var writer = new StreamWriter(EventsFile, append: true);
                foreach (var entry in migrated)
                {
                    string line = JsonSerializer.Serialize(entry);
                    writer.WriteLine(line);
                }
            }

            // Remove legacy files after successful migration
            foreach (var file in jsonFiles)
            {
                try { File.Delete(file); } catch { }
            }

            // Invalidate cache so next read picks up migrated data
            _cache = null;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Legacy log migration failed: {ex.Message}");
        }
    }

    public async Task<LogEntry?> SaveLogAsync(LogEntry entry)
    {
        await _cacheLock.WaitAsync();
        try
        {
            EnsureDirectoryExists();
            string line = JsonSerializer.Serialize(entry);
            await File.AppendAllTextAsync(EventsFile, line + Environment.NewLine);

            // Update cache
            var cache = await GetOrLoadCacheAsync();
            cache.Insert(0, entry); // newest first
            if (cache.Count > MaxCachedEntries)
            {
                cache.RemoveRange(MaxCachedEntries, cache.Count - MaxCachedEntries);
            }

            return entry;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to save log: {ex.Message}");
            return null;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    public async Task<List<LogEntry>> GetLogsAsync()
    {
        await _cacheLock.WaitAsync();
        try
        {
            var cache = await GetOrLoadCacheAsync();
            return cache.ToList(); // Return a copy to prevent external mutation
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    private async Task<List<LogEntry>> GetOrLoadCacheAsync()
    {
        if (_cache != null) return _cache;

        _cache = await Task.Run(() =>
        {
            var entries = new List<LogEntry>();
            try
            {
                EnsureDirectoryExists();
                if (!File.Exists(EventsFile)) return entries;

                var lines = File.ReadAllLines(EventsFile);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var entry = JsonSerializer.Deserialize<LogEntry>(line);
                        if (entry != null) entries.Add(entry);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to read logs: {ex.Message}");
            }

            // Sort newest first, keep only MaxCachedEntries
            entries.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));
            if (entries.Count > MaxCachedEntries)
            {
                entries.RemoveRange(MaxCachedEntries, entries.Count - MaxCachedEntries);
            }

            return entries;
        });

        return _cache;
    }

    public async Task<bool> ClearAllLogsAsync()
    {
        await _cacheLock.WaitAsync();
        try
        {
            EnsureDirectoryExists();

            // Delete the JSONL file
            if (File.Exists(EventsFile))
            {
                File.Delete(EventsFile);
            }

            // Also clean up any remaining legacy .json files
            var jsonFiles = Directory.GetFiles(LogsDir, "*.json");
            foreach (var file in jsonFiles)
            {
                try { File.Delete(file); } catch { }
            }

            _cache = new List<LogEntry>();
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to clear logs: {ex.Message}");
            return false;
        }
        finally
        {
            _cacheLock.Release();
        }
    }
}
