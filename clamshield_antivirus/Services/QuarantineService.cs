using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading.Tasks;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.Services;

public class QuarantineService
{
    private static readonly string QuarantineDir = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "quarantine"
    );
    private static readonly string KeyFile = Path.Combine(QuarantineDir, ".key");

    private byte[] _key;
    private byte[] _iv;

    public QuarantineService()
    {
        EnsureDirectoryExists();
        (_key, _iv) = LoadOrCreateKey();
    }

    private void EnsureDirectoryExists()
    {
        if (!Directory.Exists(QuarantineDir))
            Directory.CreateDirectory(QuarantineDir);
    }

    private (byte[] key, byte[] iv) LoadOrCreateKey()
    {
        if (File.Exists(KeyFile))
        {
            var data = File.ReadAllBytes(KeyFile);
            return (data.AsSpan(0, 32).ToArray(), data.AsSpan(32, 16).ToArray());
        }

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        var combined = new byte[48];
        aes.Key.CopyTo(combined, 0);
        aes.IV.CopyTo(combined, 32);
        File.WriteAllBytes(KeyFile, combined);

        return (aes.Key, aes.IV);
    }

    private byte[] Encrypt(byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        using var encryptor = aes.CreateEncryptor();
        return PerformCryptography(plaintext, encryptor);
    }

    private byte[] Decrypt(byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        using var decryptor = aes.CreateDecryptor();
        return PerformCryptography(ciphertext, decryptor);
    }

    private static byte[] PerformCryptography(byte[] data, ICryptoTransform transform)
    {
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    public async Task<QuarantineEntry?> QuarantineFileAsync(string filePath, string threatName)
    {
        return await Task.Run(() =>
        {
            try
            {
                EnsureDirectoryExists();

                if (!File.Exists(filePath))
                    throw new FileNotFoundException("Target file to quarantine not found.", filePath);

                var fileInfo = new FileInfo(filePath);
                var entryId = Guid.NewGuid().ToString();
                string destFilePath = Path.Combine(QuarantineDir, $"{entryId}.dat");
                string destMetadataPath = Path.Combine(QuarantineDir, $"{entryId}.json");

                byte[] plaintext = File.ReadAllBytes(filePath);
                byte[] ciphertext = Encrypt(plaintext);
                File.WriteAllBytes(destFilePath, ciphertext);

                File.Delete(filePath);

                var entry = new QuarantineEntry
                {
                    Id = entryId,
                    ThreatName = threatName,
                    OriginalPath = filePath,
                    QuarantinePath = destFilePath,
                    FileSize = fileInfo.Length,
                    QuarantineDate = DateTime.Now
                };

                string json = JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(destMetadataPath, json);

                return entry;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to quarantine file {filePath}: {ex.Message}");
                return null;
            }
        });
    }

    public async Task<bool> RestoreFileAsync(QuarantineEntry entry)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (!File.Exists(entry.QuarantinePath))
                    return false;

                byte[] ciphertext = File.ReadAllBytes(entry.QuarantinePath);
                byte[] plaintext = Decrypt(ciphertext);

                string? originalDir = Path.GetDirectoryName(entry.OriginalPath);
                if (originalDir != null && !Directory.Exists(originalDir))
                    Directory.CreateDirectory(originalDir);

                File.WriteAllBytes(entry.OriginalPath, plaintext);
                File.Delete(entry.QuarantinePath);

                string metadataPath = Path.Combine(QuarantineDir, $"{entry.Id}.json");
                if (File.Exists(metadataPath))
                    File.Delete(metadataPath);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to restore file {entry.OriginalPath}: {ex.Message}");
                return false;
            }
        });
    }

    public async Task<bool> DeleteFileAsync(QuarantineEntry entry)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (File.Exists(entry.QuarantinePath))
                    File.Delete(entry.QuarantinePath);

                string metadataPath = Path.Combine(QuarantineDir, $"{entry.Id}.json");
                if (File.Exists(metadataPath))
                    File.Delete(metadataPath);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to delete quarantined file: {ex.Message}");
                return false;
            }
        });
    }

    public async Task<List<QuarantineEntry>> GetAllEntriesAsync()
    {
        return await Task.Run(() =>
        {
            var entries = new List<QuarantineEntry>();
            try
            {
                EnsureDirectoryExists();

                var jsonFiles = Directory.GetFiles(QuarantineDir, "*.json");
                foreach (var jsonFile in jsonFiles)
                {
                    try
                    {
                        string json = File.ReadAllText(jsonFile);
                        var entry = JsonSerializer.Deserialize<QuarantineEntry>(json);
                        if (entry != null)
                            entries.Add(entry);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to list quarantined files: {ex.Message}");
            }

            return entries;
        });
    }
}
