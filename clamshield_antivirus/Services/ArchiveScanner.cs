using System;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.Services;

public class ArchiveEntry
{
    public string FileName { get; set; } = string.Empty;
    public byte[] Content { get; set; } = Array.Empty<byte>();
    public long FileSize { get; set; }
    public bool IsEncrypted { get; set; }
}

public static class ArchiveScanner
{
    public static List<ArchiveEntry> ExtractArchive(string filePath, ClamFileType fileType)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return ExtractArchiveFromStream(fs, fileType);
        }
        catch
        {
            return entries;
        }
    }

    public static List<ArchiveEntry> ExtractArchiveFromStream(Stream stream, ClamFileType fileType)
    {
        long origPos = stream.Position;

        try
        {
            return fileType switch
            {
                ClamFileType.ZIP => ExtractZip(stream),
                ClamFileType.GZ => ExtractGzip(stream),
                ClamFileType.BZ => ExtractBZip2(stream),
                ClamFileType.XZ => ExtractXz(stream),
                ClamFileType.POSIX_TAR or ClamFileType.OLD_TAR => ExtractTar(stream),
                _ => new List<ArchiveEntry>()
            };
        }
        finally
        {
            stream.Position = origPos;
        }
    }

    private static List<ArchiveEntry> ExtractZip(Stream stream)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
            foreach (var entry in archive.Entries)
            {
                if (entry.Length == 0) continue;

                var archiveEntry = new ArchiveEntry
                {
                    FileName = entry.FullName,
                    FileSize = entry.Length
                };

                using var entryStream = entry.Open();
                using var ms = new MemoryStream();
                entryStream.CopyTo(ms);
                archiveEntry.Content = ms.ToArray();

                entries.Add(archiveEntry);
            }
        }
        catch (InvalidDataException)
        {
        }

        return entries;
    }

    private static List<ArchiveEntry> ExtractGzip(Stream stream)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            using var gzip = new GZipStream(stream, CompressionMode.Decompress, true);
            using var ms = new MemoryStream();
            gzip.CopyTo(ms);
            byte[] decompressed = ms.ToArray();

            string outName = "decompressed";
            entries.Add(new ArchiveEntry
            {
                FileName = outName,
                Content = decompressed,
                FileSize = decompressed.Length
            });
        }
        catch
        {
        }

        return entries;
    }

    private static List<ArchiveEntry> ExtractBZip2(Stream stream)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] decompressed = BZip2Decoder.Decompress(ms.ToArray());

            entries.Add(new ArchiveEntry
            {
                FileName = "decompressed",
                Content = decompressed,
                FileSize = decompressed.Length
            });
        }
        catch
        {
        }

        return entries;
    }

    private static List<ArchiveEntry> ExtractXz(Stream stream)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] decompressed = XzDecoder.Decompress(ms.ToArray());

            entries.Add(new ArchiveEntry
            {
                FileName = "decompressed",
                Content = decompressed,
                FileSize = decompressed.Length
            });
        }
        catch
        {
        }

        return entries;
    }

    private static List<ArchiveEntry> ExtractTar(Stream stream)
    {
        var entries = new List<ArchiveEntry>();

        try
        {
            byte[] tarBytes;
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                tarBytes = ms.ToArray();
            }

            int offset = 0;
            var entryNames = new HashSet<string>();

            while (offset + 512 <= tarBytes.Length)
            {
                byte[] header = new byte[512];
                Array.Copy(tarBytes, offset, header, 0, 512);

                bool isEmpty = true;
                for (int i = 0; i < 100; i++)
                {
                    if (header[i] != 0) { isEmpty = false; break; }
                }
                if (isEmpty) break;

                string fileName = System.Text.Encoding.ASCII.GetString(header, 0, 100).Split('\0')[0].Trim();
                if (string.IsNullOrEmpty(fileName)) break;

                long fileSize = ParseTarSize(header, 124, 12);
                if (fileSize < 0) break;

                offset += 512;

                if (offset + fileSize > tarBytes.Length) break;

                if (fileSize > 0)
                {
                    byte[] fileContent = new byte[fileSize];
                    Array.Copy(tarBytes, offset, fileContent, 0, fileSize);

                    string uniqueName = fileName;
                    int counter = 1;
                    while (!entryNames.Add(uniqueName))
                        uniqueName = $"{fileName}_{counter++}";

                    entries.Add(new ArchiveEntry
                    {
                        FileName = uniqueName,
                        Content = fileContent,
                        FileSize = fileSize
                    });
                }

                long padding = (512 - (fileSize % 512)) % 512;
                offset += (int)(fileSize + padding);
            }
        }
        catch
        {
        }

        return entries;
    }

    private static long ParseTarSize(byte[] header, int start, int length)
    {
        string sizeStr = System.Text.Encoding.ASCII.GetString(header, start, length);
        int nullPos = sizeStr.IndexOf('\0');
        if (nullPos > 0) sizeStr = sizeStr.Substring(0, nullPos);
        sizeStr = sizeStr.Trim();

        if (string.IsNullOrEmpty(sizeStr)) return 0;

        if (sizeStr.Length > 0 && sizeStr[0] >= 0x80)
        {
            long size = 0;
            for (int i = 0; i < length - 1 && (start + i) < header.Length; i++)
                size = (size << 8) | header[start + i];
            return size & 0x7FFFFFFFFFFFFFFF;
        }

        try
        {
            return Convert.ToInt64(sizeStr, 8);
        }
        catch
        {
            return long.TryParse(sizeStr, out long decimalSize) ? decimalSize : -1;
        }
    }

    public static bool IsEncryptedArchive(string filePath, ClamFileType fileType)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return fileType switch
            {
                ClamFileType.ZIP => CheckZipEncrypted(fs),
                ClamFileType.RAR => CheckRarEncrypted(fs),
                ClamFileType.S7Z => Check7zEncrypted(fs),
                _ => false
            };
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckZipEncrypted(Stream stream)
    {
        try
        {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
            foreach (var entry in archive.Entries)
            {
                if ((entry.ExternalAttributes & 0x1) != 0)
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static bool CheckRarEncrypted(Stream stream)
    {
        try
        {
            byte[] magic = new byte[8];
            stream.ReadExactly(magic, 0, Math.Min(8, (int)stream.Length));

            if (magic[0] == 0x52 && magic[1] == 0x61 && magic[2] == 0x72 && magic[3] == 0x21)
            {
                stream.Position = 0;
                byte[] header = new byte[32];
                stream.ReadExactly(header, 0, Math.Min(32, (int)stream.Length));
                return (header[9] & 0x08) != 0;
            }
        }
        catch { }
        return false;
    }

    private static bool Check7zEncrypted(Stream stream)
    {
        try
        {
            byte[] magic = new byte[32];
            stream.ReadExactly(magic, 0, Math.Min(32, (int)stream.Length));

            if (magic[0] == 0x37 && magic[1] == 0x7A && magic[2] == 0xBC && magic[3] == 0xAF)
            {
                stream.Position = 0;
                byte[] data = new byte[Math.Min(stream.Length, 4096)];
                stream.ReadExactly(data, 0, data.Length);

                string ascii = System.Text.Encoding.ASCII.GetString(data);
                return ascii.Contains("Encrypted", StringComparison.OrdinalIgnoreCase) ||
                       ascii.Contains("PASSWORD", StringComparison.Ordinal);
            }
        }
        catch { }
        return false;
    }
}
