using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Collections.Generic;

namespace clamshield_antivirus.Services.UpdateSvc;

public class CvdInfo
{
    public string DatabaseName { get; set; } = string.Empty;
    public int Version { get; set; }
    public int SignatureCount { get; set; }
    public int FunctionalityLevel { get; set; }
    public int RequiredFunctionalityLevel { get; set; }
    public DateTime BuildTime { get; set; }
    public string Md5Signature { get; set; } = string.Empty;
    public string DigitalSignature { get; set; } = string.Empty;
    public string Builder { get; set; } = string.Empty;
}

public class CvdReader
{
    public class ExtractedFile
    {
        public string FileName { get; set; } = string.Empty;
        public byte[] Content { get; set; } = Array.Empty<byte>();
        public long FileSize { get; set; }
    }

    public static CvdInfo? ReadCvdHeader(string cvdFilePath)
    {
        try
        {
            using var fs = File.OpenRead(cvdFilePath);
            if (fs.Length <= 512)
                return null;

            byte[] headerBytes = new byte[512];
            fs.ReadExactly(headerBytes, 0, 512);

            string headerStr = Encoding.ASCII.GetString(headerBytes);
            return ParseCvdHeader(headerStr);
        }
        catch
        {
            return null;
        }
    }

    private static CvdInfo? ParseCvdHeader(string header)
    {
        if (string.IsNullOrEmpty(header)) return null;

        var parts = header.Split(':');
        if (parts.Length < 5) return null;

        var info = new CvdInfo();
        info.DatabaseName = parts[0].Trim();

        if (parts.Length > 2 && int.TryParse(parts[2].Trim(), out int ver))
            info.Version = ver;

        if (parts.Length > 3 && int.TryParse(parts[3].Trim(), out int sigCount))
            info.SignatureCount = sigCount;

        if (parts.Length > 4 && int.TryParse(parts[4].Trim(), out int funcLevel))
            info.FunctionalityLevel = funcLevel;

        bool timeParsed = false;
        if (parts.Length > 8 && long.TryParse(parts[8].Trim('\0', ' '), out long epoch))
        {
            try
            {
                info.BuildTime = DateTimeOffset.FromUnixTimeSeconds(epoch).LocalDateTime;
                timeParsed = true;
            }
            catch { }
        }

        if (!timeParsed && parts.Length > 1)
        {
            string dateStr = parts[1].Trim();
            if (DateTime.TryParseExact(dateStr, "dd MMM yyyy HH-mm zzzz", null,
                System.Globalization.DateTimeStyles.None, out var buildTime))
            {
                info.BuildTime = buildTime;
            }
            else
            {
                string cleaned = dateStr.Trim('\0', ' ');
                if (DateTime.TryParse(cleaned, out buildTime))
                    info.BuildTime = buildTime;
            }
        }

        if (parts.Length > 5)
            info.Md5Signature = parts[5].Trim('\0', ' ');

        if (parts.Length > 6)
            info.DigitalSignature = parts[6].Trim('\0', ' ');

        if (parts.Length > 7)
            info.Builder = parts[7].Trim('\0', ' ');

        return info;
    }

    public static List<ExtractedFile> ExtractCvd(string cvdFilePath)
    {
        var extractedFiles = new List<ExtractedFile>();

        using var fs = File.OpenRead(cvdFilePath);
        if (fs.Length <= 512)
            throw new InvalidDataException("Invalid CVD file size. File is too small.");

        fs.Seek(512, SeekOrigin.Begin);

        int zlibHeader1 = fs.ReadByte();
        int zlibHeader2 = fs.ReadByte();

        bool skipZlibHeader = (zlibHeader1 == 0x78 && (zlibHeader2 == 0x9C || zlibHeader2 == 0xDA || zlibHeader2 == 0x01));

        if (!skipZlibHeader && zlibHeader1 == 0x1F && zlibHeader2 == 0x8B)
        {
            fs.Seek(512, SeekOrigin.Begin);

            try
            {
                using var gzipStream = new GZipStream(fs, CompressionMode.Decompress, leaveOpen: true);
                using var ms = new MemoryStream();
                gzipStream.CopyTo(ms);
                byte[] tarBytes = ms.ToArray();
                ParseTarArchive(tarBytes, extractedFiles);
                return extractedFiles;
            }
            catch (Exception ex)
            {
                throw new InvalidDataException($"Failed to decompress gzip CVD body: {ex.Message}", ex);
            }
        }

        if (skipZlibHeader)
        {
            // Already consumed 2 bytes of zlib header, DeflateStream handles the rest
        }
        else
        {
            fs.Seek(512, SeekOrigin.Begin);
        }

        using var deflateStream = new DeflateStream(fs, CompressionMode.Decompress, leaveOpen: true);
        using var ms2 = new MemoryStream();

        try
        {
            deflateStream.CopyTo(ms2);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Failed to decompress CVD body: {ex.Message}", ex);
        }

        byte[] tarBytes2 = ms2.ToArray();
        ParseTarArchive(tarBytes2, extractedFiles);

        return extractedFiles;
    }

    private static void ParseTarArchive(byte[] tarBytes, List<ExtractedFile> extractedFiles)
    {
        int offset = 0;
        while (offset + 512 <= tarBytes.Length)
        {
            byte[] header = new byte[512];
            Array.Copy(tarBytes, offset, header, 0, 512);

            bool isEmpty = true;
            for (int i = 0; i < 100; i++)
            {
                if (header[i] != 0)
                {
                    isEmpty = false;
                    break;
                }
            }
            if (isEmpty) break;

            string fileName = Encoding.ASCII.GetString(header, 0, 100).Split('\0')[0].Trim();
            if (string.IsNullOrEmpty(fileName))
                break;

            long fileSize = ParseTarSize(header, 124, 12);
            if (fileSize < 0)
                break;

            offset += 512;

            if (offset + fileSize > tarBytes.Length)
                break;

            byte[] fileContent = new byte[fileSize];
            Array.Copy(tarBytes, offset, fileContent, 0, fileSize);

            extractedFiles.Add(new ExtractedFile
            {
                FileName = fileName,
                Content = fileContent,
                FileSize = fileSize
            });

            long padding = (512 - (fileSize % 512)) % 512;
            offset += (int)(fileSize + padding);
        }
    }

    private static long ParseTarSize(byte[] header, int start, int length)
    {
        string sizeStr = Encoding.ASCII.GetString(header, start, length);

        int nullPos = sizeStr.IndexOf('\0');
        if (nullPos > 0)
            sizeStr = sizeStr.Substring(0, nullPos);
        sizeStr = sizeStr.Trim();

        if (string.IsNullOrEmpty(sizeStr))
            return 0;

        if (sizeStr.Length > 0 && (sizeStr[0] == '\0' || sizeStr[0] == ' '))
        {
            sizeStr = sizeStr.TrimStart('\0', ' ');
        }

        if (sizeStr.StartsWith(" "))
            sizeStr = sizeStr.TrimStart();

        if (sizeStr.Length > 0 && sizeStr[0] >= (char)0x80)
        {
            long size = 0;
            for (int i = 0; i < length - 1 && (start + i) < header.Length; i++)
            {
                size = (size << 8) | header[start + i];
            }
            return size & 0x7FFFFFFFFFFFFFFF;
        }

        try
        {
            return Convert.ToInt64(sizeStr, 8);
        }
        catch
        {
            if (long.TryParse(sizeStr, out long decimalSize))
                return decimalSize;
            return -1;
        }
    }

    public static CvdInfo? ParseInfoFileHeader(string infoFilePath)
    {
        try
        {
            if (!File.Exists(infoFilePath)) return null;
            using var reader = new StreamReader(infoFilePath);
            string? firstLine = reader.ReadLine();
            if (firstLine == null) return null;

            // Tries ClamAV-VDB header format first
            if (firstLine.StartsWith("ClamAV-VDB:", StringComparison.OrdinalIgnoreCase))
                return ParseCvdHeader(firstLine);

            // Fallback: name:size:sha256 format (modern ClamAV .info files)
            var parts = firstLine.Split(':');
            if (parts.Length >= 3 && !string.IsNullOrEmpty(parts[0]))
            {
                return new CvdInfo
                {
                    DatabaseName = parts[0].Trim(),
                    Md5Signature = parts[^1].Trim()
                };
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    public static bool TryGetCvdInfoFromDbDir(string dbDir, out Dictionary<string, CvdInfo> cvdInfos)
    {
        cvdInfos = new Dictionary<string, CvdInfo>(StringComparer.OrdinalIgnoreCase);

        if (!Directory.Exists(dbDir))
            return false;

        foreach (var cvdFile in Directory.GetFiles(dbDir, "*.c*d"))
        {
            try
            {
                var info = ReadCvdHeader(cvdFile);
                if (info != null)
                {
                    string dbName = Path.GetFileNameWithoutExtension(cvdFile);
                    cvdInfos[dbName] = info;
                }
            }
            catch { }
        }

        foreach (var infoFile in Directory.GetFiles(dbDir, "*.info"))
        {
            try
            {
                string dbName = Path.GetFileNameWithoutExtension(infoFile);
                if (cvdInfos.ContainsKey(dbName)) continue;

                var info = ParseInfoFileHeader(infoFile);
                if (info != null)
                {
                    cvdInfos[dbName] = info;
                }
            }
            catch { }
        }

        return cvdInfos.Count > 0;
    }
}
