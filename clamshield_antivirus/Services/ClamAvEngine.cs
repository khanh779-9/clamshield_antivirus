using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO.Compression;
using clamshield_antivirus.Models;

namespace clamshield_antivirus.Services;

public class HexPattern
{
    public string Name { get; set; } = string.Empty;
    public byte[] Pattern { get; set; } = Array.Empty<byte>();
    public string Offset { get; set; } = "*";
    public uint TargetType { get; set; }
    public bool IsPrefixOnly { get; set; }
    public byte[]? PrefixPattern { get; set; }
    public byte[]? SuffixPattern { get; set; }
    public int MinOffset { get; set; }
    public int MaxOffset { get; set; } = -1;
}

public class ScanOptions
{
    public bool AllMatchMode { get; set; }
    public bool HeuristicAlerts { get; set; } = true;
    public bool AlertPdf { get; set; } = false;
    public bool AlertMacros { get; set; } = false;
    public bool AlertSwf { get; set; } = false;
    public bool ParseArchives { get; set; } = true;
    public bool ParsePe { get; set; } = true;
    public bool ParsePdf { get; set; } = true;
    public bool ParseMail { get; set; } = true;
    public bool ParseOle2 { get; set; } = true;
    public bool ParseHtml { get; set; } = true;
    public bool ParseElf { get; set; } = true;
    public bool ParseSwf { get; set; } = true;
    public bool ParseRtf { get; set; } = true;
    public long MaxFileSize { get; set; } = 100 * 1024 * 1024;
    public long MaxScanSize { get; set; } = 500 * 1024 * 1024;
    public int MaxRecursion { get; set; } = 16;
    public int MaxFiles { get; set; } = 10000;
}

public class ClamAvEngine
{
    private readonly Dictionary<string, string> _md5Signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sha256Signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sha1Signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sectionMd5Signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sectionSha256Signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<HexPattern> _hexPatterns = new();
    private readonly HashSet<string> _fpHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ignoredSigs = new(StringComparer.OrdinalIgnoreCase);
    private readonly AhoCorasickEngine _acEngine = new();

    private readonly ReaderWriterLockSlim _engineLock = new();
    private int _totalSignatures;
    private DateTime? _dbBuildTime;

    public int TotalSignatures => _totalSignatures;
    public DateTime? DbBuildTime => _dbBuildTime;

    public ClamAvEngine()
    {
        InitializeDefaultSignatures();
    }

    private void InitializeDefaultSignatures()
    {
        byte[] eicarPattern = Encoding.ASCII.GetBytes(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        _hexPatterns.Add(new HexPattern
        {
            Name = "Eicar-Test-Signature",
            Pattern = eicarPattern,
            Offset = "*"
        });

        _acEngine.AddPattern(eicarPattern, "Eicar-Test-Signature");

        _md5Signatures["44d88612fea8a8f36de82e1278abb02f"] = "Eicar-Test-Signature-MD5";
        _sha256Signatures["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = "Eicar-Test-Signature-SHA256";
    }

    public void Clear()
    {
        _engineLock.EnterWriteLock();
        try
        {
            _md5Signatures.Clear();
            _sha256Signatures.Clear();
            _sha1Signatures.Clear();
            _sectionMd5Signatures.Clear();
            _sectionSha256Signatures.Clear();
            _hexPatterns.Clear();
            _fpHashes.Clear();
            _ignoredSigs.Clear();
            _acEngine.Clear();
            _totalSignatures = 0;
            _dbBuildTime = null;
            InitializeDefaultSignatures();
        }
        finally
        {
            _engineLock.ExitWriteLock();
        }
    }

    public int LoadSignaturesFromContent(string fileName, string content)
    {
        int loaded = 0;
        string ext = Path.GetExtension(fileName).ToLowerInvariant();

        using var reader = new StringReader(content);
        string? line;

        _engineLock.EnterWriteLock();
        try
        {
            while ((line = reader.ReadLine()) != null)
            {
                line = line.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith(';'))
                    continue;

                try
                {
                    loaded += LoadSignatureLine(ext, line);
                }
                catch
                {
                }
            }

            if (loaded > 0)
            {
                _totalSignatures += loaded;
            }
            return loaded;
        }
        finally
        {
            _engineLock.ExitWriteLock();
        }
    }

    private int LoadSignatureLine(string ext, string line)
    {
        return ext switch
        {
            ".hdb" or ".hdu" => LoadHashSignature(line, HashType.MD5),
            ".hsb" or ".hsu" => LoadHashSignature(line, HashType.SHA256),
            ".mdb" or ".mdu" => LoadHashSignature(line, HashType.MD5, isSectionHash: true),
            ".msb" or ".msu" => LoadHashSignature(line, HashType.SHA256, isSectionHash: true),
            ".ndb" or ".ndu" => LoadNdbSignature(line),
            ".ldb" or ".ldu" => LoadLdbSignature(line),
            ".fp" or ".sfp" => LoadFpSignature(line),
            ".ign" or ".ign2" => LoadIgnoreSignature(line),
            ".sha256" => LoadHashSignature(line, HashType.SHA256),
            ".db" => LoadOldFormatSignature(line),
            ".cdb" => LoadCdbSignature(line),
            _ => 0
        };
    }

    private enum HashType { MD5, SHA1, SHA256 }

    private int LoadHashSignature(string line, HashType hashType, bool isSectionHash = false)
    {
        var parts = line.Split(':');
        if (parts.Length < 2) return 0;

        string hash = parts[0].Trim();
        string name = parts[parts.Length - 1].Trim();

        int expectedLen = hashType switch
        {
            HashType.MD5 => 32,
            HashType.SHA1 => 40,
            HashType.SHA256 => 64,
            _ => 0
        };

        if (hash.Length == expectedLen && !string.IsNullOrEmpty(name))
        {
            if (isSectionHash)
            {
                var dict = hashType switch
                {
                    HashType.MD5 => _sectionMd5Signatures,
                    HashType.SHA256 => _sectionSha256Signatures,
                    _ => _sectionMd5Signatures
                };
                dict[hash] = name;
            }
            else
            {
                var dict = hashType switch
                {
                    HashType.MD5 => _md5Signatures,
                    HashType.SHA256 => _sha256Signatures,
                    _ => _md5Signatures
                };
                dict[hash] = name;
            }
            return 1;
        }
        return 0;
    }

    private int LoadNdbSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 4) return 0;

        string name = parts[0].Trim();
        uint targetType = 0;
        if (parts.Length > 1 && uint.TryParse(parts[1].Trim(), out var tt))
            targetType = tt;

        string offset = parts[2].Trim();
        string hexPatternStr = parts[3].Trim();

        var (prefix, isPrefixOnly) = ParseHexPatternAdvanced(hexPatternStr);
        if (prefix.Length == 0) return 0;

        var pattern = new HexPattern
        {
            Name = name,
            Pattern = prefix,
            Offset = offset,
            TargetType = targetType,
            IsPrefixOnly = isPrefixOnly,
            MinOffset = ParseOffset(offset, out var maxOff),
            MaxOffset = maxOff
        };

        _hexPatterns.Add(pattern);
        if (!isPrefixOnly)
            _acEngine.AddPattern(prefix, name);
        return 1;
    }

    private int LoadLdbSignature(string line)
    {
        var parts = line.Split(';');
        if (parts.Length < 2) return 0;

        var headerParts = parts[0].Split(':');
        string name = headerParts[0].Trim();

        if (parts.Length < 3) return 0;

        string hexPatternStr = parts[^1].Trim();
        var (prefix, _) = ParseHexPatternAdvanced(hexPatternStr);
        if (prefix.Length == 0) return 0;

        _hexPatterns.Add(new HexPattern
        {
            Name = name,
            Pattern = prefix,
            Offset = "*"
        });
        _acEngine.AddPattern(prefix, name);
        return 1;
    }

    private int LoadCdbSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 5) return 0;

        string name = parts[0].Trim();
        _hexPatterns.Add(new HexPattern
        {
            Name = name,
            Pattern = Encoding.ASCII.GetBytes(name),
            Offset = "*"
        });
        _acEngine.AddPattern(Encoding.ASCII.GetBytes(name), name);
        return 1;
    }

    private int LoadFpSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 1) return 0;

        string hash = parts[0].Trim();
        if (hash.Length == 32 || hash.Length == 40 || hash.Length == 64)
        {
            _fpHashes.Add(hash);
            return 1;
        }
        return 0;
    }

    private int LoadIgnoreSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 1) return 0;

        string sigName = parts[0].Trim();
        if (!string.IsNullOrEmpty(sigName))
        {
            _ignoredSigs.Add(sigName);
            return 1;
        }
        return 0;
    }

    private int LoadOldFormatSignature(string line)
    {
        var parts = line.Split('=');
        if (parts.Length < 2) return 0;

        string name = parts[0].Trim();
        string hexPatternStr = parts[1].Trim();

        var (pattern, _) = ParseHexPatternAdvanced(hexPatternStr);
        if (pattern.Length == 0) return 0;

        _hexPatterns.Add(new HexPattern
        {
            Name = name,
            Pattern = pattern,
            Offset = "*"
        });
        _acEngine.AddPattern(pattern, name);
        return 1;
    }

    private (byte[] prefix, bool isPrefixOnly) ParseHexPatternAdvanced(string hexStr)
    {
        if (string.IsNullOrEmpty(hexStr))
            return (Array.Empty<byte>(), true);

        if (hexStr.Contains('*') || hexStr.Contains('?') ||
            hexStr.Contains('(') || hexStr.Contains('{') ||
            hexStr.Contains('[') || hexStr.Contains('<'))
        {
            int wildcardPos = hexStr.IndexOfAny(new[] { '*', '?', '(', '{', '[', '<' });
            if (wildcardPos > 0 && wildcardPos >= 4)
            {
                string prefixStr = hexStr.Substring(0, wildcardPos);
                if (wildcardPos % 2 != 0)
                    prefixStr = hexStr.Substring(0, wildcardPos - 1);

                try
                {
                    var prefixBytes = HexToBytes(prefixStr);
                    return (prefixBytes, true);
                }
                catch
                {
                    return (Array.Empty<byte>(), true);
                }
            }
            return (Array.Empty<byte>(), true);
        }

        try
        {
            return (HexToBytes(hexStr), false);
        }
        catch
        {
            return (Array.Empty<byte>(), true);
        }
    }

    private static byte[] HexToBytes(string hexStr)
    {
        int len = hexStr.Length;
        if (len % 2 != 0) return Array.Empty<byte>();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            bytes[i / 2] = Convert.ToByte(hexStr.Substring(i, 2), 16);
        return bytes;
    }

    private static int ParseOffset(string offsetStr, out int maxOffset)
    {
        maxOffset = -1;
        if (string.IsNullOrEmpty(offsetStr)) return 0;
        if (offsetStr == "*") return 0;

        if (int.TryParse(offsetStr, out int abs))
        {
            maxOffset = abs;
            return abs;
        }

        if (offsetStr.StartsWith("EOF-") && int.TryParse(offsetStr.AsSpan(4), out int _))
        {
            return 0;
        }

        if (offsetStr.Contains(','))
        {
            var range = offsetStr.Split(',');
            if (range.Length == 2)
            {
                int.TryParse(range[0], out int min);
                int.TryParse(range[1], out maxOffset);
                return min;
            }
        }

        return 0;
    }

    public void SetDbBuildTime(DateTime buildTime)
    {
        _engineLock.EnterWriteLock();
        try
        {
            _dbBuildTime = buildTime;
        }
        finally
        {
            _engineLock.ExitWriteLock();
        }
    }

    public void Compile()
    {
        _engineLock.EnterWriteLock();
        try
        {
            _acEngine.BuildFailureLinks();
        }
        finally
        {
            _engineLock.ExitWriteLock();
        }
    }

    public List<ThreatDetail> ScanFile(string filePath, ScanOptions? options = null)
    {
        _engineLock.EnterReadLock();
        try
        {
            options ??= new ScanOptions();
            var threats = new List<ThreatDetail>();

            if (!File.Exists(filePath)) return threats;

            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > options.MaxFileSize) return threats;

            var recursionCtx = new RecursionContext(
                options.MaxRecursion,
                options.MaxFiles,
                options.MaxScanSize,
                options.MaxFileSize);

            ScanFileInternal(filePath, options, threats, recursionCtx, 0);
            return threats;
        }
        finally
        {
            _engineLock.ExitReadLock();
        }
    }

    private void ScanFileInternal(
        string filePath,
        ScanOptions options,
        List<ThreatDetail> threats,
        RecursionContext recursionCtx,
        int depth)
    {
        if (recursionCtx.LimitExceeded || threats.Count > 0 && !options.AllMatchMode)
            return;

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!recursionCtx.CanScanFile(fileInfo.Length))
                return;

            var fileType = FileTypeDetector.DetectType(filePath);

            if (options.ParseArchives && IsArchiveType(fileType))
            {
                try
                {
                    var archiveEntries = ArchiveScanner.ExtractArchive(filePath, fileType);
                    using (recursionCtx.EnterArchive())
                    {
                        foreach (var entry in archiveEntries)
                        {
                            if (recursionCtx.LimitExceeded || threats.Count > 0 && !options.AllMatchMode)
                                break;

                            if (!recursionCtx.CanScanFile(entry.FileSize))
                                continue;

                            string tempPath = Path.Combine(Path.GetTempPath(), $"clamui_scan_{Guid.NewGuid():N}_{SanitizeFileName(entry.FileName)}");
                            try
                            {
                                File.WriteAllBytes(tempPath, entry.Content);
                                recursionCtx.RecordFile(entry.FileSize);

                                ScanFileInternal(tempPath, options, threats, recursionCtx, depth + 1);
                            }
                            finally
                            {
                                try { File.Delete(tempPath); } catch { }
                            }
                        }
                    }
                    return;
                }
                catch
                {
                }
            }

            if (!recursionCtx.CanScanFile(fileInfo.Length))
                return;

            recursionCtx.RecordFile(fileInfo.Length);

            ScanFileContent(filePath, options, threats, fileType, recursionCtx);
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Scan error {filePath}: {ex.Message}");
        }
    }

    private bool IsArchiveType(ClamFileType type)
    {
        return type switch
        {
            ClamFileType.ZIP or ClamFileType.ZIPSFX or ClamFileType.GZ or
            ClamFileType.BZ or ClamFileType.XZ or ClamFileType.RAR or
            ClamFileType.RARSFX or ClamFileType.S7Z or ClamFileType.POSIX_TAR or
            ClamFileType.OLD_TAR or ClamFileType.MSCAB or ClamFileType.S7ZSFX or
            ClamFileType.CABSFX or ClamFileType.ARJ => true,
            _ => false
        };
    }

    private void ScanFileContent(
        string filePath,
        ScanOptions options,
        List<ThreatDetail> threats,
        ClamFileType fileType,
        RecursionContext recursionCtx)
    {
        try
        {
            string md5Hash, sha256Hash, sha1Hash;
            byte[] fileBytes;

            using (var stream = File.OpenRead(filePath))
            {
                var fileInfo = new FileInfo(filePath);

                if (fileInfo.Length > 10 * 1024 * 1024)
                {
                    fileBytes = new byte[10 * 1024 * 1024];
                    stream.ReadExactly(fileBytes, 0, fileBytes.Length);
                }
                else
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    fileBytes = ms.ToArray();
                }

                stream.Position = 0;
                using var md5 = MD5.Create();
                using var sha256 = SHA256.Create();
                using var sha1 = SHA1.Create();

                byte[] md5HashBytes = md5.ComputeHash(stream);
                md5Hash = ConvertToHexString(md5HashBytes);

                stream.Position = 0;
                byte[] sha256HashBytes = sha256.ComputeHash(stream);
                sha256Hash = ConvertToHexString(sha256HashBytes);

                stream.Position = 0;
                byte[] sha1HashBytes = sha1.ComputeHash(stream);
                sha1Hash = ConvertToHexString(sha1HashBytes);
            }

            if (threats.Count > 0 && !options.AllMatchMode) return;

            if (IsFalsePositive(md5Hash, sha256Hash, sha1Hash))
                return;

            CheckHashSignatures(threats, filePath, md5Hash, sha256Hash, sha1Hash, options);
            if (threats.Count > 0 && !options.AllMatchMode) return;

            if (options.ParsePe && fileType == ClamFileType.MSEXE)
            {
                ScanPeFile(filePath, threats, options);
                if (threats.Count > 0 && !options.AllMatchMode) return;
            }

            var acMatches = _acEngine.Search(fileBytes);
            foreach (var match in acMatches)
            {
                if (!IsIgnored(match) && !threats.Exists(t => t.ThreatName == match))
                {
                    threats.Add(new ThreatDetail
                    {
                        FilePath = filePath,
                        ThreatName = match,
                        Severity = DetermineSeverity(match),
                        MatchType = "Content"
                    });
                    if (!options.AllMatchMode) return;
                }
            }

            foreach (var hexPattern in _hexPatterns)
            {
                if (threats.Count > 0 && !options.AllMatchMode) return;

                if (hexPattern.TargetType != 0 && hexPattern.TargetType != (uint)GetFileTargetType(filePath))
                    continue;

                if (hexPattern.MinOffset > 0 && hexPattern.MaxOffset >= hexPattern.MinOffset)
                {
                    int startOff = Math.Min(hexPattern.MinOffset, fileBytes.Length);
                    int endOff = Math.Min(hexPattern.MaxOffset + hexPattern.Pattern.Length, fileBytes.Length);
                    int regionLen = endOff - startOff;
                    if (regionLen > 0 && hexPattern.Pattern.Length <= regionLen)
                    {
                        byte[] region = new byte[regionLen];
                        Array.Copy(fileBytes, startOff, region, 0, regionLen);
                        if (SearchBytes(region, hexPattern.Pattern))
                            AddPatternThreat(threats, filePath, hexPattern, options);
                    }
                }
                else
                {
                    if (SearchBytes(fileBytes, hexPattern.Pattern))
                        AddPatternThreat(threats, filePath, hexPattern, options);
                }
            }

            if (options.ParsePdf && fileType == ClamFileType.PDF)
            {
                ScanPdfContent(fileBytes, filePath, threats, options);
            }

            if (options.ParseHtml && fileType == ClamFileType.HTML)
            {
                ScanHtmlContent(fileBytes, filePath, threats, options);
            }

            if (options.ParseOle2 && fileType == ClamFileType.MSOLE2)
            {
                ScanOle2Content(fileBytes, filePath, threats, options);
            }

            if (options.ParseMail && fileType == ClamFileType.MAIL)
            {
                ScanMailContent(fileBytes, filePath, threats, options);
            }

            if (options.ParseRtf && fileType == ClamFileType.RTF)
            {
                ScanRtfContent(fileBytes, filePath, threats, options);
            }

            if (options.ParseSwf && fileType == ClamFileType.SWF)
            {
                ScanSwfContent(fileBytes, filePath, threats, options);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {filePath}: {ex.Message}");
        }
    }

    private void CheckHashSignatures(
        List<ThreatDetail> threats,
        string filePath,
        string md5Hash,
        string sha256Hash,
        string sha1Hash,
        ScanOptions options)
    {
        if (_md5Signatures.TryGetValue(md5Hash, out string? md5Name))
        {
            if (!IsIgnored(md5Name))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = md5Name,
                    Severity = DetermineSeverity(md5Name),
                    HashType = "MD5",
                    FileHash = md5Hash
                });
                if (!options.AllMatchMode) return;
            }
        }

        if (_sha256Signatures.TryGetValue(sha256Hash, out string? sha256Name))
        {
            if (!IsIgnored(sha256Name))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = sha256Name,
                    Severity = DetermineSeverity(sha256Name),
                    HashType = "SHA256",
                    FileHash = sha256Hash
                });
                if (!options.AllMatchMode) return;
            }
        }

        if (_sha1Signatures.TryGetValue(sha1Hash, out string? sha1Name))
        {
            if (!IsIgnored(sha1Name))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = sha1Name,
                    Severity = DetermineSeverity(sha1Name),
                    HashType = "SHA1",
                    FileHash = sha1Hash
                });
            }
        }
    }

    private void ScanPeFile(string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        try
        {
            var peInfo = PeParser.Parse(filePath);
            if (!peInfo.IsValid || peInfo.Sections.Length == 0)
                return;

            foreach (var section in peInfo.Sections)
            {
                if (section.RawSize == 0) continue;

                if (_sectionMd5Signatures.TryGetValue(section.Md5Hash, out string? md5Name) && !IsIgnored(md5Name))
                {
                    if (!threats.Exists(t => t.ThreatName == md5Name))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = md5Name,
                            Severity = DetermineSeverity(md5Name),
                            HashType = "MD5",
                            MatchType = $"PE Section ({section.Name})"
                        });
                        if (!options.AllMatchMode) return;
                    }
                }

                if (_sectionSha256Signatures.TryGetValue(section.Sha256Hash, out string? sha256Name) && !IsIgnored(sha256Name))
                {
                    if (!threats.Exists(t => t.ThreatName == sha256Name))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = sha256Name,
                            Severity = DetermineSeverity(sha256Name),
                            HashType = "SHA256",
                            MatchType = $"PE Section ({section.Name})"
                        });
                        if (!options.AllMatchMode) return;
                    }
                }

                if (section.IsSuspicious && options.HeuristicAlerts && !IsIgnored($"Heuristic.PE.SuspiciousSection.{section.Name}"))
                {
                    if (!threats.Exists(t => t.ThreatName == $"Heuristic.PE.SuspiciousSection.{section.Name}"))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = $"Heuristic.PE.SuspiciousSection.{section.Name}",
                            Severity = DetermineSeverity("Heuristic"),
                            MatchType = $"Heuristic ({section.Name}: ent={section.Entropy:F2}, vsize={section.VirtualSize}, rsize={section.RawSize})"
                        });
                        if (!options.AllMatchMode) return;
                    }
                }
            }
        }
        catch
        {
        }
    }

    private void ScanPdfContent(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts || !options.AlertPdf) return;

        try
        {
            string content = Encoding.ASCII.GetString(data);

            if ((content.Contains("/JavaScript", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("/JS", StringComparison.OrdinalIgnoreCase)) &&
                !IsIgnored("Heuristic.PDF.ContainsJavaScript"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.PDF.ContainsJavaScript",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "PDF"
                });
                if (!options.AllMatchMode) return;
            }

            if (content.Contains("/Launch", StringComparison.OrdinalIgnoreCase) &&
                !IsIgnored("Heuristic.PDF.HasLaunchAction"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.PDF.HasLaunchAction",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "PDF"
                });
                if (!options.AllMatchMode) return;
            }

            if ((content.Contains("/EmbeddedFile", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("/EF", StringComparison.OrdinalIgnoreCase)) &&
                !IsIgnored("Heuristic.PDF.ContainsEmbeddedFile"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.PDF.ContainsEmbeddedFile",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "PDF"
                });
                if (!options.AllMatchMode) return;
            }

            if ((content.Contains("/AA") || content.Contains("/OpenAction")) &&
                !IsIgnored("Heuristic.PDF.AutoActionWithExec"))
            {
                if (content.Contains("/JavaScript", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("/Launch", StringComparison.OrdinalIgnoreCase))
                {
                    threats.Add(new ThreatDetail
                    {
                        FilePath = filePath,
                        ThreatName = "Heuristic.PDF.AutoActionWithExec",
                        Severity = "High",
                        MatchType = "PDF"
                    });
                }
            }
        }
        catch
        {
        }
    }

    private void ScanHtmlContent(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts) return;

        try
        {
            string content = Encoding.UTF8.GetString(data);

            if (content.Contains("<script", StringComparison.OrdinalIgnoreCase))
            {
                int idx = 0;
                while ((idx = content.IndexOf("<script", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    int end = content.IndexOf("</script>", idx, StringComparison.OrdinalIgnoreCase);
                    if (end < 0) break;

                    string script = content.Substring(idx, end - idx + 9);

                    if (script.Contains("eval(", StringComparison.OrdinalIgnoreCase) &&
                        (script.Contains("fromCharCode", StringComparison.OrdinalIgnoreCase) ||
                         script.Contains("unescape", StringComparison.OrdinalIgnoreCase)) &&
                        !IsIgnored("Heuristic.HTML.ObfuscatedScript"))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = "Heuristic.HTML.ObfuscatedScript",
                            Severity = "Medium",
                            MatchType = "HTML"
                        });
                        if (!options.AllMatchMode) return;
                    }

                    if (script.Contains("document.write", StringComparison.OrdinalIgnoreCase) &&
                        script.Contains("decompression", StringComparison.OrdinalIgnoreCase) &&
                        !IsIgnored("Heuristic.HTML.ScriptDecompression"))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = "Heuristic.HTML.ScriptDecompression",
                            Severity = DetermineSeverity("Heuristic"),
                            MatchType = "HTML"
                        });
                        if (!options.AllMatchMode) return;
                    }

                    idx = end + 9;
                }
            }

            if (content.Contains("<iframe", StringComparison.OrdinalIgnoreCase))
            {
                int idx = 0;
                while ((idx = content.IndexOf("<iframe", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    int end = content.IndexOf('>', idx);
                    if (end < 0) break;

                    string iframe = content.Substring(idx, end - idx);

                    bool zeroWidth = iframe.Contains("width=\"0\"", StringComparison.OrdinalIgnoreCase) || 
                                     iframe.Contains("width='0'", StringComparison.OrdinalIgnoreCase) ||
                                     iframe.Contains("width:0", StringComparison.OrdinalIgnoreCase) ||
                                     iframe.Contains("width: 0", StringComparison.OrdinalIgnoreCase);

                    bool zeroHeight = iframe.Contains("height=\"0\"", StringComparison.OrdinalIgnoreCase) || 
                                      iframe.Contains("height='0'", StringComparison.OrdinalIgnoreCase) ||
                                      iframe.Contains("height:0", StringComparison.OrdinalIgnoreCase) ||
                                      iframe.Contains("height: 0", StringComparison.OrdinalIgnoreCase);

                    if ((iframe.Contains("srcdoc", StringComparison.OrdinalIgnoreCase) || (zeroWidth && zeroHeight)) &&
                        !IsIgnored("Heuristic.HTML.SuspiciousIframe"))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = "Heuristic.HTML.SuspiciousIframe",
                            Severity = DetermineSeverity("Heuristic"),
                            MatchType = "HTML"
                        });
                        if (!options.AllMatchMode) return;
                    }

                    idx = end + 1;
                }
            }
        }
        catch
        {
        }
    }

    private void ScanOle2Content(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts || !options.AlertMacros) return;

        try
        {
            string content = Encoding.ASCII.GetString(data);

            if (content.Contains("VBA", StringComparison.Ordinal) &&
                (content.Contains("Auto_Open", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("AutoOpen", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("Workbook_Open", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("Document_Open", StringComparison.OrdinalIgnoreCase)) &&
                !IsIgnored("Heuristic.OLE2.AutoOpenMacro"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.OLE2.AutoOpenMacro",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "OLE2"
                });
            }
        }
        catch
        {
        }
    }

    private void ScanMailContent(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts) return;

        try
        {
            string content = Encoding.UTF8.GetString(data);

            if (content.Contains("Content-Type: multipart/mixed", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("Content-Type: multipart/related", StringComparison.OrdinalIgnoreCase))
            {
                if ((content.Contains("Content-Disposition: attachment", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("name=", StringComparison.OrdinalIgnoreCase)) &&
                    (content.Contains(".exe", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".vbs", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".scr", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".pif", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains(".js", StringComparison.OrdinalIgnoreCase)) &&
                    !IsIgnored("Heuristic.Mail.ExecutableAttachment"))
                {
                    threats.Add(new ThreatDetail
                    {
                        FilePath = filePath,
                        ThreatName = "Heuristic.Mail.ExecutableAttachment",
                        Severity = DetermineSeverity("Heuristic"),
                        MatchType = "Mail"
                    });
                }
            }
        }
        catch
        {
        }
    }

    private void ScanRtfContent(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts || !options.AlertMacros) return;

        try
        {
            string content = Encoding.ASCII.GetString(data);

            if (content.Contains("\\objdata", StringComparison.OrdinalIgnoreCase) &&
                content.Contains("\\objclass", StringComparison.OrdinalIgnoreCase) &&
                !IsIgnored("Heuristic.RTF.EmbeddedObject"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.RTF.EmbeddedObject",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "RTF"
                });
                if (!options.AllMatchMode) return;
            }

            if (content.Contains("\\objdata", StringComparison.OrdinalIgnoreCase) &&
                content.Contains("Equation.3", StringComparison.OrdinalIgnoreCase) &&
                !IsIgnored("Heuristic.RTF.EquationEditor"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.RTF.EquationEditor",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "RTF"
                });
            }
        }
        catch
        {
        }
    }

    private void ScanSwfContent(byte[] data, string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        if (!options.HeuristicAlerts || !options.AlertSwf) return;

        try
        {
            if (data.Length < 8) return;

            bool compressed = data[0] == 0x43;
            byte[] swfData;

            if (compressed)
            {
                try
                {
                    using var compressedStream = new MemoryStream(data, 8, data.Length - 8);
                    using var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress);
                    using var ms = new MemoryStream();
                    deflateStream.CopyTo(ms);
                    swfData = ms.ToArray();
                }
                catch
                {
                    swfData = data;
                }
            }
            else
            {
                swfData = data;
            }

            string content = Encoding.ASCII.GetString(swfData);

            if ((content.Contains("ActionScript", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("asfunction", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("getURL", StringComparison.OrdinalIgnoreCase)) &&
                !IsIgnored("Heuristic.SWF.ContainsActionScript"))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = "Heuristic.SWF.ContainsActionScript",
                    Severity = DetermineSeverity("Heuristic"),
                    MatchType = "SWF"
                });
            }
        }
        catch
        {
        }
    }

    private void AddPatternThreat(List<ThreatDetail> threats, string filePath, HexPattern pattern, ScanOptions options)
    {
        if (IsIgnored(pattern.Name)) return;
        if (threats.Exists(t => t.ThreatName == pattern.Name)) return;

        threats.Add(new ThreatDetail
        {
            FilePath = filePath,
            ThreatName = pattern.Name,
            Severity = DetermineSeverity(pattern.Name),
            MatchType = "Pattern"
        });
    }

    private bool IsFalsePositive(string md5, string sha256, string sha1)
    {
        return _fpHashes.Contains(md5) ||
               _fpHashes.Contains(sha256) ||
               _fpHashes.Contains(sha1);
    }

    private bool IsIgnored(string sigName)
    {
        return _ignoredSigs.Contains(sigName);
    }

    private static string DetermineSeverity(string threatName)
    {
        if (threatName.Contains("Eicar", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Test", StringComparison.OrdinalIgnoreCase))
            return "Low";
        if (threatName.Contains("Trojan", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Ransom", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Backdoor", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Worm", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Rootkit", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Spyware", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Keylogger", StringComparison.OrdinalIgnoreCase))
            return "Critical";
        if (threatName.Contains("PUA", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Adware", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Toolbar", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Heuristic", StringComparison.OrdinalIgnoreCase))
            return "Medium";
        if (threatName.Contains("Phishing", StringComparison.OrdinalIgnoreCase) ||
            threatName.Contains("Exploit", StringComparison.OrdinalIgnoreCase))
            return "High";
        return "High";
    }

    private static int GetFileTargetType(string filePath)
    {
        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext switch
        {
            ".exe" or ".dll" or ".sys" or ".ocx" => 1,
            ".doc" or ".xls" or ".ppt" or ".docx" or ".xlsx" or ".pptx" => 2,
            ".htm" or ".html" => 3,
            ".eml" or ".msg" or ".mbox" => 4,
            ".gif" or ".png" or ".jpg" or ".jpeg" or ".tiff" => 5,
            ".elf" => 6,
            ".txt" or ".csv" or ".json" or ".xml" => 7,
            ".pdf" => 10,
            ".swf" => 11,
            ".jar" or ".class" => 12,
            _ => 0
        };
    }

    private static string ConvertToHexString(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static bool SearchBytes(byte[] source, byte[] pattern)
    {
        if (pattern.Length == 0 || source.Length < pattern.Length) return false;

        if (pattern.Length >= 4)
            return BoyerMooreSearch(source, pattern);

        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    private static bool BoyerMooreSearch(byte[] source, byte[] pattern)
    {
        int patternLen = pattern.Length;
        int sourceLen = source.Length;

        int[] badCharShift = new int[256];
        for (int i = 0; i < 256; i++)
            badCharShift[i] = patternLen;
        for (int i = 0; i < patternLen - 1; i++)
            badCharShift[pattern[i]] = patternLen - 1 - i;

        int[] goodSuffixShift = new int[patternLen + 1];
        ComputeGoodSuffixTable(pattern, goodSuffixShift);

        int j = 0;
        while (j <= sourceLen - patternLen)
        {
            int i = patternLen - 1;
            while (i >= 0 && pattern[i] == source[j + i])
                i--;

            if (i < 0) return true;

            j += Math.Max(goodSuffixShift[patternLen - 1 - i], badCharShift[source[j + i]] - (patternLen - 1 - i));
        }
        return false;
    }

    private static void ComputeGoodSuffixTable(byte[] pattern, int[] shift)
    {
        int m = pattern.Length;
        int[] suffix = new int[m + 1];

        suffix[m - 1] = m;
        int g = m - 1;
        int f = 0;

        for (int i = m - 2; i >= 0; i--)
        {
            if (i > g && suffix[i + m - 1 - f] < i - g)
            {
                suffix[i] = suffix[i + m - 1 - f];
            }
            else
            {
                g = Math.Min(g, i);
                f = i;
                while (g >= 0 && pattern[g] == pattern[g + m - 1 - f])
                    g--;
                suffix[i] = f - g;
            }
        }

        for (int i = 0; i < m; i++)
            shift[i] = m;

        int j = 0;
        for (int i = m - 1; i >= 0; i--)
        {
            if (suffix[i] == i + 1)
            {
                for (; j < m - 1 - i; j++)
                {
                    if (shift[j] == m)
                        shift[j] = m - 1 - i;
                }
            }
        }

        for (int i = 0; i <= m - 2; i++)
            shift[m - 1 - suffix[i]] = m - 1 - i;
    }

    private static string SanitizeFileName(string fileName)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(fileName.Length);
        foreach (char c in fileName)
        {
            if (c == '/' || c == '\\')
                sb.Append('_');
            else if (Array.IndexOf(invalid, c) >= 0)
                sb.Append('_');
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}

public class AhoCorasickEngine
{
    private class AcNode
    {
        public Dictionary<byte, AcNode> Children { get; } = new();
        public AcNode? Failure { get; set; }
        public List<string> Outputs { get; } = new();
        public bool IsEnd { get; set; }
    }

    private readonly AcNode _root = new();
    private bool _built;

    public void AddPattern(byte[] pattern, string name)
    {
        if (pattern.Length == 0) return;

        var current = _root;
        foreach (byte b in pattern)
        {
            if (!current.Children.TryGetValue(b, out var child))
            {
                child = new AcNode();
                current.Children[b] = child;
            }
            current = child;
        }
        current.IsEnd = true;
        if (!current.Outputs.Contains(name))
            current.Outputs.Add(name);
        _built = false;
    }

    private readonly object _buildLock = new();

    public void BuildFailureLinks()
    {
        if (_built) return;
        lock (_buildLock)
        {
            if (_built) return;

            var queue = new Queue<AcNode>();

            foreach (var child in _root.Children)
            {
                child.Value.Failure = _root;
                queue.Enqueue(child.Value);
            }

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();

                foreach (var child in current.Children)
                {
                    var failNode = current.Failure ?? _root;

                    while (failNode != null && !failNode.Children.ContainsKey(child.Key))
                        failNode = failNode.Failure ?? _root;

                    child.Value.Failure = failNode?.Children.GetValueOrDefault(child.Key) ?? _root;

                    if (child.Value.Failure != null)
                        child.Value.Outputs.AddRange(child.Value.Failure.Outputs);

                    queue.Enqueue(child.Value);
                }
            }

            _built = true;
        }
    }

    public List<string> Search(byte[] text)
    {
        BuildFailureLinks();
        var results = new List<string>();
        var found = new HashSet<string>();

        var current = _root;
        for (int i = 0; i < text.Length; i++)
        {
            byte b = text[i];

            while (current != _root && !current.Children.ContainsKey(b))
                current = current.Failure ?? _root;

            if (current.Children.TryGetValue(b, out var next))
                current = next;
            else
                current = _root;

            if (current.IsEnd)
            {
                foreach (var output in current.Outputs)
                {
                    if (found.Add(output))
                        results.Add(output);
                }
            }
        }

        return results;
    }

    public void Clear()
    {
        _root.Children.Clear();
        _root.Failure = null;
        _root.Outputs.Clear();
        _root.IsEnd = false;
        _built = false;
    }
}
