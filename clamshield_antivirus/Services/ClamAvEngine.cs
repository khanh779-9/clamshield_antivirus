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

public struct Hash128 : IEquatable<Hash128>
{
    public ulong Low;
    public ulong High;

    public Hash128(ulong low, ulong high)
    {
        Low = low;
        High = high;
    }

    public bool Equals(Hash128 other) => Low == other.Low && High == other.High;
    public override bool Equals(object? obj) => obj is Hash128 other && Equals(other);
    public override int GetHashCode()
    {
        unchecked
        {
            return (Low.GetHashCode() * 397) ^ High.GetHashCode();
        }
    }

    public static Hash128 Parse(string hex)
    {
        if (hex.Length < 32) return default;
        ulong high = Convert.ToUInt64(hex.Substring(0, 16), 16);
        ulong low = Convert.ToUInt64(hex.Substring(16, 16), 16);
        return new Hash128(low, high);
    }
}

public struct Hash256 : IEquatable<Hash256>
{
    public ulong A;
    public ulong B;
    public ulong C;
    public ulong D;

    public bool Equals(Hash256 other) => A == other.A && B == other.B && C == other.C && D == other.D;
    public override bool Equals(object? obj) => obj is Hash256 other && Equals(other);
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = A.GetHashCode();
            hash = (hash * 397) ^ B.GetHashCode();
            hash = (hash * 397) ^ C.GetHashCode();
            hash = (hash * 397) ^ D.GetHashCode();
            return hash;
        }
    }

    public static Hash256 Parse(string hex)
    {
        if (hex.Length < 64) return default;
        ulong a = Convert.ToUInt64(hex.Substring(0, 16), 16);
        ulong b = Convert.ToUInt64(hex.Substring(16, 16), 16);
        ulong c = Convert.ToUInt64(hex.Substring(32, 16), 16);
        ulong d = Convert.ToUInt64(hex.Substring(48, 16), 16);
        return new Hash256 { A = a, B = b, C = c, D = d };
    }
}

public struct Hash160 : IEquatable<Hash160>
{
    public ulong Low;
    public ulong Mid;
    public uint High;

    public bool Equals(Hash160 other) => Low == other.Low && Mid == other.Mid && High == other.High;
    public override bool Equals(object? obj) => obj is Hash160 other && Equals(other);
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = Low.GetHashCode();
            hash = (hash * 397) ^ Mid.GetHashCode();
            hash = (hash * 397) ^ High.GetHashCode();
            return hash;
        }
    }

    public static Hash160 Parse(string hex)
    {
        if (hex.Length < 40) return default;
        ulong low = Convert.ToUInt64(hex.Substring(0, 16), 16);
        ulong mid = Convert.ToUInt64(hex.Substring(16, 16), 16);
        uint high = Convert.ToUInt32(hex.Substring(32, 8), 16);
        return new Hash160 { Low = low, Mid = mid, High = high };
    }
}

public class HexConstraint
{
    public int? HighNibble;
    public int? LowNibble;
}

public class GapConstraint
{
    public int Min;
    public int Max = -1;
}

public class AltConstraint
{
    public byte[][] Alternatives = Array.Empty<byte[]>();
}

public class ParsedPattern
{
    public List<object> Elements = new();
    public bool HasWildcards;
    public byte[]? PrefixBytes;
}

public static class PatternCache
{
    private static readonly Dictionary<string, ParsedPattern> _cache = new();
    private const int MaxSize = 2000;

    public static ParsedPattern GetOrParse(string hexStr)
    {
        lock (_cache)
        {
            if (_cache.TryGetValue(hexStr, out var cached))
                return cached;
            var parsed = ParseHexPattern(hexStr);
            if (_cache.Count < MaxSize)
                _cache[hexStr] = parsed;
            return parsed;
        }
    }

    public static void Clear() { lock (_cache) _cache.Clear(); }

    private static ParsedPattern ParseHexPattern(string hexStr)
    {
        var result = new ParsedPattern();
        int i = 0;
        while (i < hexStr.Length)
        {
            if (hexStr[i] == '*')
            {
                result.HasWildcards = true;
                result.Elements.Add(new GapConstraint { Min = 0, Max = -1 });
                i++;
            }
            else if (hexStr[i] == '(')
            {
                result.HasWildcards = true;
                int end = hexStr.IndexOf(')', i);
                if (end < 0) return result;
                string altGroup = hexStr.Substring(i + 1, end - i - 1);
                bool negate = altGroup.StartsWith('!');
                if (negate) altGroup = altGroup.Substring(1);
                bool isBoundary = altGroup == "B" || altGroup == "L" || altGroup == "W";
                if (isBoundary)
                {
                    i = end + 1;
                    continue;
                }
                var alts = altGroup.Split('|');
                var altBytes = new List<byte[]>();
                foreach (var alt in alts)
                {
                    var trimmed = alt.Trim();
                    if (trimmed.Length > 0)
                    {
                        var parsedAlt = ParseHexOnly(trimmed);
                        if (parsedAlt != null && parsedAlt.Length > 0)
                            altBytes.Add(parsedAlt);
                    }
                }
                if (altBytes.Count > 0 && !negate)
                    result.Elements.Add(new AltConstraint { Alternatives = altBytes.ToArray() });
                i = end + 1;
            }
            else if (hexStr[i] == '{')
            {
                result.HasWildcards = true;
                int end = hexStr.IndexOf('}', i);
                if (end < 0) return result;
                string range = hexStr.Substring(i + 1, end - i - 1);
                ParseRangeSt(range, out int min, out int max);
                result.Elements.Add(new GapConstraint { Min = min, Max = max });
                i = end + 1;
            }
            else if (hexStr[i] == '<')
            {
                int end = hexStr.IndexOf('>', i);
                if (end < 0) return result;
                i = end + 1;
            }
            else if (hexStr[i] == '[')
            {
                result.HasWildcards = true;
                int end = hexStr.IndexOf(']', i);
                if (end < 0) return result;
                string range = hexStr.Substring(i + 1, end - i - 1);
                if (range.Contains('-'))
                {
                    var parts2 = range.Split('-');
                    int min2 = 0, max2 = 0;
                    int.TryParse(parts2[0].Trim(), out min2);
                    int.TryParse(parts2[1].Trim(), out max2);
                    if (max2 >= min2)
                        result.Elements.Add(new GapConstraint { Min = min2, Max = max2 });
                }
                i = end + 1;
            }
            else if (IsHexOrWildcardSt(hexStr[i]))
            {
                if (i + 1 < hexStr.Length && IsHexOrWildcardSt(hexStr[i + 1]))
                {
                    char c1 = hexStr[i];
                    char c2 = hexStr[i + 1];
                    {
                        int? high = CharToNibbleSt(c1);
                        int? low = CharToNibbleSt(c2);
                        result.Elements.Add(new HexConstraint { HighNibble = high, LowNibble = low });
                        result.HasWildcards = result.HasWildcards || !high.HasValue || !low.HasValue;
                        i += 2;
                        continue;
                    }
                }
                i++;
            }
            else
            {
                i++;
            }
        }

        for (int j = 0; j < result.Elements.Count; j++)
        {
            if (result.Elements[j] is HexConstraint hc && hc.HighNibble.HasValue && hc.LowNibble.HasValue)
            {
                byte b = (byte)((hc.HighNibble.Value << 4) | hc.LowNibble.Value);
                int start = j;
                int count = 0;
                while (j + count < result.Elements.Count && result.Elements[j + count] is HexConstraint hc2 && hc2.HighNibble.HasValue && hc2.LowNibble.HasValue)
                    count++;
                if (count >= 2 && result.PrefixBytes == null)
                {
                    int prefixLen = Math.Min(count, 32);
                    result.PrefixBytes = new byte[prefixLen];
                    for (int k = 0; k < prefixLen; k++)
                    {
                        var h = (HexConstraint)result.Elements[j + k];
                        if (h.HighNibble.HasValue && h.LowNibble.HasValue)
                            result.PrefixBytes[k] = (byte)((h.HighNibble.Value << 4) | h.LowNibble.Value);
                    }
                }
            }
            else if (result.Elements[j] is GapConstraint || result.Elements[j] is AltConstraint)
            {
                break;
            }
        }

        return result;
    }

    private static bool IsHexCharSt(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    private static bool IsHexOrWildcardSt(char c) => IsHexCharSt(c) || c == '?';
    private static int? CharToNibbleSt(char c)
    {
        if (c == '?') return null;
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return null;
    }

    private static byte[]? ParseHexOnly(string hex)
    {
        if (hex.Length % 2 != 0) return null;
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                return null;
        }
        return bytes;
    }

    private static void ParseRangeSt(string text, out int min, out int max)
    {
        min = 0; max = -1;
        if (string.IsNullOrEmpty(text)) return;
        int dashIdx = text.IndexOf('-');
        if (dashIdx < 0)
        {
            int.TryParse(text, out min);
            max = min;
        }
        else if (dashIdx == 0)
        {
            int.TryParse(text.AsSpan(1), out max);
            min = 0;
        }
        else if (dashIdx == text.Length - 1)
        {
            int.TryParse(text.AsSpan(0, dashIdx), out min);
            max = -1;
        }
        else
        {
            int.TryParse(text.AsSpan(0, dashIdx), out min);
            int.TryParse(text.AsSpan(dashIdx + 1), out max);
        }
    }

    public static bool MatchData(byte[] data, int startOffset, ParsedPattern pattern)
    {
        if (pattern.Elements.Count == 0) return false;
        if (!pattern.HasWildcards && pattern.PrefixBytes != null)
            return ContainsBytesSt(data, startOffset, pattern.PrefixBytes);
        return MatchElements(pattern.Elements, 0, data, startOffset);
    }

    public static int CountMatches(byte[] data, int startOffset, ParsedPattern pattern)
    {
        int count = 0;
        if (pattern.Elements.Count == 0) return 0;
        if (!pattern.HasWildcards && pattern.PrefixBytes != null)
        {
            int end = data.Length - pattern.PrefixBytes.Length;
            for (int i = startOffset; i <= end; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.PrefixBytes.Length; j++)
                    if (data[i + j] != pattern.PrefixBytes[j]) { match = false; break; }
                if (match) count++;
            }
            return count;
        }
        for (int i = startOffset; i < data.Length; i++)
        {
            if (MatchElements(pattern.Elements, 0, data, i))
                count++;
        }
        return count;
    }

    private static bool MatchElements(List<object> elements, int ei, byte[] data, int di)
    {
        if (ei == elements.Count) return true;
        if (di > data.Length) return false;

        var el = elements[ei];
        if (el is HexConstraint hc)
        {
            if (di >= data.Length) return false;
            byte b = data[di];
            int hi = (b >> 4) & 0xF;
            int lo = b & 0xF;
            if (hc.HighNibble.HasValue && hc.HighNibble.Value != hi) return false;
            if (hc.LowNibble.HasValue && hc.LowNibble.Value != lo) return false;
            return MatchElements(elements, ei + 1, data, di + 1);
        }
        if (el is GapConstraint gap)
        {
            int max = gap.Max < 0 ? data.Length - di : Math.Min(gap.Max, data.Length - di);
            if (gap.Min > max) return false;
            for (int skip = gap.Min; skip <= max; skip++)
            {
                if (MatchElements(elements, ei + 1, data, di + skip))
                    return true;
            }
            return false;
        }
        if (el is AltConstraint alt)
        {
            foreach (var a in alt.Alternatives)
            {
                if (di + a.Length > data.Length) continue;
                bool match = true;
                for (int j = 0; j < a.Length; j++)
                    if (data[di + j] != a[j]) { match = false; break; }
                if (match && MatchElements(elements, ei + 1, data, di + a.Length))
                    return true;
            }
            return false;
        }
        return false;
    }

    private static bool ContainsBytesSt(byte[] source, int startOff, byte[] pattern)
    {
        if (startOff + pattern.Length > source.Length) return false;
        for (int i = startOff; i <= source.Length - pattern.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
                if (source[i + j] != pattern[j]) { found = false; break; }
            if (found) return true;
        }
        return false;
    }
}

public static class ExpressionEvaluator
{
    public static bool Evaluate(string expression, int[] matchCounts)
    {
        if (string.IsNullOrWhiteSpace(expression) || matchCounts == null) return false;
        int pos = 0;
        return ParseOr(expression, ref pos, matchCounts);
    }

    private static bool ParseOr(string expr, ref int pos, int[] counts)
    {
        bool value = ParseAnd(expr, ref pos, counts);
        while (true)
        {
            SkipSpace(expr, ref pos);
            if (pos < expr.Length && expr[pos] == '|')
            {
                pos++;
                value = value || ParseAnd(expr, ref pos, counts);
            }
            else break;
        }
        return value;
    }

    private static bool ParseAnd(string expr, ref int pos, int[] counts)
    {
        bool value = ParsePrimary(expr, ref pos, counts);
        while (true)
        {
            SkipSpace(expr, ref pos);
            if (pos < expr.Length && expr[pos] == '&')
            {
                pos++;
                value = value && ParsePrimary(expr, ref pos, counts);
            }
            else break;
        }
        return value;
    }

    private static bool ParsePrimary(string expr, ref int pos, int[] counts)
    {
        SkipSpace(expr, ref pos);
        if (pos < expr.Length && expr[pos] == '(')
        {
            pos++;
            bool inner = ParseOr(expr, ref pos, counts);
            SkipSpace(expr, ref pos);
            if (pos < expr.Length && expr[pos] == ')') pos++;
            return inner;
        }
        return ParseIndexTerm(expr, ref pos, counts);
    }

    private static bool ParseIndexTerm(string expr, ref int pos, int[] counts)
    {
        SkipSpace(expr, ref pos);
        int index = ParseNumber(expr, ref pos);
        int c = (index >= 0 && index < counts.Length) ? counts[index] : 0;
        SkipSpace(expr, ref pos);
        if (pos >= expr.Length) return c > 0;

        char op = expr[pos];
        if (op != '=' && op != '<' && op != '>') return c > 0;
        pos++;
        SkipSpace(expr, ref pos);

        int a = ParseNumber(expr, ref pos);
        int? b = null;
        SkipSpace(expr, ref pos);
        if (pos < expr.Length && expr[pos] == ',')
        {
            pos++;
            SkipSpace(expr, ref pos);
            b = ParseNumber(expr, ref pos);
        }

        return op switch
        {
            '=' => !b.HasValue ? c == a : c >= a && c <= b.Value,
            '>' => !b.HasValue ? c > a : c > a && c <= b.Value,
            '<' => !b.HasValue ? c < a : c >= a && c < b.Value,
            _ => c > 0
        };
    }

    private static int ParseNumber(string expr, ref int pos)
    {
        SkipSpace(expr, ref pos);
        int start = pos;
        while (pos < expr.Length && char.IsDigit(expr[pos])) pos++;
        if (start == pos) return 0;
        int.TryParse(expr.Substring(start, pos - start), out int val);
        return val;
    }

    private static void SkipSpace(string expr, ref int pos)
    {
        while (pos < expr.Length && char.IsWhiteSpace(expr[pos])) pos++;
    }
}

public enum NdbOffsetType
{
    Any,
    Absolute,
    EntryPoint,
    EndOfFile,
    SectionIndex,
    SectionLast,
    VirtualImage
}

public class LdbSignature
{
    public string Name { get; set; } = string.Empty;
    public string LogicalExpression { get; set; } = string.Empty;
    public List<ParsedPattern> SubPatterns { get; set; } = new();
    public uint TargetType { get; set; }
    public int MinEngineLevel { get; set; }
    public int MaxEngineLevel { get; set; } = 255;
    public long MinFileSize { get; set; }
    public long MaxFileSize { get; set; } = long.MaxValue;

    public bool Match(byte[] data, List<ThreatDetail> existingThreats, long fileSize)
    {
        if (fileSize < MinFileSize || fileSize > MaxFileSize) return false;
        int[] counts = new int[SubPatterns.Count];
        for (int i = 0; i < SubPatterns.Count; i++)
            counts[i] = PatternCache.CountMatches(data, 0, SubPatterns[i]);
        return ExpressionEvaluator.Evaluate(LogicalExpression, counts);
    }
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

public class StoredPattern
{
    public string Name { get; set; } = string.Empty;
    public uint TargetType { get; set; }
    public NdbOffsetType OffsetType { get; set; } = NdbOffsetType.Any;
    public int OffsetValue { get; set; }
    public int MaxShift { get; set; } = -1;
    public int MinOffset { get; set; }
    public int MaxOffset { get; set; } = -1;
    public ParsedPattern Parsed { get; set; } = new();
}

public class ClamAvEngine
{
    private readonly Dictionary<Hash128, string> _md5Signatures = new();
    private readonly Dictionary<Hash256, string> _sha256Signatures = new();
    private readonly Dictionary<Hash160, string> _sha1Signatures = new();
    private readonly Dictionary<Hash128, string> _sectionMd5Signatures = new();
    private readonly Dictionary<Hash256, string> _sectionSha256Signatures = new();
    private readonly List<StoredPattern> _storedPatterns = new();
    private readonly List<LdbSignature> _ldbSignatures = new();
    private readonly HashSet<string> _fpHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ignoredSigs = new(StringComparer.OrdinalIgnoreCase);
    private readonly AhoCorasickEngine _acEngine = new();

    // Cache to pool and deduplicate signature names
    private readonly Dictionary<string, string> _namePool = new(StringComparer.OrdinalIgnoreCase);

    private readonly ReaderWriterLockSlim _engineLock = new();
    private int _totalSignatures;
    private DateTime? _dbBuildTime;

    public int TotalSignatures => _totalSignatures;
    public DateTime? DbBuildTime => _dbBuildTime;

    public ClamAvEngine()
    {
        InitializeDefaultSignatures();
    }

    private string Intern(string name)
    {
        if (_namePool.TryGetValue(name, out var pooled))
            return pooled;
        _namePool[name] = name;
        return name;
    }

    private void InitializeDefaultSignatures()
    {
        byte[] eicarPattern = Encoding.ASCII.GetBytes(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        var eicarParsed = PatternCache.GetOrParse(ConvertToHexString(eicarPattern));
        _storedPatterns.Add(new StoredPattern
        {
            Name = "Eicar-Test-Signature",
            Parsed = eicarParsed
        });

        _acEngine.AddPattern(eicarPattern, "Eicar-Test-Signature");

        _md5Signatures[Hash128.Parse("44d88612fea8a8f36de82e1278abb02f")] = "Eicar-Test-Signature-MD5";
        _sha256Signatures[Hash256.Parse("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")] = "Eicar-Test-Signature-SHA256";
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
            _storedPatterns.Clear();
            _ldbSignatures.Clear();
            _fpHashes.Clear();
            _ignoredSigs.Clear();
            _acEngine.Clear();
            PatternCache.Clear();
            _namePool.Clear();
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
            name = Intern(name);
            if (isSectionHash)
            {
                if (hashType == HashType.MD5)
                    _sectionMd5Signatures[Hash128.Parse(hash)] = name;
                else if (hashType == HashType.SHA256)
                    _sectionSha256Signatures[Hash256.Parse(hash)] = name;
            }
            else
            {
                if (hashType == HashType.MD5)
                    _md5Signatures[Hash128.Parse(hash)] = name;
                else if (hashType == HashType.SHA256)
                    _sha256Signatures[Hash256.Parse(hash)] = name;
                else if (hashType == HashType.SHA1)
                    _sha1Signatures[Hash160.Parse(hash)] = name;
            }
            return 1;
        }
        return 0;
    }

    private int LoadNdbSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 4) return 0;

        string name = Intern(parts[0].Trim());
        uint targetType = 0;
        if (parts.Length > 1 && uint.TryParse(parts[1].Trim(), out var tt))
            targetType = tt;

        string offset = parts[2].Trim();
        string hexPatternStr = parts[3].Trim();

        var parsed = PatternCache.GetOrParse(hexPatternStr);
        if (parsed.Elements.Count == 0) return 0;

        var offType = ParseOffset(offset, out var offVal, out var maxShift, out var minOff, out var maxOff);

        if (!parsed.HasWildcards && offType == NdbOffsetType.Any && parsed.PrefixBytes != null)
        {
            _acEngine.AddPattern(parsed.PrefixBytes, name);
        }
        else
        {
            _storedPatterns.Add(new StoredPattern
            {
                Name = name,
                TargetType = targetType,
                OffsetType = offType,
                OffsetValue = offVal,
                MaxShift = maxShift,
                MinOffset = minOff,
                MaxOffset = maxOff,
                Parsed = parsed
            });
        }
        return 1;
    }

    private int LoadLdbSignature(string line)
    {
        var parts = line.Split(';');
        if (parts.Length < 4) return 0;

        string name = Intern(parts[0].Trim());
        string targetBlock = parts[1].Trim();
        string logicalExpr = parts[2].Trim();

        uint targetType = 0;
        int minEngine = 0;
        int maxEngine = 255;
        long minFileSize = 0;
        long maxFileSize = long.MaxValue;

        foreach (var kv in targetBlock.Split(','))
        {
            var kvParts = kv.Split(':');
            if (kvParts.Length != 2) continue;
            string key = kvParts[0].Trim();
            string val = kvParts[1].Trim();

            switch (key)
            {
                case "Target":
                    uint.TryParse(val, out targetType);
                    break;
                case "Engine":
                    var range = val.Split('-');
                    if (range.Length == 2)
                    {
                        int.TryParse(range[0], out minEngine);
                        int.TryParse(range[1], out maxEngine);
                    }
                    break;
                case "FileSize":
                    var fsRange = val.Split('-');
                    if (fsRange.Length == 2)
                    {
                        long.TryParse(fsRange[0], out minFileSize);
                        long.TryParse(fsRange[1], out maxFileSize);
                    }
                    break;
            }
        }

        var subPatterns = new List<ParsedPattern>();
        for (int i = 3; i < parts.Length; i++)
        {
            string hexPart = parts[i].Trim();
            if (hexPart.Contains(':'))
            {
                var offsetParts = hexPart.Split(':');
                hexPart = offsetParts[^1].Trim();
            }
            if (hexPart.Length < 4) continue;

            var parsed = PatternCache.GetOrParse(hexPart);
            if (parsed.Elements.Count > 0)
                subPatterns.Add(parsed);
        }

        if (subPatterns.Count == 0) return 0;

        _ldbSignatures.Add(new LdbSignature
        {
            Name = name,
            LogicalExpression = logicalExpr,
            SubPatterns = subPatterns,
            TargetType = targetType,
            MinEngineLevel = minEngine,
            MaxEngineLevel = maxEngine,
            MinFileSize = minFileSize,
            MaxFileSize = maxFileSize
        });

        return 1;
    }

    private int LoadCdbSignature(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 5) return 0;

        string name = Intern(parts[0].Trim());
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

        string name = Intern(parts[0].Trim());
        string hexPatternStr = parts[1].Trim();

        var parsed = PatternCache.GetOrParse(hexPatternStr);
        if (parsed.Elements.Count == 0 || parsed.PrefixBytes == null) return 0;

        if (!parsed.HasWildcards)
            _acEngine.AddPattern(parsed.PrefixBytes, name);
        else
        {
            _storedPatterns.Add(new StoredPattern
            {
                Name = name,
                Parsed = parsed
            });
        }
        return 1;
    }

    private static NdbOffsetType ParseOffset(string offsetStr, out int offsetValue, out int maxShift, out int minOffset, out int maxOffset)
    {
        offsetValue = 0;
        maxShift = -1;
        minOffset = 0;
        maxOffset = -1;

        if (string.IsNullOrEmpty(offsetStr) || offsetStr == "*")
            return NdbOffsetType.Any;

        if (offsetStr.StartsWith("EP+"))
        {
            var rest = offsetStr.AsSpan(3);
            var colonIdx = rest.IndexOf(':');
            if (colonIdx >= 0)
            {
                int.TryParse(rest[..colonIdx], out offsetValue);
                int.TryParse(rest[(colonIdx + 1)..], out maxShift);
            }
            else
            {
                int.TryParse(rest, out offsetValue);
            }
            return NdbOffsetType.EntryPoint;
        }

        if (offsetStr.StartsWith("EP-") && int.TryParse(offsetStr.AsSpan(3), out offsetValue))
            return NdbOffsetType.EntryPoint;

        if (offsetStr.StartsWith("EOF-"))
        {
            int.TryParse(offsetStr.AsSpan(4), out offsetValue);
            return NdbOffsetType.EndOfFile;
        }

        if (offsetStr.StartsWith("EOF+") && int.TryParse(offsetStr.AsSpan(4), out offsetValue))
            return NdbOffsetType.EndOfFile;

        if (offsetStr.StartsWith("S") && offsetStr.Length > 2 && offsetStr[1] is >= '0' and <= '9')
        {
            var sSpan = offsetStr.AsSpan(1);
            var plusIdx = sSpan.IndexOf('+');
            if (plusIdx > 0 && int.TryParse(sSpan[..plusIdx], out offsetValue))
            {
                int.TryParse(sSpan[(plusIdx + 1)..], out var secOff);
                offsetValue = secOff;
                return NdbOffsetType.SectionIndex;
            }
        }

        if (offsetStr.StartsWith("SL+") && int.TryParse(offsetStr.AsSpan(3), out offsetValue))
            return NdbOffsetType.SectionLast;

        if (offsetStr.Equals("VI", StringComparison.OrdinalIgnoreCase))
            return NdbOffsetType.VirtualImage;

        if (offsetStr.Contains(','))
        {
            var range = offsetStr.Split(',');
            if (range.Length == 2)
            {
                int.TryParse(range[0], out minOffset);
                if (int.TryParse(range[1], out maxOffset))
                {
                    maxShift = maxOffset;
                    return NdbOffsetType.Absolute;
                }
            }
        }

        if (int.TryParse(offsetStr, out int abs))
        {
            offsetValue = abs;
            minOffset = abs;
            maxOffset = abs;
            return NdbOffsetType.Absolute;
        }

        return NdbOffsetType.Any;
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

            int fileTargetType = GetFileTargetType(filePath);
            int? entryPointOff = null;
            foreach (var sp in _storedPatterns)
            {
                if (threats.Count > 0 && !options.AllMatchMode) return;

                if (sp.TargetType != 0 && sp.TargetType != (uint)fileTargetType)
                    continue;

                if (!TryResolveSearchRegion(fileBytes, sp, ref entryPointOff, out int searchStart, out int searchLen))
                    continue;

                if (searchLen <= 0) continue;

                if (searchStart == 0 && searchLen == fileBytes.Length)
                {
                    if (PatternCache.MatchData(fileBytes, 0, sp.Parsed))
                        AddStoredPatternThreat(threats, filePath, sp, options);
                }
                else
                {
                    byte[] region = new byte[searchLen];
                    Array.Copy(fileBytes, searchStart, region, 0, searchLen);
                    if (PatternCache.MatchData(region, 0, sp.Parsed))
                        AddStoredPatternThreat(threats, filePath, sp, options);
                }
            }

            foreach (var ldb in _ldbSignatures)
            {
                if (threats.Count > 0 && !options.AllMatchMode) return;
                if (IsIgnored(ldb.Name)) continue;
                if (threats.Exists(t => t.ThreatName == ldb.Name)) continue;
                if (ldb.TargetType != 0 && ldb.TargetType != (uint)fileTargetType) continue;

                if (ldb.Match(fileBytes, threats, fileBytes.Length))
                {
                    threats.Add(new ThreatDetail
                    {
                        FilePath = filePath,
                        ThreatName = ldb.Name,
                        Severity = DetermineSeverity(ldb.Name),
                        MatchType = "Logical"
                    });
                    if (!options.AllMatchMode) return;
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

    private static bool TryResolveSearchRegion(byte[] fileBytes, StoredPattern sp, ref int? entryPointOff,
        out int searchStart, out int searchLen)
    {
        searchStart = 0;
        searchLen = fileBytes.Length;

        switch (sp.OffsetType)
        {
            case NdbOffsetType.Any:
                return true;

            case NdbOffsetType.Absolute:
                if (sp.MinOffset > 0 && sp.MaxOffset >= sp.MinOffset)
                {
                    searchStart = Math.Min(sp.MinOffset, fileBytes.Length);
                    int endOff = Math.Min(sp.MaxOffset + (sp.Parsed.PrefixBytes?.Length ?? 0), fileBytes.Length);
                    searchLen = endOff - searchStart;
                    return searchLen > 0;
                }
                return true;

            case NdbOffsetType.EndOfFile:
                searchStart = Math.Max(0, fileBytes.Length - sp.OffsetValue);
                searchLen = fileBytes.Length - searchStart;
                return searchLen > 0;

            case NdbOffsetType.EntryPoint:
                if (fileBytes.Length < 2 || fileBytes[0] != 0x4D || fileBytes[1] != 0x5A)
                    return false;
                if (entryPointOff == null)
                    entryPointOff = GetPeEntryPointOffset(fileBytes);
                if (entryPointOff < 0)
                    return false;
                int epBase = entryPointOff.Value + sp.OffsetValue;
                if (sp.MaxShift > 0)
                {
                    searchStart = Math.Min(epBase, fileBytes.Length);
                    int endOff = Math.Min(epBase + sp.MaxShift + (sp.Parsed.PrefixBytes?.Length ?? 0), fileBytes.Length);
                    searchLen = endOff - searchStart;
                }
                else
                {
                    searchStart = Math.Min(epBase, fileBytes.Length);
                    searchLen = Math.Min(sp.Parsed.PrefixBytes?.Length ?? 1, fileBytes.Length - searchStart);
                }
                return searchLen > 0;

            default:
                return true;
        }
    }

    private static int GetPeEntryPointOffset(byte[] data)
    {
        try
        {
            if (data.Length < 0x40) return -1;
            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset <= 0 || peOffset + 64 >= data.Length) return -1;
            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return -1;

            ushort sections = BitConverter.ToUInt16(data, peOffset + 6);
            ushort optHdrSize = BitConverter.ToUInt16(data, peOffset + 20);

            int entryPointRva;
            int optHdrStart = peOffset + 24;
            if (optHdrStart + 20 >= data.Length) return -1;

            entryPointRva = BitConverter.ToInt32(data, optHdrStart + 16);

            int sectionTableOff = optHdrStart + optHdrSize;
            int sectionEntrySize = 40;
            for (int i = 0; i < sections; i++)
            {
                int secOff = sectionTableOff + i * sectionEntrySize;
                if (secOff + 24 >= data.Length) return -1;
                int virtAddr = BitConverter.ToInt32(data, secOff + 12);
                int virtSize = BitConverter.ToInt32(data, secOff + 8);
                int rawOff = BitConverter.ToInt32(data, secOff + 20);

                if (virtSize > 0 && entryPointRva >= virtAddr && entryPointRva < virtAddr + virtSize)
                    return rawOff + (entryPointRva - virtAddr);
            }
            return -1;
        }
        catch
        {
            return -1;
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
        if (_md5Signatures.TryGetValue(Hash128.Parse(md5Hash), out string? md5Name))
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

        if (_sha256Signatures.TryGetValue(Hash256.Parse(sha256Hash), out string? sha256Name))
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

        if (_sha1Signatures.TryGetValue(Hash160.Parse(sha1Hash), out string? sha1Name))
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

                if (_sectionMd5Signatures.TryGetValue(Hash128.Parse(section.Md5Hash), out string? md5Name) && !IsIgnored(md5Name))
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

                if (_sectionSha256Signatures.TryGetValue(Hash256.Parse(section.Sha256Hash), out string? sha256Name) && !IsIgnored(sha256Name))
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

    private void AddStoredPatternThreat(List<ThreatDetail> threats, string filePath, StoredPattern pattern, ScanOptions options)
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
        private byte _singleKey;
        private AcNode? _singleChild;
        private KeyValuePair<byte, AcNode>[]? _childrenArray;

        public AcNode? GetChild(byte key)
        {
            if (_singleChild != null)
            {
                return _singleKey == key ? _singleChild : null;
            }
            if (_childrenArray != null)
            {
                int min = 0;
                int max = _childrenArray.Length - 1;
                while (min <= max)
                {
                    int mid = (min + max) / 2;
                    byte midKey = _childrenArray[mid].Key;
                    if (midKey == key) return _childrenArray[mid].Value;
                    if (midKey < key) min = mid + 1;
                    else max = mid - 1;
                }
            }
            return null;
        }

        public void AddChild(byte key, AcNode child)
        {
            if (_singleChild == null && _childrenArray == null)
            {
                _singleKey = key;
                _singleChild = child;
                return;
            }

            if (_singleChild != null)
            {
                _childrenArray = new KeyValuePair<byte, AcNode>[]
                {
                    new(_singleKey, _singleChild),
                    new(key, child)
                };
                Array.Sort(_childrenArray, (x, y) => x.Key.CompareTo(y.Key));
                _singleChild = null;
                return;
            }

            var len = _childrenArray!.Length;
            var newArray = new KeyValuePair<byte, AcNode>[len + 1];
            Array.Copy(_childrenArray, newArray, len);
            newArray[len] = new(key, child);
            Array.Sort(newArray, (x, y) => x.Key.CompareTo(y.Key));
            _childrenArray = newArray;
        }

        public IEnumerable<KeyValuePair<byte, AcNode>> GetChildren()
        {
            if (_singleChild != null)
            {
                yield return new KeyValuePair<byte, AcNode>(_singleKey, _singleChild);
            }
            else if (_childrenArray != null)
            {
                foreach (var kvp in _childrenArray)
                    yield return kvp;
            }
        }

        public AcNode? Failure { get; set; }

        private string? _singleOutput;
        private string[]? _outputsArray;

        public List<string> Outputs
        {
            get
            {
                var list = new List<string>();
                if (_singleOutput != null) list.Add(_singleOutput);
                if (_outputsArray != null) list.AddRange(_outputsArray);
                return list;
            }
        }

        public void AddOutput(string name)
        {
            if (_singleOutput == null && _outputsArray == null)
            {
                _singleOutput = name;
                return;
            }

            if (_singleOutput != null)
            {
                if (_singleOutput == name) return;
                _outputsArray = new[] { _singleOutput, name };
                _singleOutput = null;
                return;
            }

            if (_outputsArray == null) return;
            if (_outputsArray.Contains(name)) return;
            var len = _outputsArray.Length;
            var newArray = new string[len + 1];
            Array.Copy(_outputsArray, newArray, len);
            newArray[len] = name;
            _outputsArray = newArray;
        }

        public void AddOutputs(IEnumerable<string> names)
        {
            foreach (var name in names)
                AddOutput(name);
        }

        public bool IsEnd { get; set; }
    }

    private AcNode _root = new();
    private bool _built;

    public void AddPattern(byte[] pattern, string name)
    {
        if (pattern.Length == 0) return;

        var current = _root;
        foreach (byte b in pattern)
        {
            var child = current.GetChild(b);
            if (child == null)
            {
                child = new AcNode();
                current.AddChild(b, child);
            }
            current = child;
        }
        current.IsEnd = true;
        current.AddOutput(name);
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

            foreach (var child in _root.GetChildren())
            {
                child.Value.Failure = _root;
                queue.Enqueue(child.Value);
            }

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();

                foreach (var child in current.GetChildren())
                {
                    var failNode = current.Failure;
                    while (failNode != null && failNode.GetChild(child.Key) == null)
                        failNode = failNode.Failure;

                    child.Value.Failure = failNode?.GetChild(child.Key) ?? _root;

                    if (child.Value.Failure != null)
                        child.Value.AddOutputs(child.Value.Failure.Outputs);

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

            while (current != _root && current.GetChild(b) == null)
                current = current.Failure ?? _root;

            var next = current.GetChild(b);
            if (next != null)
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
        _root = new AcNode();
        _built = false;
    }
}
