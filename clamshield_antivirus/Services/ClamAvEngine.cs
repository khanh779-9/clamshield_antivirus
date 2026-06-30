using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using clamshield_antivirus.Models;
using clamshield_antivirus.Services.ScanSvc;

namespace clamshield_antivirus.Services;

internal static class HexParser
{
    public static ulong ParseUInt64(ReadOnlySpan<char> span)
    {
        ulong result = 0;
        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            uint val = 0;
            if (c >= '0' && c <= '9') val = (uint)(c - '0');
            else if (c >= 'a' && c <= 'f') val = (uint)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = (uint)(c - 'A' + 10);
            result = (result << 4) | val;
        }
        return result;
    }

    public static uint ParseUInt32(ReadOnlySpan<char> span)
    {
        uint result = 0;
        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            uint val = 0;
            if (c >= '0' && c <= '9') val = (uint)(c - '0');
            else if (c >= 'a' && c <= 'f') val = (uint)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = (uint)(c - 'A' + 10);
            result = (result << 4) | val;
        }
        return result;
    }
}

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

    public static Hash128 Parse(ReadOnlySpan<char> hex)
    {
        if (hex.Length < 32) return default;
        ulong high = HexParser.ParseUInt64(hex.Slice(0, 16));
        ulong low = HexParser.ParseUInt64(hex.Slice(16, 16));
        return new Hash128(low, high);
    }

    public static Hash128 Parse(string hex) => Parse(hex.AsSpan());
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

    public static Hash256 Parse(ReadOnlySpan<char> hex)
    {
        if (hex.Length < 64) return default;
        ulong a = HexParser.ParseUInt64(hex.Slice(0, 16));
        ulong b = HexParser.ParseUInt64(hex.Slice(16, 16));
        ulong c = HexParser.ParseUInt64(hex.Slice(32, 16));
        ulong d = HexParser.ParseUInt64(hex.Slice(48, 16));
        return new Hash256 { A = a, B = b, C = c, D = d };
    }

    public static Hash256 Parse(string hex) => Parse(hex.AsSpan());
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

    public static Hash160 Parse(ReadOnlySpan<char> hex)
    {
        if (hex.Length < 40) return default;
        ulong low = HexParser.ParseUInt64(hex.Slice(0, 16));
        ulong mid = HexParser.ParseUInt64(hex.Slice(16, 16));
        uint high = HexParser.ParseUInt32(hex.Slice(32, 8));
        return new Hash160 { Low = low, Mid = mid, High = high };
    }

    public static Hash160 Parse(string hex) => Parse(hex.AsSpan());
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
    public ParsedPattern[] Alternatives = Array.Empty<ParsedPattern>();
}

public class NegatedAltConstraint
{
    public ParsedPattern[] Alternatives = Array.Empty<ParsedPattern>();
}

public class CrbSignature
{
    public string Name { get; set; } = string.Empty;
    public bool Trusted { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string Serial { get; set; } = string.Empty;
    public string Pubkey { get; set; } = string.Empty;
    public string Exponent { get; set; } = string.Empty;
    public bool CodeSign { get; set; }
    public bool TimeSign { get; set; }
    public bool CertSign { get; set; }
    public long NotBefore { get; set; }
    public string Comment { get; set; } = string.Empty;
}

public class CdbSignature
{
    public string Name { get; set; } = string.Empty;
    public string ContainerType { get; set; } = string.Empty;
    public string ContainerSize { get; set; } = string.Empty;
    public string FileNameRegex { get; set; } = string.Empty;
    public string FileSizeInContainer { get; set; } = string.Empty;
    public string FileSizeReal { get; set; } = string.Empty;
    public string IsEncrypted { get; set; } = string.Empty;
    public string FilePos { get; set; } = string.Empty;
    public string Res1 { get; set; } = string.Empty;
    public string Res2 { get; set; } = string.Empty;
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
    private const int MaxSize = 100000;

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
            else if (hexStr[i] == '!' && i + 1 < hexStr.Length && hexStr[i + 1] == '(')
            {
                result.HasWildcards = true;
                int end = hexStr.IndexOf(')', i + 1);
                if (end < 0) return result;
                string altGroup = hexStr.Substring(i + 2, end - i - 2);
                var alts = altGroup.Split('|');
                var altPatterns = new List<ParsedPattern>();
                foreach (var alt in alts)
                {
                    var trimmed = alt.Trim();
                    if (trimmed.Length > 0)
                    {
                        var parsedAlt = ParseMiniPattern(trimmed);
                        if (parsedAlt.Elements.Count > 0)
                            altPatterns.Add(parsedAlt);
                    }
                }
                if (altPatterns.Count > 0)
                {
                    result.Elements.Add(new NegatedAltConstraint { Alternatives = altPatterns.ToArray() });
                }
                i = end + 1;
            }
            else if (hexStr[i] == '(')
            {
                result.HasWildcards = true;
                int end = hexStr.IndexOf(')', i);
                if (end < 0) return result;
                string altGroup = hexStr.Substring(i + 1, end - i - 1);
                bool isBoundary = altGroup == "B" || altGroup == "L" || altGroup == "W";
                if (isBoundary)
                {
                    i = end + 1;
                    continue;
                }
                var alts = altGroup.Split('|');
                var altPatterns = new List<ParsedPattern>();
                foreach (var alt in alts)
                {
                    var trimmed = alt.Trim();
                    if (trimmed.Length > 0)
                    {
                        var parsedAlt = ParseMiniPattern(trimmed);
                        if (parsedAlt.Elements.Count > 0)
                            altPatterns.Add(parsedAlt);
                    }
                }
                if (altPatterns.Count > 0)
                {
                    result.Elements.Add(new AltConstraint { Alternatives = altPatterns.ToArray() });
                }
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

    private static ParsedPattern ParseMiniPattern(string hex)
    {
        var result = new ParsedPattern();
        int i = 0;
        while (i < hex.Length)
        {
            if (hex[i] == '!' && i + 1 < hex.Length && hex[i + 1] == '(')
            {
                int end = hex.IndexOf(')', i + 1);
                if (end < 0) break;
                string altGroup = hex.Substring(i + 2, end - i - 2);
                var alts = altGroup.Split('|');
                var altPatterns = new List<ParsedPattern>();
                foreach (var alt in alts)
                {
                    var trimmed = alt.Trim();
                    if (trimmed.Length > 0)
                    {
                        var parsedAlt = ParseMiniPattern(trimmed);
                        if (parsedAlt.Elements.Count > 0)
                            altPatterns.Add(parsedAlt);
                    }
                }
                if (altPatterns.Count > 0)
                {
                    result.Elements.Add(new NegatedAltConstraint { Alternatives = altPatterns.ToArray() });
                }
                i = end + 1;
            }
            else if (hex[i] == '(')
            {
                int end = hex.IndexOf(')', i);
                if (end < 0) break;
                string altGroup = hex.Substring(i + 1, end - i - 1);
                var alts = altGroup.Split('|');
                var altPatterns = new List<ParsedPattern>();
                foreach (var alt in alts)
                {
                    var trimmed = alt.Trim();
                    if (trimmed.Length > 0)
                    {
                        var parsedAlt = ParseMiniPattern(trimmed);
                        if (parsedAlt.Elements.Count > 0)
                            altPatterns.Add(parsedAlt);
                    }
                }
                if (altPatterns.Count > 0)
                {
                    result.Elements.Add(new AltConstraint { Alternatives = altPatterns.ToArray() });
                }
                i = end + 1;
            }
            else if (hex[i] == '{')
            {
                int end = hex.IndexOf('}', i);
                if (end < 0) break;
                string range = hex.Substring(i + 1, end - i - 1);
                ParseRangeSt(range, out int min, out int max);
                result.Elements.Add(new GapConstraint { Min = min, Max = max });
                i = end + 1;
            }
            else if (hex[i] == '[')
            {
                int end = hex.IndexOf(']', i);
                if (end < 0) break;
                string range = hex.Substring(i + 1, end - i - 1);
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
            else if (IsHexOrWildcardSt(hex[i]))
            {
                if (i + 1 < hex.Length && IsHexOrWildcardSt(hex[i + 1]))
                {
                    int? high = CharToNibbleSt(hex[i]);
                    int? low = CharToNibbleSt(hex[i + 1]);
                    result.Elements.Add(new HexConstraint { HighNibble = high, LowNibble = low });
                    result.HasWildcards = result.HasWildcards || !high.HasValue || !low.HasValue;
                    i += 2;
                }
                else { i++; }
            }
            else { i++; }
        }
        return result;
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

            int nextEi = ei + 1;
            int nextDi = di + 1;
            while (nextEi < elements.Count && elements[nextEi] is HexConstraint nextHc)
            {
                if (nextDi >= data.Length) return false;
                byte nextB = data[nextDi];
                int nextHi = (nextB >> 4) & 0xF;
                int nextLo = nextB & 0xF;
                if (nextHc.HighNibble.HasValue && nextHc.HighNibble.Value != nextHi) return false;
                if (nextHc.LowNibble.HasValue && nextHc.LowNibble.Value != nextLo) return false;
                nextEi++;
                nextDi++;
            }
            return MatchElements(elements, nextEi, data, nextDi);
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
                int altDi = di;
                if (MatchElementsInner(a.Elements, 0, data, ref altDi))
                {
                    if (MatchElements(elements, ei + 1, data, altDi))
                        return true;
                }
            }
            return false;
        }
        if (el is NegatedAltConstraint neg)
        {
            if (di >= data.Length) return false;
            int altLen = neg.Alternatives.Length > 0 ? neg.Alternatives[0].Elements.Count : 1;
            bool matchesAny = false;
            foreach (var a in neg.Alternatives)
            {
                int altDi = di;
                if (MatchElementsInner(a.Elements, 0, data, ref altDi))
                {
                    matchesAny = true;
                    break;
                }
            }
            if (matchesAny) return false;
            return MatchElements(elements, ei + 1, data, di + altLen);
        }
        return false;
    }

    private static bool MatchElementsInner(List<object> elements, int ei, byte[] data, ref int di)
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
            di++;

            int nextEi = ei + 1;
            while (nextEi < elements.Count && elements[nextEi] is HexConstraint nextHc)
            {
                if (di >= data.Length) return false;
                byte nextB = data[di];
                int nextHi = (nextB >> 4) & 0xF;
                int nextLo = nextB & 0xF;
                if (nextHc.HighNibble.HasValue && nextHc.HighNibble.Value != nextHi) return false;
                if (nextHc.LowNibble.HasValue && nextHc.LowNibble.Value != nextLo) return false;
                di++;
                nextEi++;
            }
            return MatchElementsInner(elements, nextEi, data, ref di);
        }
        if (el is GapConstraint gap)
        {
            int max = gap.Max < 0 ? data.Length - di : Math.Min(gap.Max, data.Length - di);
            if (gap.Min > max) return false;
            int savedDi = di;
            for (int skip = gap.Min; skip <= max; skip++)
            {
                di = savedDi + skip;
                if (MatchElementsInner(elements, ei + 1, data, ref di))
                    return true;
            }
            di = savedDi;
            return false;
        }
        if (el is AltConstraint alt)
        {
            foreach (var a in alt.Alternatives)
            {
                int altDi = di;
                if (MatchElementsInner(a.Elements, 0, data, ref altDi))
                {
                    di = altDi;
                    return MatchElementsInner(elements, ei + 1, data, ref di);
                }
            }
            return false;
        }
        if (el is NegatedAltConstraint neg)
        {
            if (di >= data.Length) return false;
            int altLen = neg.Alternatives.Length > 0 ? neg.Alternatives[0].Elements.Count : 1;
            bool matchesAny = false;
            foreach (var a in neg.Alternatives)
            {
                int altDi = di;
                if (MatchElementsInner(a.Elements, 0, data, ref altDi))
                {
                    matchesAny = true;
                    break;
                }
            }
            if (matchesAny) return false;
            di += altLen;
            return MatchElementsInner(elements, ei + 1, data, ref di);
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
                bool right = ParseAnd(expr, ref pos, counts);
                value = value | right;
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
                bool right = ParsePrimary(expr, ref pos, counts);
                value = value & right;
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

public class LdbSubPattern
{
    public int StartOffset { get; set; } = -1; // -1 = any (search entire file)
    public bool IsEofRelative { get; set; }
    public bool IsEpRelative { get; set; }
    public int SectionIndex { get; set; } // 1-based, 0 = none
    public ParsedPattern Pattern { get; set; } = new();

    public int GetEffectiveOffset(int dataLength, int entryPointRawOffset = -1)
    {
        if (StartOffset < 0) return 0;
        if (IsEofRelative) return Math.Max(0, dataLength + StartOffset);
        if (IsEpRelative && entryPointRawOffset >= 0)
            return Math.Max(0, entryPointRawOffset + StartOffset);
        return StartOffset;
    }
}

public class LdbSignature
{
    public string Name { get; set; } = string.Empty;
    public string LogicalExpression { get; set; } = string.Empty;
    public List<LdbSubPattern> SubPatterns { get; set; } = new();
    public uint TargetType { get; set; }
    public int MinEngineLevel { get; set; }
    public int MaxEngineLevel { get; set; } = 255;
    public long MinFileSize { get; set; }
    public long MaxFileSize { get; set; } = long.MaxValue;

    public bool Match(byte[] data, List<ThreatDetail> existingThreats, long fileSize, int entryPointRawOffset = -1)
    {
        if (fileSize < MinFileSize || fileSize > MaxFileSize) return false;
        int[] counts = new int[SubPatterns.Count];
        for (int i = 0; i < SubPatterns.Count; i++)
        {
            int startOff = SubPatterns[i].GetEffectiveOffset(data.Length, entryPointRawOffset);
            counts[i] = PatternCache.CountMatches(data, startOff, SubPatterns[i].Pattern);
        }
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
    public bool AlertPua { get; set; } = false;
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
    public int SectionIndex { get; set; }
    public int MinOffset { get; set; }
    public int MaxOffset { get; set; } = -1;
    public ParsedPattern Parsed { get; set; } = new();
}

public class ClamAvEngine
{
    private readonly Dictionary<Hash128, (string Name, long Size)> _md5Signatures = new();
    private readonly Dictionary<Hash256, (string Name, long Size)> _sha256Signatures = new();
    private readonly Dictionary<Hash160, (string Name, long Size)> _sha1Signatures = new();
    private readonly Dictionary<Hash128, string> _sectionMd5Signatures = new();
    private readonly Dictionary<Hash256, string> _sectionSha256Signatures = new();
    private readonly Dictionary<Hash160, string> _sectionSha1Signatures = new();
    private readonly Dictionary<Hash128, (int Size, string Name)> _importHashSignatures = new();
    private readonly List<StoredPattern> _storedPatterns = new();
    private readonly Dictionary<uint, List<StoredPattern>> _patternsByTarget = new();
    private readonly List<StoredPattern> _type0Patterns = new();
    private readonly List<LdbSignature> _ldbSignatures = new();
    private readonly List<CdbSignature> _cdbSignatures = new();
    private readonly List<CrbSignature> _crbSignatures = new();
    private readonly Dictionary<string, long> _fpHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ignoredSigs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _puaSignatureNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly AhoCorasickEngine _acEngine = new();
    private readonly Dictionary<string, (string Name, byte[] Pattern)> _staticSignatures = new(StringComparer.OrdinalIgnoreCase);

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
        var lookup = _namePool.GetAlternateLookup<ReadOnlySpan<char>>();
        if (lookup.TryGetValue(name.AsSpan(), out var pooled))
            return pooled;
        _namePool[name] = name;
        return name;
    }

    private string Intern(ReadOnlySpan<char> nameSpan)
    {
        var lookup = _namePool.GetAlternateLookup<ReadOnlySpan<char>>();
        if (lookup.TryGetValue(nameSpan, out var pooled))
            return pooled;
        string name = nameSpan.ToString();
        _namePool[name] = name;
        return name;
    }

    private bool IsIgnored(ReadOnlySpan<char> sigName)
    {
        var lookup = _ignoredSigs.GetAlternateLookup<ReadOnlySpan<char>>();
        return lookup.Contains(sigName);
    }

    private bool ShouldSkipPua(ReadOnlySpan<char> sigName, ScanOptions options)
    {
        if (options.AlertPua) return false;
        var lookup = _puaSignatureNames.GetAlternateLookup<ReadOnlySpan<char>>();
        return lookup.Contains(sigName);
    }

    private void InitializeDefaultSignatures()
    {
        byte[] eicarPattern = Encoding.ASCII.GetBytes(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        var eicarParsed = PatternCache.GetOrParse(ConvertToHexString(eicarPattern));
        AddStoredPattern(new StoredPattern
        {
            Name = "Eicar-Test-Signature",
            Parsed = eicarParsed
        });

        _acEngine.AddPattern(eicarPattern, "Eicar-Test-Signature");
        _staticSignatures["Eicar-Test-Signature"] = ("Eicar-Test-Signature", eicarPattern);

        _md5Signatures[Hash128.Parse("44d88612fea8a8f36de82e1278abb02f")] = ("Eicar-Test-Signature-MD5", -1);
        _sha256Signatures[Hash256.Parse("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")] = ("Eicar-Test-Signature-SHA256", -1);
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
            _sectionSha1Signatures.Clear();
            _storedPatterns.Clear();
            _patternsByTarget.Clear();
            _type0Patterns.Clear();
            _importHashSignatures.Clear();
            _ldbSignatures.Clear();
            _cdbSignatures.Clear();
            _crbSignatures.Clear();
            _fpHashes.Clear();
            _ignoredSigs.Clear();
            _puaSignatureNames.Clear();
            _acEngine.Clear();
            _staticSignatures.Clear();
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

    public int LoadSignaturesFromStream(string fileName, Stream stream)
    {
        int loaded = 0;
        string ext = Path.GetExtension(fileName).ToLowerInvariant();

        using var reader = new StreamReader(stream, Encoding.ASCII);
        string? line;

        _engineLock.EnterWriteLock();
        try
        {
            while ((line = reader.ReadLine()) != null)
            {
                var lineSpan = line.AsSpan().Trim();
                if (lineSpan.IsEmpty || lineSpan.StartsWith("#") || lineSpan.StartsWith(";"))
                    continue;

                try
                {
                    loaded += LoadSignatureLine(ext, lineSpan);
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
                var lineSpan = line.AsSpan().Trim();
                if (lineSpan.IsEmpty || lineSpan.StartsWith("#") || lineSpan.StartsWith(";"))
                    continue;

                try
                {
                    loaded += LoadSignatureLine(ext, lineSpan);
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

    private int LoadSignatureLine(string ext, ReadOnlySpan<char> line)
    {
        return ext switch
        {
            ".hdb" => LoadHashSignature(line, HashType.MD5),
            ".hdu" => LoadHashSignature(line, HashType.MD5, isPua: true),
            ".hsb" => LoadHashSignature(line, HashType.AutoDetect),
            ".hsu" => LoadHashSignature(line, HashType.AutoDetect, isPua: true),
            ".mdb" => LoadHashSignature(line, HashType.MD5, isSectionHash: true),
            ".mdu" => LoadHashSignature(line, HashType.MD5, isSectionHash: true, isPua: true),
            ".msb" => LoadHashSignature(line, HashType.AutoDetect, isSectionHash: true),
            ".msu" => LoadHashSignature(line, HashType.AutoDetect, isSectionHash: true, isPua: true),
            ".ndb" => LoadNdbSignature(line),
            ".ndu" => LoadNdbSignature(line, isPua: true),
            ".ldb" => LoadLdbSignature(line),
            ".ldu" => LoadLdbSignature(line, isPua: true),
            ".fp" or ".sfp" => LoadFpSignature(line),
            ".ign" or ".ign2" => LoadIgnoreSignature(line),
            ".sha256" => LoadHashSignature(line, HashType.SHA256),
            ".db" or ".sdb" => LoadOldFormatSignature(line),
            ".cdb" => LoadCdbSignature(line),
            ".crb" or ".cat" => LoadCrbSignature(line),
            ".imp" => LoadImportHashSignature(line),
            ".idb" => LoadHashSignature(line, HashType.MD5),
            _ => 0
        };
    }

    private enum HashType { MD5, SHA1, SHA256, AutoDetect }

    private int LoadHashSignature(ReadOnlySpan<char> line, HashType hashType, bool isSectionHash = false, bool isPua = false)
    {
        int firstColon = line.IndexOf(':');
        if (firstColon < 0) return 0;

        ReadOnlySpan<char> part1 = line.Slice(0, firstColon).Trim();
        ReadOnlySpan<char> rest = line.Slice(firstColon + 1);

        int secondColon = rest.IndexOf(':');
        ReadOnlySpan<char> part2;
        ReadOnlySpan<char> part3 = default;

        if (secondColon < 0)
        {
            part2 = rest.Trim();
        }
        else
        {
            part2 = rest.Slice(0, secondColon).Trim();
            part3 = rest.Slice(secondColon + 1).Trim();
        }

        ReadOnlySpan<char> hashSpan;
        ReadOnlySpan<char> nameSpan;
        ReadOnlySpan<char> sizeFieldSpan = "*".AsSpan();

        if (isSectionHash)
        {
            if (secondColon < 0) return 0;
            sizeFieldSpan = part1;
            hashSpan = part2;
            nameSpan = part3;
        }
        else
        {
            if (secondColon < 0)
            {
                hashSpan = part1;
                nameSpan = part2;
            }
            else
            {
                hashSpan = part1;
                sizeFieldSpan = part2;
                nameSpan = part3;
            }
        }

        if (hashSpan.IsEmpty || nameSpan.IsEmpty)
            return 0;

        HashType effectiveType = hashType;
        if (effectiveType == HashType.AutoDetect)
        {
            effectiveType = hashSpan.Length switch
            {
                32 => HashType.MD5,
                40 => HashType.SHA1,
                64 => HashType.SHA256,
                _ => HashType.MD5
            };
        }

        int expectedLen = effectiveType switch
        {
            HashType.MD5 => 32,
            HashType.SHA1 => 40,
            HashType.SHA256 => 64,
            _ => 0
        };

        if (hashSpan.Length != expectedLen)
            return 0;

        string name = Intern(nameSpan);

        if (isPua)
            _puaSignatureNames.Add(name);

        if (isSectionHash)
        {
            if (effectiveType == HashType.MD5)
                _sectionMd5Signatures[Hash128.Parse(hashSpan)] = name;
            else if (effectiveType == HashType.SHA256)
                _sectionSha256Signatures[Hash256.Parse(hashSpan)] = name;
            else if (effectiveType == HashType.SHA1)
                _sectionSha1Signatures[Hash160.Parse(hashSpan)] = name;
        }
        else
        {
            long sigSize = ParseSizeField(sizeFieldSpan);
            if (effectiveType == HashType.MD5)
                _md5Signatures[Hash128.Parse(hashSpan)] = (name, sigSize);
            else if (effectiveType == HashType.SHA256)
                _sha256Signatures[Hash256.Parse(hashSpan)] = (name, sigSize);
            else if (effectiveType == HashType.SHA1)
                _sha1Signatures[Hash160.Parse(hashSpan)] = (name, sigSize);
        }
        return 1;
    }

    private static long ParseSizeField(ReadOnlySpan<char> sizeField)
    {
        if (sizeField.Equals("*", StringComparison.Ordinal) || !long.TryParse(sizeField, out long sz))
            return -1;
        return sz;
    }

    private int LoadImportHashSignature(ReadOnlySpan<char> line)
    {
        int c1 = line.IndexOf(':');
        if (c1 < 0) return 0;
        ReadOnlySpan<char> hashSpan = line.Slice(0, c1).Trim();
        ReadOnlySpan<char> rest1 = line.Slice(c1 + 1);

        int c2 = rest1.IndexOf(':');
        if (c2 < 0) return 0;
        ReadOnlySpan<char> sizeSpan = rest1.Slice(0, c2).Trim();
        ReadOnlySpan<char> nameSpan = rest1.Slice(c2 + 1).Trim();

        int size = -1;
        if (hashSpan.Length == 32 && (sizeSpan.Equals("*", StringComparison.Ordinal) || int.TryParse(sizeSpan, out size)))
        {
            _importHashSignatures[Hash128.Parse(hashSpan)] = (size, Intern(nameSpan));
            return 1;
        }
        return 0;
    }

    private int LoadNdbSignature(ReadOnlySpan<char> line, bool isPua = false)
    {
        int c1 = line.IndexOf(':');
        if (c1 < 0) return 0;
        ReadOnlySpan<char> nameSpan = line.Slice(0, c1).Trim();
        ReadOnlySpan<char> rest1 = line.Slice(c1 + 1);

        int c2 = rest1.IndexOf(':');
        if (c2 < 0) return 0;
        ReadOnlySpan<char> targetSpan = rest1.Slice(0, c2).Trim();
        ReadOnlySpan<char> rest2 = rest1.Slice(c2 + 1);

        int c3 = rest2.IndexOf(':');
        if (c3 < 0) return 0;
        ReadOnlySpan<char> offsetSpan = rest2.Slice(0, c3).Trim();
        ReadOnlySpan<char> rest3 = rest2.Slice(c3 + 1);

        int c4 = rest3.IndexOf(':');
        ReadOnlySpan<char> hexPatternSpan = c4 < 0 ? rest3.Trim() : rest3.Slice(0, c4).Trim();

        if (hexPatternSpan.IsEmpty) return 0;

        string name = Intern(nameSpan);
        uint targetType = 0;
        uint.TryParse(targetSpan, out targetType);

        string offset = offsetSpan.ToString();
        string hexPatternStr = hexPatternSpan.ToString();

        var parsed = PatternCache.GetOrParse(hexPatternStr);
        if (parsed.Elements.Count == 0) return 0;

        if (isPua)
            _puaSignatureNames.Add(name);

        var offType = ParseOffset(offset, out var offVal, out var maxShift, out var minOff, out var maxOff, out var secIdx);

        // Check if signature is entirely static (contains only HexConstraints without wildcards/gaps)
        bool isStatic = !parsed.HasWildcards;
        byte[]? fullBytes = null;
        if (isStatic && parsed.Elements.Count >= 6)
        {
            fullBytes = new byte[parsed.Elements.Count];
            for (int k = 0; k < parsed.Elements.Count; k++)
            {
                if (parsed.Elements[k] is HexConstraint hc && hc.HighNibble.HasValue && hc.LowNibble.HasValue)
                {
                    fullBytes[k] = (byte)((hc.HighNibble.Value << 4) | hc.LowNibble.Value);
                }
                else
                {
                    isStatic = false;
                    fullBytes = null;
                    break;
                }
            }
        }

        if (isStatic && fullBytes != null && offType == NdbOffsetType.Any && parsed.PrefixBytes != null)
        {
            string uniqueKey = $"{name}_{_staticSignatures.Count}";
            _staticSignatures[uniqueKey] = (name, fullBytes);
            _acEngine.AddPattern(parsed.PrefixBytes, uniqueKey);
        }
        else
        {
            AddStoredPattern(new StoredPattern
            {
                Name = name,
                TargetType = targetType,
                OffsetType = offType,
                OffsetValue = offVal,
                MaxShift = maxShift,
                MinOffset = minOff,
                MaxOffset = maxOff,
                SectionIndex = secIdx,
                Parsed = parsed
            });
        }
        return 1;
    }

    private int LoadLdbSignature(ReadOnlySpan<char> line, bool isPua = false)
    {
        int c1 = line.IndexOf(';');
        if (c1 < 0) return 0;
        ReadOnlySpan<char> nameSpan = line.Slice(0, c1).Trim();
        ReadOnlySpan<char> rest1 = line.Slice(c1 + 1);

        int c2 = rest1.IndexOf(';');
        if (c2 < 0) return 0;
        ReadOnlySpan<char> targetBlockSpan = rest1.Slice(0, c2).Trim();
        ReadOnlySpan<char> rest2 = rest1.Slice(c2 + 1);

        int c3 = rest2.IndexOf(';');
        if (c3 < 0) return 0;
        ReadOnlySpan<char> logicalExprSpan = rest2.Slice(0, c3).Trim();
        ReadOnlySpan<char> subPatternsSpan = rest2.Slice(c3 + 1);

        string name = Intern(nameSpan);

        if (isPua)
            _puaSignatureNames.Add(name);

        string targetBlock = targetBlockSpan.ToString();
        string logicalExpr = logicalExprSpan.ToString();

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

        var subPatterns = new List<LdbSubPattern>();
        ReadOnlySpan<char> remainingSubs = subPatternsSpan;
        while (!remainingSubs.IsEmpty)
        {
            int nextSemi = remainingSubs.IndexOf(';');
            ReadOnlySpan<char> rawPartSpan;
            if (nextSemi < 0)
            {
                rawPartSpan = remainingSubs.Trim();
                remainingSubs = ReadOnlySpan<char>.Empty;
            }
            else
            {
                rawPartSpan = remainingSubs.Slice(0, nextSemi).Trim();
                remainingSubs = remainingSubs.Slice(nextSemi + 1);
            }

            if (rawPartSpan.IsEmpty) continue;

            string rawPart = rawPartSpan.ToString();

            // Skip PCRE subsignatures (contain '/') - not supported in C#
            if (rawPart.Contains('/') && !rawPart.StartsWith("("))
                continue;

            // Skip ByteCompare subsignatures (contain '#') - not supported
            if (rawPart.Contains('#'))
                continue;

            // Skip Macro subsignatures (wrapped in ${...}$) - not supported
            if (rawPart.StartsWith("$", StringComparison.Ordinal) && rawPart.EndsWith("$", StringComparison.Ordinal))
                continue;

            // Skip Image Fuzzy Hash subsignatures (fuzzy_img#...) - not supported
            if (rawPart.StartsWith("fuzzy_img", StringComparison.OrdinalIgnoreCase))
                continue;

            // Strip subsignature modifiers like ::i, ::w, ::f, ::a (not supported yet)
            int modIdx = rawPart.IndexOf("::", StringComparison.Ordinal);
            if (modIdx >= 0)
                rawPart = rawPart.Substring(0, modIdx);

            string hexPart = rawPart;
            int startOff = -1;
            bool isEofRel = false;
            bool isEpRel = false;
            int secIdx = 0;

            if (rawPart.Contains(':'))
            {
                var colonIdx = rawPart.IndexOf(':');
                string potentialOffset = rawPart.Substring(0, colonIdx);

                if (ParseLdbOffset(potentialOffset, out startOff, out isEofRel, out isEpRel, out secIdx))
                {
                    hexPart = rawPart.Substring(colonIdx + 1).Trim();
                }
            }

            if (hexPart.Length < 4) continue;

            var parsed = PatternCache.GetOrParse(hexPart);
            if (parsed.Elements.Count > 0)
                subPatterns.Add(new LdbSubPattern
                {
                    StartOffset = startOff,
                    IsEofRelative = isEofRel,
                    IsEpRelative = isEpRel,
                    SectionIndex = secIdx,
                    Pattern = parsed
                });
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

    private int LoadCdbSignature(ReadOnlySpan<char> line)
    {
        string lineStr = line.ToString();
        var parts = lineStr.Split(':');
        if (parts.Length < 10) return 0;

        var sig = new CdbSignature
        {
            Name = Intern(parts[0].Trim()),
            ContainerType = parts[1].Trim(),
            ContainerSize = parts[2].Trim(),
            FileNameRegex = parts[3].Trim(),
            FileSizeInContainer = parts[4].Trim(),
            FileSizeReal = parts[5].Trim(),
            IsEncrypted = parts[6].Trim(),
            FilePos = parts[7].Trim(),
            Res1 = parts[8].Trim(),
            Res2 = parts[9].Trim()
        };

        lock (_cdbSignatures)
        {
            _cdbSignatures.Add(sig);
        }
        return 1;
    }

    private int LoadCrbSignature(ReadOnlySpan<char> line)
    {
        string lineStr = line.ToString();
        var parts = lineStr.Split(';');
        if (parts.Length < 11) return 0;

        string name = Intern(parts[0].Trim());
        bool trusted = parts[1].Trim() == "1";
        string subject = parts[2].Trim().ToLowerInvariant();
        string serial = parts[3].Trim().ToLowerInvariant();
        string pubkey = parts[4].Trim().ToLowerInvariant();
        string exponent = parts[5].Trim().ToLowerInvariant();
        bool codeSign = parts[6].Trim() == "1";
        bool timeSign = parts[7].Trim() == "1";
        bool certSign = parts[8].Trim() == "1";
        long.TryParse(parts[9].Trim(), out long notBefore);
        string comment = parts[10].Trim();

        var sig = new CrbSignature
        {
            Name = name,
            Trusted = trusted,
            Subject = subject,
            Serial = serial,
            Pubkey = pubkey,
            Exponent = exponent,
            CodeSign = codeSign,
            TimeSign = timeSign,
            CertSign = certSign,
            NotBefore = notBefore,
            Comment = comment
        };

        lock (_crbSignatures)
        {
            _crbSignatures.Add(sig);
        }
        return 1;
    }

    private int LoadFpSignature(ReadOnlySpan<char> line)
    {
        int colonIdx = line.IndexOf(':');
        ReadOnlySpan<char> hashSpan;
        ReadOnlySpan<char> sizeSpan = default;

        if (colonIdx < 0)
        {
            hashSpan = line.Trim();
        }
        else
        {
            hashSpan = line.Slice(0, colonIdx).Trim();
            sizeSpan = line.Slice(colonIdx + 1).Trim();
        }

        if (hashSpan.Length == 32 || hashSpan.Length == 40 || hashSpan.Length == 64)
        {
            long size = -1;
            if (!sizeSpan.IsEmpty && !sizeSpan.Equals("*", StringComparison.Ordinal))
            {
                long.TryParse(sizeSpan, out size);
            }
            string hash = hashSpan.ToString();
            _fpHashes[hash] = size;
            return 1;
        }
        return 0;
    }

    private int LoadIgnoreSignature(ReadOnlySpan<char> line)
    {
        int colonIdx = line.IndexOf(':');
        ReadOnlySpan<char> sigNameSpan = colonIdx < 0 ? line.Trim() : line.Slice(0, colonIdx).Trim();
        if (!sigNameSpan.IsEmpty)
        {
            _ignoredSigs.Add(sigNameSpan.ToString());
            return 1;
        }
        return 0;
    }

    private int LoadOldFormatSignature(ReadOnlySpan<char> line)
    {
        int eqIdx = line.IndexOf('=');
        if (eqIdx < 0) return 0;

        ReadOnlySpan<char> nameSpan = line.Slice(0, eqIdx).Trim();
        ReadOnlySpan<char> hexPatternSpan = line.Slice(eqIdx + 1).Trim();

        string name = Intern(nameSpan);
        string hexPatternStr = hexPatternSpan.ToString();

        var parsed = PatternCache.GetOrParse(hexPatternStr);
        if (parsed.Elements.Count == 0 || parsed.PrefixBytes == null) return 0;

        bool isStatic = !parsed.HasWildcards;
        byte[]? fullBytes = null;
        if (isStatic && parsed.Elements.Count >= 6)
        {
            fullBytes = new byte[parsed.Elements.Count];
            for (int k = 0; k < parsed.Elements.Count; k++)
            {
                if (parsed.Elements[k] is HexConstraint hc && hc.HighNibble.HasValue && hc.LowNibble.HasValue)
                {
                    fullBytes[k] = (byte)((hc.HighNibble.Value << 4) | hc.LowNibble.Value);
                }
                else
                {
                    isStatic = false;
                    fullBytes = null;
                    break;
                }
            }
        }

        if (isStatic && fullBytes != null && parsed.PrefixBytes != null)
        {
            string uniqueKey = $"{name}_{_staticSignatures.Count}";
            _staticSignatures[uniqueKey] = (name, fullBytes);
            _acEngine.AddPattern(parsed.PrefixBytes, uniqueKey);
        }
        else
        {
            AddStoredPattern(new StoredPattern
            {
                Name = name,
                Parsed = parsed
            });
        }
        return 1;
    }

    private static NdbOffsetType ParseOffset(string offsetStr, out int offsetValue, out int maxShift, out int minOffset, out int maxOffset, out int sectionIndex)
    {
        offsetValue = 0;
        maxShift = -1;
        minOffset = 0;
        maxOffset = -1;
        sectionIndex = 0;

        if (string.IsNullOrEmpty(offsetStr) || offsetStr == "*")
            return NdbOffsetType.Any;

        if (offsetStr.StartsWith("EP+"))
        {
            var rest = offsetStr.AsSpan(3);
            var colonIdx = rest.IndexOf(',');
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

        if (offsetStr.StartsWith("S") && offsetStr.Length > 2)
        {
            if (offsetStr[1] == 'E' && offsetStr.Length > 2)
            {
                if (int.TryParse(offsetStr.AsSpan(2), out var wholeSec))
                {
                    offsetValue = 0;
                    sectionIndex = wholeSec;
                    return NdbOffsetType.SectionIndex;
                }
            }
            if (offsetStr[1] >= '0' && offsetStr[1] <= '9')
            {
                var sSpan = offsetStr.AsSpan(1);
                var plusIdx = sSpan.IndexOf('+');
                if (plusIdx > 0 && int.TryParse(sSpan[..plusIdx], out var secIdx))
                {
                    int.TryParse(sSpan[(plusIdx + 1)..], out var secOff);
                    offsetValue = secOff;
                    sectionIndex = secIdx;
                    return NdbOffsetType.SectionIndex;
                }
            }
            
            if (offsetStr.Length > 3 && offsetStr[1] == 'E' && offsetStr[2] >= '0' && offsetStr[2] <= '9')
            {
                if (int.TryParse(offsetStr.AsSpan(2), out var secIdx))
                {
                    offsetValue = 0;
                    sectionIndex = secIdx;
                    return NdbOffsetType.SectionIndex;
                }
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
                    maxOffset = minOffset + maxShift;
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

    private static bool IsValidOffsetFormat(string offsetStr)
    {
        if (string.IsNullOrEmpty(offsetStr)) return false;
        
        if (offsetStr == "*" || offsetStr.Equals("VI", StringComparison.OrdinalIgnoreCase))
            return true;
        
        if (offsetStr.StartsWith("EP+") || offsetStr.StartsWith("EP-") ||
            offsetStr.StartsWith("EOF+") || offsetStr.StartsWith("EOF-") ||
            offsetStr.StartsWith("SL+"))
            return true;
        
        if (offsetStr.StartsWith("S"))
        {
            if (offsetStr.Length > 2 && (offsetStr[1] == 'E' || (offsetStr[1] >= '0' && offsetStr[1] <= '9')))
                return true;
        }
        
        if (offsetStr.Contains(","))
        {
            var parts = offsetStr.Split(',');
            if (parts.Length == 2 && int.TryParse(parts[0], out _) && int.TryParse(parts[1], out _))
                return true;
        }
        
        return int.TryParse(offsetStr, out _);
    }

    private static bool ParseLdbOffset(string offsetStr, out int offset, out bool isEofRel, out bool isEpRel, out int secIdx)
    {
        offset = -1;
        isEofRel = false;
        isEpRel = false;
        secIdx = 0;

        if (string.IsNullOrEmpty(offsetStr) || offsetStr == "*")
            return true; // any offset

        if (offsetStr.StartsWith("EOF-"))
        {
            if (int.TryParse(offsetStr.AsSpan(4), out int eofOff))
            {
                offset = -eofOff;
                isEofRel = true;
                return true;
            }
            return false;
        }

        if (offsetStr.StartsWith("EP+"))
        {
            if (int.TryParse(offsetStr.AsSpan(3), out int epOff))
            {
                offset = epOff;
                isEpRel = true;
                return true;
            }
            return false;
        }

        if (offsetStr.StartsWith("EP-"))
        {
            if (int.TryParse(offsetStr.AsSpan(3), out int epOff))
            {
                offset = -epOff;
                isEpRel = true;
                return true;
            }
            return false;
        }

        if (offsetStr.StartsWith("SE") && offsetStr.Length > 2)
        {
            if (int.TryParse(offsetStr.AsSpan(2), out int si) && si > 0)
            {
                offset = 0;
                secIdx = si;
                return true;
            }
            return false;
        }

        if (int.TryParse(offsetStr, out int absOff))
        {
            offset = absOff;
            return true;
        }

        return false;
    }

    private void AddStoredPattern(StoredPattern sp)
    {
        _storedPatterns.Add(sp);
        if (sp.TargetType == 0)
            _type0Patterns.Add(sp);
        else
        {
            if (!_patternsByTarget.TryGetValue(sp.TargetType, out var bucket))
            {
                bucket = new List<StoredPattern>();
                _patternsByTarget[sp.TargetType] = bucket;
            }
            bucket.Add(sp);
        }
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

    public List<ThreatDetail> ScanFile(string filePath, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        _engineLock.EnterReadLock();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

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

            ScanFileInternal(filePath, options, threats, recursionCtx, 0, cancellationToken);
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
        int depth,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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
                    var containerInfo = new FileInfo(filePath);
                    using (recursionCtx.EnterArchive())
                    {
                        int entryPos = 0;
                        foreach (var entry in archiveEntries)
                        {
                            cancellationToken.ThrowIfCancellationRequested();

                            entryPos++;
                            if (recursionCtx.LimitExceeded || threats.Count > 0 && !options.AllMatchMode)
                                break;

                            // Check CDB signatures against archive metadata
                            foreach (var cdb in _cdbSignatures)
                            {
                                if (MatchCdb(cdb, fileType, containerInfo.Length, entry, entryPos))
                                {
                                    threats.Add(new ThreatDetail
                                    {
                                        FilePath = filePath,
                                        ThreatName = cdb.Name,
                                        Severity = DetermineSeverity(cdb.Name),
                                        MatchType = $"CDB (Archive Entry: {entry.FileName})"
                                    });
                                    if (!options.AllMatchMode) break;
                                }
                            }
                            if (threats.Count > 0 && !options.AllMatchMode)
                                break;

                            if (!recursionCtx.CanScanFile(entry.FileSize))
                                continue;

                            string tempPath = Path.Combine(Path.GetTempPath(), $"clamui_scan_{Guid.NewGuid():N}_{SanitizeFileName(entry.FileName)}");
                            try
                            {
                                File.WriteAllBytes(tempPath, entry.Content);
                                recursionCtx.RecordFile(entry.FileSize);

                                ScanFileInternal(tempPath, options, threats, recursionCtx, depth + 1, cancellationToken);
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

            // Attempt UPX unpacking for PE files
            if (fileType == ClamFileType.MSEXE && depth == 0)
            {
                try
                {
                    byte[] allBytes = File.ReadAllBytes(filePath);
                    if (TryUnpackPe(allBytes, out var unpacked))
                    {
                        string tempPath = Path.Combine(Path.GetTempPath(), $"clamui_unpacked_{Guid.NewGuid():N}.exe");
                        try
                        {
                            File.WriteAllBytes(tempPath, unpacked);
                            recursionCtx.RecordFile(unpacked.Length);
                            ScanFileInternal(tempPath, options, threats, recursionCtx, depth + 1, cancellationToken);
                        }
                        finally
                        {
                            try { File.Delete(tempPath); } catch { }
                        }
                    }
                }
                catch { }
            }

            ScanFileContent(filePath, options, threats, fileType, recursionCtx, cancellationToken);
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
        RecursionContext recursionCtx,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            string md5Hash, sha256Hash, sha1Hash;
            byte[] fileBytes;
            long fileSize;

            using (var stream = File.OpenRead(filePath))
            {
                fileSize = stream.Length;
                long scanLen = Math.Min(fileSize, options.MaxFileSize);
                fileBytes = new byte[scanLen];
                stream.ReadExactly(fileBytes, 0, (int)scanLen);

                using var incMd5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
                using var incSha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using var incSha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

                incMd5.AppendData(fileBytes);
                incSha256.AppendData(fileBytes);
                incSha1.AppendData(fileBytes);

                if (fileSize > scanLen)
                {
                    byte[] buf = new byte[65536];
                    int read, totalRead = 0;
                    while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        incMd5.AppendData(buf, 0, read);
                        incSha256.AppendData(buf, 0, read);
                        incSha1.AppendData(buf, 0, read);
                        totalRead += read;
                        if (totalRead % (10 * 1024 * 1024) == 0) // every 10MB
                            cancellationToken.ThrowIfCancellationRequested();
                    }
                }

                md5Hash = ConvertToHexString(incMd5.GetHashAndReset());
                sha256Hash = ConvertToHexString(incSha256.GetHashAndReset());
                sha1Hash = ConvertToHexString(incSha1.GetHashAndReset());
            }

            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "clamav_scan_log.txt"), $"[{DateTime.Now:HH:mm:ss}] Scan {filePath} type={fileType} size={fileSize} md5={md5Hash} sigCount={_md5Signatures.Count}\n"); } catch { }

            if (threats.Count > 0 && !options.AllMatchMode) return;

            if (IsFalsePositive(md5Hash, sha256Hash, sha1Hash, fileSize))
                return;

            if (fileType == ClamFileType.MSEXE && _crbSignatures.Count > 0)
            {
                bool isTrusted = CheckAuthenticodeSignature(filePath, threats, options);
                if (isTrusted)
                    return;
                if (threats.Count > 0 && !options.AllMatchMode)
                    return;
            }

            CheckHashSignatures(threats, filePath, md5Hash, sha256Hash, sha1Hash, fileSize, options);
            if (threats.Count > 0 && !options.AllMatchMode) return;

            if (options.ParsePe && fileType == ClamFileType.MSEXE)
            {
                ScanPeFile(filePath, threats, options);
                if (threats.Count > 0 && !options.AllMatchMode) return;
            }

            var acMatches = _acEngine.Search(fileBytes);
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "clamav_scan_log.txt"), $"[{DateTime.Now:HH:mm:ss}] AC found {acMatches.Count} matches, hash thread {_md5Signatures.Count} sigs\n"); } catch { }
            foreach (var matchKey in acMatches)
            {
                if (_staticSignatures.TryGetValue(matchKey, out var entry))
                {
                    string name = entry.Name;
                    if (!IsIgnored(name) && !threats.Exists(t => t.ThreatName == name) && !ShouldSkipPua(name, options))
                    {
                        bool verified = fileBytes.AsSpan().IndexOf(entry.Pattern) >= 0;
                        if (verified)
                        {
                            threats.Add(new ThreatDetail
                            {
                                FilePath = filePath,
                                ThreatName = name,
                                Severity = DetermineSeverity(name),
                                MatchType = "Content"
                            });
                            if (!options.AllMatchMode) return;
                        }
                    }
                }
            }

            int fileTargetType = GetFileTargetType(fileType);
            int? entryPointOff = null;
            int ldbEpRawOffset = -1;

            List<StoredPattern>? targetBucket = null;
            if (fileTargetType != 0 && _patternsByTarget.TryGetValue((uint)fileTargetType, out var b))
                targetBucket = b;

            if (targetBucket != null)
            {
                foreach (var sp in targetBucket)
                {
                    if (threats.Count > 0 && !options.AllMatchMode) return;
                    if (MatchStoredPattern(fileBytes, sp, ref entryPointOff))
                        AddStoredPatternThreat(threats, filePath, sp, options);
                }
            }

            foreach (var sp in _type0Patterns)
            {
                if (threats.Count > 0 && !options.AllMatchMode) return;
                if (MatchStoredPattern(fileBytes, sp, ref entryPointOff))
                    AddStoredPatternThreat(threats, filePath, sp, options);
            }

            // Pre-compute entry point offset for LDB EP-relative subsigs
            if (ldbEpRawOffset < 0 && fileTargetType == 1 && fileBytes.Length >= 0x40)
                ldbEpRawOffset = GetPeEntryPointOffset(fileBytes);

            foreach (var ldb in _ldbSignatures)
            {
                if (threats.Count > 0 && !options.AllMatchMode) return;
                if (IsIgnored(ldb.Name)) continue;
                if (ShouldSkipPua(ldb.Name, options)) continue;
                if (threats.Exists(t => t.ThreatName == ldb.Name)) continue;
                if (ldb.TargetType != 0 && ldb.TargetType != (uint)fileTargetType) continue;

                if (ldb.Match(fileBytes, threats, fileBytes.Length, ldbEpRawOffset))
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

    private static bool MatchStoredPattern(byte[] fileBytes, StoredPattern sp, ref int? entryPointOff)
    {
        if (sp.Parsed.Elements.Count == 0) return false;

        if (!sp.Parsed.HasWildcards && sp.Parsed.PrefixBytes != null)
        {
            return MatchWildcardOrStaticPattern(fileBytes, sp, ref entryPointOff, true);
        }

        return MatchWildcardOrStaticPattern(fileBytes, sp, ref entryPointOff, false);
    }

    private static bool MatchWildcardOrStaticPattern(byte[] fileBytes, StoredPattern sp, ref int? entryPointOff, bool isStaticOnly)
    {
        int minStart = 0;
        int maxStart = 0;

        switch (sp.OffsetType)
        {
            case NdbOffsetType.Any:
                minStart = 0;
                maxStart = fileBytes.Length - 1;
                break;

            case NdbOffsetType.Absolute:
                if (sp.MaxOffset >= sp.MinOffset && sp.MinOffset >= 0)
                {
                    minStart = Math.Min(sp.MinOffset, fileBytes.Length);
                    maxStart = Math.Min(sp.MaxOffset, fileBytes.Length - 1);
                }
                else
                {
                    minStart = Math.Min(Math.Max(0, sp.OffsetValue), fileBytes.Length);
                    maxStart = minStart;
                }
                break;

            case NdbOffsetType.EndOfFile:
                minStart = Math.Max(0, fileBytes.Length - sp.OffsetValue);
                maxStart = minStart;
                break;

            case NdbOffsetType.EntryPoint:
                if (fileBytes.Length < 2 || fileBytes[0] != 0x4D || fileBytes[1] != 0x5A)
                    return false;
                if (entryPointOff == null)
                    entryPointOff = GetPeEntryPointOffset(fileBytes);
                if (entryPointOff < 0)
                    return false;
                int epBase = entryPointOff.Value + sp.OffsetValue;
                if (epBase < 0 || epBase >= fileBytes.Length) return false;
                
                minStart = epBase;
                if (sp.MaxShift > 0)
                    maxStart = Math.Min(epBase + sp.MaxShift, fileBytes.Length - 1);
                else
                    maxStart = epBase;
                break;

            case NdbOffsetType.SectionIndex:
                {
                    var peInfo = PeParser.Parse(fileBytes);
                    if (!peInfo.IsValid || peInfo.Sections.Length == 0)
                        return false;
                    // ClamAV section indices are 1-based
                    int idx = sp.SectionIndex - 1;
                    if (idx < 0 || idx >= peInfo.Sections.Length)
                        return false;
                    int secBase = (int)peInfo.Sections[idx].RawOffset + sp.OffsetValue;
                    if (secBase < 0 || secBase >= fileBytes.Length)
                        return false;
                    minStart = secBase;
                    if (sp.MaxShift > 0)
                        maxStart = Math.Min(secBase + sp.MaxShift, fileBytes.Length - 1);
                    else
                        maxStart = secBase;
                }
                break;

            case NdbOffsetType.SectionLast:
                {
                    var peInfo = PeParser.Parse(fileBytes);
                    if (!peInfo.IsValid || peInfo.Sections.Length == 0)
                        return false;
                    int lastSecBase = (int)peInfo.Sections[^1].RawOffset + sp.OffsetValue;
                    if (lastSecBase < 0 || lastSecBase >= fileBytes.Length)
                        return false;
                    minStart = lastSecBase;
                    if (sp.MaxShift > 0)
                        maxStart = Math.Min(lastSecBase + sp.MaxShift, fileBytes.Length - 1);
                    else
                        maxStart = lastSecBase;
                }
                break;

            case NdbOffsetType.VirtualImage:
                {
                    var peInfo = PeParser.Parse(fileBytes);
                    if (!peInfo.IsValid || peInfo.Sections.Length == 0)
                        return false;
                    uint rva = (uint)sp.OffsetValue;
                    uint rawOffset = PeParser.RvaToOffset(rva, peInfo.Sections);
                    if (rawOffset == 0)
                        return false;
                    int viBase = (int)rawOffset;
                    minStart = viBase;
                    if (sp.MaxShift > 0)
                        maxStart = Math.Min(viBase + sp.MaxShift, fileBytes.Length - 1);
                    else
                        maxStart = viBase;
                }
                break;

            default:
                return false;
        }

        if (minStart > maxStart || minStart >= fileBytes.Length) return false;

        if (sp.Parsed.PrefixBytes != null)
        {
            byte[] pat = sp.Parsed.PrefixBytes;
            if (minStart == maxStart)
            {
                if (minStart + pat.Length > fileBytes.Length) return false;
                for (int j = 0; j < pat.Length; j++)
                    if (fileBytes[minStart + j] != pat[j]) return false;
                if (isStaticOnly) return true;
                return PatternCache.MatchData(fileBytes, minStart, sp.Parsed);
            }
            else
            {
                int currentStart = minStart;
                while (true)
                {
                    int searchLen = Math.Min(maxStart - currentStart + pat.Length, fileBytes.Length - currentStart);
                    if (searchLen < pat.Length)
                        break;

                    int idx = fileBytes.AsSpan(currentStart, searchLen).IndexOf(pat);
                    if (idx < 0)
                        break;

                    int matchPos = currentStart + idx;
                    if (isStaticOnly) return true;

                    if (PatternCache.MatchData(fileBytes, matchPos, sp.Parsed))
                        return true;

                    currentStart = matchPos + 1;
                    if (currentStart > maxStart)
                        break;
                }
                return false;
            }
        }
        else
        {
            if (isStaticOnly) return false;
            for (int i = minStart; i <= maxStart; i++)
            {
                if (PatternCache.MatchData(fileBytes, i, sp.Parsed))
                    return true;
            }
            return false;
        }
    }

    private bool MatchCdb(CdbSignature sig, ClamFileType containerType, long containerSize, ArchiveEntry entry, int position)
    {
        if (sig.ContainerType != "*" && !CdbContainerTypeMatches(sig.ContainerType, containerType))
            return false;

        if (sig.ContainerSize != "*" && !CdbValueMatchesRange(sig.ContainerSize, containerSize))
            return false;

        if (sig.FileNameRegex != "*" && !string.IsNullOrEmpty(sig.FileNameRegex))
        {
            try
            {
                var regex = new System.Text.RegularExpressions.Regex(sig.FileNameRegex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!regex.IsMatch(entry.FileName)) return false;
            }
            catch { return false; }
        }

        if (sig.FileSizeReal != "*" && !CdbValueMatchesRange(sig.FileSizeReal, entry.FileSize))
            return false;

        if (sig.IsEncrypted != "*")
        {
            bool reqEncrypt = sig.IsEncrypted == "1";
            if (entry.IsEncrypted != reqEncrypt) return false;
        }

        if (sig.FilePos != "*" && !CdbValueMatchesRange(sig.FilePos, position))
            return false;

        return true;
    }

    private static bool CdbContainerTypeMatches(string sigType, ClamFileType fileType)
    {
        if (int.TryParse(sigType, out int typeVal))
        {
            int currentTypeVal = fileType switch
            {
                ClamFileType.ZIP or ClamFileType.ZIPSFX => 1,
                ClamFileType.RAR or ClamFileType.RARSFX => 2,
                ClamFileType.GZ => 3,
                ClamFileType.BZ => 4,
                ClamFileType.OLD_TAR or ClamFileType.POSIX_TAR => 5,
                ClamFileType.MSCAB or ClamFileType.CABSFX => 6,
                ClamFileType.MAIL => 7,
                ClamFileType.XZ => 8,
                ClamFileType.ARJ => 9,
                ClamFileType.S7Z or ClamFileType.S7ZSFX => 13,
                _ => -1
            };
            return typeVal == currentTypeVal;
        }
        return false;
    }

    private static bool CdbValueMatchesRange(string rangeStr, long value)
    {
        if (rangeStr.Contains('-'))
        {
            var parts = rangeStr.Split('-');
            if (parts.Length == 2)
            {
                long.TryParse(parts[0], out long min);
                long.TryParse(parts[1], out long max);
                if (max == 0) max = long.MaxValue;
                return value >= min && value <= max;
            }
        }
        else
        {
            if (long.TryParse(rangeStr, out long exact))
                return value == exact;
        }
        return false;
    }

    private static int GetPeEntryPointOffset(byte[] data)
    {
        try
        {
            if (data.Length < 0x40) return -1;
            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset < 0 || peOffset + 28 > data.Length) return -1;
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
        long fileSize,
        ScanOptions options)
    {
        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "clamav_scan_log.txt"), $"[{DateTime.Now:HH:mm:ss}] CheckHash: md5={md5Hash} size={fileSize} md5Sigs={_md5Signatures.Count}\n"); } catch { }
        if (_md5Signatures.TryGetValue(Hash128.Parse(md5Hash), out var md5Entry))
        {
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "clamav_scan_log.txt"), $"[{DateTime.Now:HH:mm:ss}] MD5 MATCH: {md5Entry.Name} size={md5Entry.Size} ignored={IsIgnored(md5Entry.Name)} pua={ShouldSkipPua(md5Entry.Name, options)}\n"); } catch { }
            if ((md5Entry.Size < 0 || md5Entry.Size == fileSize) && !IsIgnored(md5Entry.Name) && !ShouldSkipPua(md5Entry.Name, options))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = md5Entry.Name,
                    Severity = DetermineSeverity(md5Entry.Name),
                    HashType = "MD5",
                    FileHash = md5Hash
                });
                if (!options.AllMatchMode) return;
            }
        }

        if (_sha256Signatures.TryGetValue(Hash256.Parse(sha256Hash), out var sha256Entry))
        {
            if ((sha256Entry.Size < 0 || sha256Entry.Size == fileSize) && !IsIgnored(sha256Entry.Name) && !ShouldSkipPua(sha256Entry.Name, options))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = sha256Entry.Name,
                    Severity = DetermineSeverity(sha256Entry.Name),
                    HashType = "SHA256",
                    FileHash = sha256Hash
                });
                if (!options.AllMatchMode) return;
            }
        }

        if (_sha1Signatures.TryGetValue(Hash160.Parse(sha1Hash), out var sha1Entry))
        {
            if ((sha1Entry.Size < 0 || sha1Entry.Size == fileSize) && !IsIgnored(sha1Entry.Name) && !ShouldSkipPua(sha1Entry.Name, options))
            {
                threats.Add(new ThreatDetail
                {
                    FilePath = filePath,
                    ThreatName = sha1Entry.Name,
                    Severity = DetermineSeverity(sha1Entry.Name),
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

                if (_sectionMd5Signatures.TryGetValue(Hash128.Parse(section.Md5Hash), out string? md5Name) && !IsIgnored(md5Name) && !ShouldSkipPua(md5Name, options))
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

                if (_sectionSha256Signatures.TryGetValue(Hash256.Parse(section.Sha256Hash), out string? sha256Name) && !IsIgnored(sha256Name) && !ShouldSkipPua(sha256Name, options))
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

                if (_sectionSha1Signatures.TryGetValue(Hash160.Parse(section.Sha1Hash), out string? sha1Name) && !IsIgnored(sha1Name) && !ShouldSkipPua(sha1Name, options))
                {
                    if (!threats.Exists(t => t.ThreatName == sha1Name))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = sha1Name,
                            Severity = DetermineSeverity(sha1Name),
                            HashType = "SHA1",
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

            // Check import table hash signatures
            if (!string.IsNullOrEmpty(peInfo.ImportHashMd5) && peInfo.ImportHashMd5.Length == 32)
            {
                var importHash = Hash128.Parse(peInfo.ImportHashMd5);
                if (_importHashSignatures.TryGetValue(importHash, out var impSig) && !IsIgnored(impSig.Name))
                {
                    if (!threats.Exists(t => t.ThreatName == impSig.Name))
                    {
                        threats.Add(new ThreatDetail
                        {
                            FilePath = filePath,
                            ThreatName = impSig.Name,
                            Severity = DetermineSeverity(impSig.Name),
                            HashType = "MD5",
                            MatchType = "PE Import Table"
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

    private bool CheckAuthenticodeSignature(string filePath, List<ThreatDetail> threats, ScanOptions options)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(filePath);
#pragma warning restore SYSLIB0057
            
            byte[] subjectDer = cert.SubjectName.RawData;
            using var sha1 = SHA1.Create();
            string subjectSha1 = BitConverter.ToString(sha1.ComputeHash(subjectDer)).Replace("-", "").ToLowerInvariant();

            string serial = cert.SerialNumber.ToLowerInvariant();

            byte[] pubKeyBytes = cert.PublicKey.EncodedKeyValue.RawData;
            string pubkey = BitConverter.ToString(pubKeyBytes).Replace("-", "").ToLowerInvariant();

            lock (_crbSignatures)
            {
                foreach (var sig in _crbSignatures)
                {
                    bool subjectMatch = string.IsNullOrEmpty(sig.Subject) || sig.Subject == "*" || sig.Subject == subjectSha1;
                    bool serialMatch = string.IsNullOrEmpty(sig.Serial) || sig.Serial == "*" || sig.Serial == serial;
                    bool pubkeyMatch = string.IsNullOrEmpty(sig.Pubkey) || sig.Pubkey == "*" || pubkey.Contains(sig.Pubkey);

                    if (subjectMatch && serialMatch && pubkeyMatch)
                    {
                        if (sig.Trusted)
                        {
                            return true; // Trusted -> Whitelisted
                        }
                        else
                        {
                            if (!threats.Exists(t => t.ThreatName == sig.Name))
                            {
                                threats.Add(new ThreatDetail
                                {
                                    FilePath = filePath,
                                    ThreatName = sig.Name,
                                    Severity = "Critical",
                                    MatchType = $"Authenticode Revoked Certificate ({sig.Comment})"
                                });
                            }
                            return false; // Revoked -> Threat added
                        }
                    }
                }
            }
        }
        catch
        {
        }
        return false;
    }

    private void AddStoredPatternThreat(List<ThreatDetail> threats, string filePath, StoredPattern pattern, ScanOptions options)
    {
        if (IsIgnored(pattern.Name)) return;
        if (ShouldSkipPua(pattern.Name, options)) return;
        if (threats.Exists(t => t.ThreatName == pattern.Name)) return;

        threats.Add(new ThreatDetail
        {
            FilePath = filePath,
            ThreatName = pattern.Name,
            Severity = DetermineSeverity(pattern.Name),
            MatchType = "Pattern"
        });
    }

    private bool IsFalsePositive(string md5, string sha256, string sha1, long fileSize = -1)
    {
        if (CheckFpHash(md5, fileSize) || CheckFpHash(sha256, fileSize) || CheckFpHash(sha1, fileSize))
            return true;
        return false;
    }

    private bool CheckFpHash(string hash, long fileSize)
    {
        if (_fpHashes.TryGetValue(hash, out long expectedSize))
            return expectedSize < 0 || expectedSize == fileSize;
        return false;
    }

    private bool IsIgnored(string sigName)
    {
        return _ignoredSigs.Contains(sigName);
    }

    private bool ShouldSkipPua(string sigName, ScanOptions options)
    {
        return !options.AlertPua && _puaSignatureNames.Contains(sigName);
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

    private static int GetFileTargetType(ClamFileType fileType)
    {
        return fileType switch
        {
            ClamFileType.MSEXE => 1,
            ClamFileType.MSOLE2 => 2,
            ClamFileType.HTML or ClamFileType.HTML_UTF16 => 3,
            ClamFileType.MAIL => 4,
            ClamFileType.GIF or ClamFileType.PNG or ClamFileType.JPEG or ClamFileType.TIFF => 5,
            ClamFileType.ELF => 6,
            ClamFileType.TEXT_ASCII => 7,
            ClamFileType.MACHO or ClamFileType.MACHO_UNIBIN => 9,
            ClamFileType.PDF => 10,
            ClamFileType.SWF => 11,
            ClamFileType.JAVA => 12,
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

    private static bool TryUnpackPe(byte[] fileBytes, out byte[] unpackedBytes)
    {
        unpackedBytes = Array.Empty<byte>();
        try
        {
            var peInfo = PeParser.Parse(fileBytes);
            if (!peInfo.IsValid || peInfo.Sections.Length < 2)
                return false;

            int upx0Idx = -1, upx1Idx = -1;
            uint expectedDecompressedSize = 0;
            for (int i = 0; i < peInfo.Sections.Length; i++)
            {
                string sn = peInfo.Sections[i].Name.TrimEnd('\0');
                if (sn.Equals("UPX0", StringComparison.OrdinalIgnoreCase))
                {
                    upx0Idx = i;
                    expectedDecompressedSize = peInfo.Sections[i].VirtualSize;
                }
                else if (sn.Equals("UPX1", StringComparison.OrdinalIgnoreCase))
                    upx1Idx = i;
            }
            if (upx0Idx < 0 || upx1Idx < 0 || expectedDecompressedSize == 0)
                return false;

            var upx1 = peInfo.Sections[upx1Idx];
            if (upx1.RawSize < 32 || upx1.RawOffset + upx1.RawSize > fileBytes.Length)
                return false;

            // Read UPX1 raw content
            byte[] compressed = new byte[upx1.RawSize];
            Array.Copy(fileBytes, upx1.RawOffset, compressed, 0, upx1.RawSize);

            // Try NRV2B decompression from different offsets within UPX1
            int maxTry = (int)Math.Min(upx1.RawSize, 0x400);
            for (int off = 0; off <= maxTry; off += 4)
            {
                if (off + 16 > upx1.RawSize) break;
                var result = DecompressNrv2B(compressed, off, (int)upx1.RawSize - off, expectedDecompressedSize);
                if (result.Length > 64 && result[0] == 0x4D && result[1] == 0x5A)
                {
                    // Verify it's a valid PE
                    int peOff = BitConverter.ToInt32(result, 0x3C);
                    if (peOff > 0 && peOff + 4 < result.Length &&
                        result[peOff] == 0x50 && result[peOff + 1] == 0x45)
                    {
                        unpackedBytes = result;
                        return true;
                    }
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] DecompressNrv2B(byte[] input, int offset, int length, uint expectedSize)
    {
        if (expectedSize == 0 || expectedSize > 100 * 1024 * 1024)
            return Array.Empty<byte>();

        byte[] output = new byte[expectedSize];
        int ip = offset;
        int ipEnd = offset + length;
        int op = 0;

        uint bb = 0;
        int bc = 0;

        uint GetBit()
        {
            if (bc == 0)
            {
                if (ip + 4 > ipEnd) return 2;
                bb = (uint)(input[ip] | (input[ip + 1] << 8) | (input[ip + 2] << 16) | (input[ip + 3] << 24));
                ip += 4;
                bc = 32;
            }
            uint b = (bb >> 31);
            bb <<= 1;
            bc--;
            return b;
        }

        while (op < expectedSize)
        {
            if (GetBit() == 1)
            {
                if (ip >= ipEnd) break;
                output[op++] = input[ip++];
                continue;
            }

            uint len = 2;
            if (GetBit() == 1)
            {
                do
                {
                    len += GetBit();
                    len += GetBit();
                } while (GetBit() == 0);
                len += 2;
            }

            uint tmp = 0;
            do
            {
                tmp = (tmp << 1) | GetBit();
            } while (GetBit() == 0);

            uint off;
            if (tmp != 0)
            {
                if (ip >= ipEnd) break;
                off = ((tmp - 1) << 8) | input[ip++];
                if (off == 0) break;
            }
            else
            {
                if (ip + 2 > ipEnd) break;
                off = (uint)(input[ip++] << 8);
                off >>= 3;
                off |= input[ip++];
            }

            if (off == 0 || off > op) break;

            while (len-- > 0)
            {
                if (op >= expectedSize) break;
                output[op] = output[op - (int)off];
                op++;
            }
        }

        if (op < expectedSize)
        {
            Array.Resize(ref output, op);
        }
        return output;
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
