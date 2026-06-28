using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace clamshield_antivirus.Services;

public class PeSectionInfo
{
    public string Name { get; set; } = string.Empty;
    public uint VirtualSize { get; set; }
    public uint VirtualAddress { get; set; }
    public uint RawSize { get; set; }
    public uint RawOffset { get; set; }
    public uint Characteristics { get; set; }
    public string Md5Hash { get; set; } = string.Empty;
    public string Sha1Hash { get; set; } = string.Empty;
    public string Sha256Hash { get; set; } = string.Empty;
    public double Entropy { get; set; }
    public bool IsSuspicious =>
        (RawSize > 0 && VirtualSize > RawSize * 2) ||
        (Characteristics & 0x80000000) == 0 ||
        Entropy > 7.5 ||
        (Name.Contains(".", StringComparison.Ordinal) && !Name.StartsWith("."));
}

public class PeInfo
{
    public bool IsValid { get; set; }
    public bool Is32Bit { get; set; }
    public ushort MachineType { get; set; }
    public ushort NumberOfSections { get; set; }
    public PeSectionInfo[] Sections { get; set; } = Array.Empty<PeSectionInfo>();
    public string ImportHashMd5 { get; set; } = string.Empty;
    public string ImportHashSha256 { get; set; } = string.Empty;
    public string EntryPointHash { get; set; } = string.Empty;
    public uint EntryPointRva { get; set; }
    public uint ImageBase { get; set; }
    public uint SizeOfImage { get; set; }
    public bool HasTls { get; set; }
    public bool HasResource { get; set; }
    public bool HasRelocations { get; set; }
    public string[] ImportedDlls { get; set; } = Array.Empty<string>();
    public string[] ImportedFunctions { get; set; } = Array.Empty<string>();
}

public static class PeParser
{
    public static PeInfo Parse(Stream stream)
    {
        var info = new PeInfo { IsValid = false };

        try
        {
            long origPos = stream.Position;
            using var reader = new BinaryReader(stream, Encoding.UTF8, true);

            if (reader.ReadUInt16() != 0x5A4D)
                return info;

            reader.BaseStream.Position = 0x3C;
            uint peOffset = reader.ReadUInt32();
            if (peOffset > reader.BaseStream.Length - 4)
                return info;

            reader.BaseStream.Position = peOffset;
            uint peSignature = reader.ReadUInt32();
            if (peSignature != 0x00004550)
                return info;

            info.MachineType = reader.ReadUInt16();
            info.NumberOfSections = reader.ReadUInt16();
            uint timestamp = reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt16();
            reader.ReadUInt16();

            ushort sizeOfOptionalHeader = reader.ReadUInt16();
            ushort characteristics = reader.ReadUInt16();

            ushort peMagic = reader.ReadUInt16();
            info.Is32Bit = peMagic == 0x010B;
            info.IsValid = true;

            if (info.Is32Bit)
            {
                reader.ReadBytes(4);
                info.ImageBase = reader.ReadUInt32();
                reader.ReadBytes(4);
                info.SizeOfImage = reader.ReadUInt32();
                reader.ReadBytes(4);
                info.EntryPointRva = reader.ReadUInt32();
            }
            else
            {
                reader.ReadBytes(4);
                info.ImageBase = reader.ReadUInt32();
                reader.ReadBytes(4);
                info.SizeOfImage = reader.ReadUInt32();
                reader.ReadBytes(4);
                info.EntryPointRva = reader.ReadUInt32();
            }

            int dataDirCount = info.Is32Bit ? 16 : 16;
            long dataDirOffset = reader.BaseStream.Position;
            if (dataDirOffset > reader.BaseStream.Length - (dataDirCount * 8))
            {
                info.IsValid = false;
                return info;
            }

            for (int i = 0; i < dataDirCount && i <= 15; i++)
            {
                uint dirRva = reader.ReadUInt32();
                uint dirSize = reader.ReadUInt32();
                if (i == 1 && dirRva > 0 && dirSize > 0) info.HasTls = true;
                if (i == 2 && dirRva > 0 && dirSize > 0) info.HasResource = true;
                if (i == 5 && dirRva > 0 && dirSize > 0) info.HasRelocations = true;
            }

            long sectionOffset = peOffset + 24 + sizeOfOptionalHeader;
            if (sectionOffset > reader.BaseStream.Length)
            {
                info.IsValid = false;
                return info;
            }

            reader.BaseStream.Position = sectionOffset;
            int sectionCount = Math.Min((int)info.NumberOfSections, 96);
            info.Sections = new PeSectionInfo[sectionCount];

            for (int i = 0; i < sectionCount; i++)
            {
                byte[] nameBytes = reader.ReadBytes(8);
                string name = Encoding.UTF8.GetString(nameBytes).TrimEnd('\0');
                uint virtualSize = reader.ReadUInt32();
                uint virtualAddress = reader.ReadUInt32();
                uint rawSize = reader.ReadUInt32();
                uint rawOffset = reader.ReadUInt32();
                reader.ReadBytes(12);
                uint characteristicsFlags = reader.ReadUInt32();

                var section = new PeSectionInfo
                {
                    Name = name,
                    VirtualSize = virtualSize,
                    VirtualAddress = virtualAddress,
                    RawSize = rawSize,
                    RawOffset = rawOffset,
                    Characteristics = characteristicsFlags
                };

                if (rawSize > 0 && rawOffset > 0 &&
                    rawOffset + rawSize <= reader.BaseStream.Length)
                {
                    long savedPos = reader.BaseStream.Position;
                    reader.BaseStream.Position = rawOffset;
                    byte[] sectionData = reader.ReadBytes((int)rawSize);
                    reader.BaseStream.Position = savedPos;

                    using var md5 = MD5.Create();
                    using var sha1 = SHA1.Create();
                    using var sha256 = SHA256.Create();

                    section.Md5Hash = BitConverter.ToString(md5.ComputeHash(sectionData)).Replace("-", "").ToLowerInvariant();
                    section.Sha1Hash = BitConverter.ToString(sha1.ComputeHash(sectionData)).Replace("-", "").ToLowerInvariant();
                    section.Sha256Hash = BitConverter.ToString(sha256.ComputeHash(sectionData)).Replace("-", "").ToLowerInvariant();
                    section.Entropy = CalculateEntropy(sectionData);

                    if (name.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("CODE", StringComparison.OrdinalIgnoreCase))
                    {
                        using var epMd5 = MD5.Create();
                        int epHashLen = Math.Min((int)rawSize, 4096);
                        byte[] epData = new byte[epHashLen];
                        Array.Copy(sectionData, 0, epData, 0, epHashLen);
                        info.EntryPointHash = BitConverter.ToString(epMd5.ComputeHash(epData)).Replace("-", "").ToLowerInvariant();
                    }
                }

                info.Sections[i] = section;
            }

            reader.BaseStream.Position = origPos;
            return info;
        }
        catch
        {
            info.IsValid = false;
            return info;
        }
    }

    public static PeInfo Parse(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Parse(fs);
        }
        catch
        {
            return new PeInfo { IsValid = false };
        }
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var freq = new int[256];
        foreach (byte b in data)
            freq[b]++;

        double entropy = 0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
