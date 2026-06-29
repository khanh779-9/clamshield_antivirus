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
    public bool IsSuspicious
    {
        get
        {
            // 1. Writable and Executable section (highly suspicious code injection/packer characteristic)
            // MEM_WRITE = 0x80000000, MEM_EXECUTE = 0x20000000
            bool isWritableAndExecutable = (Characteristics & 0x80000000) != 0 && (Characteristics & 0x20000000) != 0;

            // 2. Virtual size is excessively larger than raw size (e.g. VirtualSize > RawSize * 10, common in packers)
            // only alert if the section is of significant size to avoid false positives on small stub sections.
            bool isVirtualSizeAnomaly = RawSize > 0 && VirtualSize > RawSize * 10 && VirtualSize > 100 * 1024;

            // 3. Extremely high entropy specifically on code/text sections (e.g. entropy > 7.9)
            // which strongly indicates packed/encrypted code, as opposed to normal resources.
            bool isHighEntropyCode = (Name.Equals(".text", StringComparison.OrdinalIgnoreCase) || 
                                      Name.Equals("CODE", StringComparison.OrdinalIgnoreCase)) && Entropy > 7.9;

            // 4. Section name contains a dot in the middle, which is non-standard
            bool hasInvalidNameFormat = Name.Contains(".", StringComparison.Ordinal) && !Name.StartsWith(".", StringComparison.Ordinal);

            return isWritableAndExecutable || isVirtualSizeAnomaly || isHighEntropyCode || hasInvalidNameFormat;
        }
    }
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

            reader.ReadBytes(14); // skip MajorLinker, MinorLinker, SizeOfCode, SizeOfInit, SizeOfUninit to offset 16
            info.EntryPointRva = reader.ReadUInt32(); // offset 16 (4 bytes)

            if (info.Is32Bit)
            {
                reader.ReadBytes(8); // skip BaseOfCode (4 bytes), BaseOfData (4 bytes) to offset 28
                info.ImageBase = reader.ReadUInt32(); // offset 28 (4 bytes)
            }
            else
            {
                reader.ReadBytes(4); // skip BaseOfCode (4 bytes) to offset 24
                ulong imageBase64 = reader.ReadUInt64(); // offset 24 (8 bytes)
                info.ImageBase = (uint)(imageBase64 & 0xFFFFFFFF);
            }

            reader.ReadBytes(24); // skip to offset 56
            info.SizeOfImage = reader.ReadUInt32(); // offset 56 (4 bytes)

            if (info.Is32Bit)
            {
                reader.ReadBytes(36); // skip to offset 96
            }
            else
            {
                reader.ReadBytes(52); // skip to offset 112
            }

            uint importDirectoryRva = 0;
            uint importDirectorySize = 0;

            for (int i = 0; i < 16; i++)
            {
                uint dirRva = reader.ReadUInt32();
                uint dirSize = reader.ReadUInt32();
                if (i == 1)
                {
                    importDirectoryRva = dirRva;
                    importDirectorySize = dirSize;
                }
                if (i == 9 && dirRva > 0 && dirSize > 0) info.HasTls = true; // Index 9 is TLS directory
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

            // Calculate Import Hash (imphash)
            if (importDirectoryRva > 0 && importDirectorySize > 0)
            {
                uint importOffset = RvaToOffset(importDirectoryRva, info.Sections);
                if (importOffset > 0 && importOffset + 20 <= stream.Length)
                {
                    var importList = new List<string>();
                    var dllList = new List<string>();
                    var funcList = new List<string>();
                    
                    reader.BaseStream.Position = importOffset;
                    
                    var descriptors = new List<(uint LookupTableRva, uint NameRva, uint AddressTableRva)>();
                    while (reader.BaseStream.Position + 20 <= stream.Length)
                    {
                        uint lookupRva = reader.ReadUInt32();
                        uint timeDate = reader.ReadUInt32();
                        uint forwarder = reader.ReadUInt32();
                        uint nameRva = reader.ReadUInt32();
                        uint addrRva = reader.ReadUInt32();
                        
                        if (lookupRva == 0 && nameRva == 0 && addrRva == 0)
                            break; // null descriptor
                            
                        descriptors.Add((lookupRva, nameRva, addrRva));
                    }
                    
                    foreach (var desc in descriptors)
                    {
                        uint nameOff = RvaToOffset(desc.NameRva, info.Sections);
                        if (nameOff == 0 || nameOff >= stream.Length) continue;
                        
                        reader.BaseStream.Position = nameOff;
                        string dllName = ReadNullTerminatedAscii(reader);
                        if (string.IsNullOrEmpty(dllName)) continue;
                        
                        string dllNameLower = dllName.ToLowerInvariant();
                        if (dllNameLower.EndsWith(".dll"))
                            dllNameLower = dllNameLower.Substring(0, dllNameLower.Length - 4);
                            
                        dllList.Add(dllName);
                        
                        uint thunkRva = desc.LookupTableRva != 0 ? desc.LookupTableRva : desc.AddressTableRva;
                        uint thunkOff = RvaToOffset(thunkRva, info.Sections);
                        if (thunkOff == 0 || thunkOff >= stream.Length) continue;
                        
                        reader.BaseStream.Position = thunkOff;
                        
                        var thunks = new List<ulong>();
                        if (info.Is32Bit)
                        {
                            while (reader.BaseStream.Position + 4 <= stream.Length)
                            {
                                uint t = reader.ReadUInt32();
                                if (t == 0) break;
                                thunks.Add(t);
                            }
                        }
                        else
                        {
                            while (reader.BaseStream.Position + 8 <= stream.Length)
                            {
                                ulong t = reader.ReadUInt64();
                                if (t == 0) break;
                                thunks.Add(t);
                            }
                        }
                        
                        foreach (var thunk in thunks)
                        {
                            bool isOrdinal = info.Is32Bit 
                                ? (thunk & 0x80000000) != 0 
                                : (thunk & 0x8000000000000000) != 0;
                                
                            if (isOrdinal)
                            {
                                ulong ordinal = info.Is32Bit ? (thunk & 0xFFFF) : (thunk & 0xFFFF);
                                string impStr = $"{dllNameLower}.{ordinal}";
                                importList.Add(impStr);
                                funcList.Add($"Ordinal_{ordinal}");
                            }
                            else
                            {
                                uint nameRva = (uint)(thunk & 0xFFFFFFFF);
                                uint funcNameOff = RvaToOffset(nameRva, info.Sections);
                                if (funcNameOff > 0 && funcNameOff + 2 < stream.Length)
                                {
                                    long savedPos = reader.BaseStream.Position;
                                    reader.BaseStream.Position = funcNameOff + 2; // skip Hint (2 bytes)
                                    string funcName = ReadNullTerminatedAscii(reader);
                                    reader.BaseStream.Position = savedPos;
                                    
                                    if (!string.IsNullOrEmpty(funcName))
                                    {
                                        string impStr = $"{dllNameLower}.{funcName.ToLowerInvariant()}";
                                        importList.Add(impStr);
                                        funcList.Add(funcName);
                                    }
                                }
                            }
                        }
                    }
                    
                    info.ImportedDlls = dllList.ToArray();
                    info.ImportedFunctions = funcList.ToArray();
                    
                    if (importList.Count > 0)
                    {
                        string importStr = string.Join(",", importList);
                        byte[] importBytes = Encoding.ASCII.GetBytes(importStr);
                        using var md5 = MD5.Create();
                        byte[] hashBytes = md5.ComputeHash(importBytes);
                        info.ImportHashMd5 = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                        
                        using var sha256 = SHA256.Create();
                        byte[] hashBytesSha = sha256.ComputeHash(importBytes);
                        info.ImportHashSha256 = BitConverter.ToString(hashBytesSha).Replace("-", "").ToLowerInvariant();
                    }
                }
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

    private static uint RvaToOffset(uint rva, PeSectionInfo[] sections)
    {
        if (rva == 0) return 0;
        foreach (var sec in sections)
        {
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize)
            {
                return sec.RawOffset + (rva - sec.VirtualAddress);
            }
        }
        return 0;
    }

    private static string ReadNullTerminatedAscii(BinaryReader reader)
    {
        var sb = new StringBuilder();
        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            byte b = reader.ReadByte();
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }
}
