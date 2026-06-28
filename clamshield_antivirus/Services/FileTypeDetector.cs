using System;
using System.IO;
using System.Text;

namespace clamshield_antivirus.Services;

public enum ClamFileType
{
    ANY = 0,
    TEXT_ASCII = 500,
    TEXT_UTF8,
    TEXT_UTF16LE,
    TEXT_UTF16BE,
    BINARY_DATA,
    ERROR_TYPE,
    MSEXE,
    ELF,
    MACHO,
    MACHO_UNIBIN,
    POSIX_TAR,
    OLD_TAR,
    CPIO_OLD,
    CPIO_ODC,
    CPIO_NEWC,
    CPIO_CRC,
    GZ,
    ZIP,
    BZ,
    RAR,
    ARJ,
    MSSZDD,
    MSOLE2,
    MSCAB,
    MSCHM,
    SIS,
    SCRENC,
    GRAPHICS,
    GIF,
    PNG,
    JPEG,
    TIFF,
    RIFF,
    BINHEX,
    TNEF,
    CRYPTFF,
    PDF,
    UUENCODED,
    SCRIPT,
    HTML_UTF16,
    RTF,
    S7Z,
    SWF,
    JAVA,
    XAR,
    XZ,
    INTERNAL,
    HTML,
    MAIL,
    SFX,
    ZIPSFX,
    RARSFX,
    S7ZSFX,
    CABSFX,
    AUTOIT,
    ISHIELD_MSI,
    ISO9660,
    DMG,
    LNK,
    OTHER,
    IGNORED
}

public static class FileTypeDetector
{
    private static readonly byte[] GZIP_MAGIC = { 0x1F, 0x8B };
    private static readonly byte[] BZIP2_MAGIC = { 0x42, 0x5A };
    private static readonly byte[] XZ_MAGIC = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
    private static readonly byte[] RAR_MAGIC = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 };
    private static readonly byte[] RAR5_MAGIC = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    private static readonly byte[] S7Z_MAGIC = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
    private static readonly byte[] ZIP_MAGIC = { 0x50, 0x4B };
    private static readonly byte[] TAR_MAGIC_USTAR = { 0x75, 0x73, 0x74, 0x61, 0x72 }; // "ustar" at offset 257
    private static readonly byte[] PE_MAGIC = { 0x4D, 0x5A };
    private static readonly byte[] ELF_MAGIC = { 0x7F, 0x45, 0x4C, 0x46 };
    private static readonly byte[] PDF_MAGIC = { 0x25, 0x50, 0x44, 0x46 };
    private static readonly byte[] OLE2_MAGIC = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    private static readonly byte[] RTF_MAGIC = { 0x7B, 0x5C, 0x72, 0x74, 0x66 };
    private static readonly byte[] SWF_CWS_MAGIC = { 0x43, 0x57, 0x53 };
    private static readonly byte[] SWF_FWS_MAGIC = { 0x46, 0x57, 0x53 };
    private static readonly byte[] JAVA_CLASS_MAGIC = { 0xCA, 0xFE, 0xBA, 0xBE };
    private static readonly byte[] CAB_MAGIC = { 0x4D, 0x53, 0x43, 0x46 };
    private static readonly byte[] CHM_MAGIC = { 0x49, 0x54, 0x53, 0x46 };
    private static readonly byte[] ARJ_MAGIC = { 0xEA, 0x60 };
    private static readonly byte[] GIF_MAGIC = { 0x47, 0x49, 0x46 };
    private static readonly byte[] PNG_MAGIC = { 0x89, 0x50, 0x4E, 0x47 };
    private static readonly byte[] JPEG_MAGIC = { 0xFF, 0xD8, 0xFF };
    private static readonly byte[] TIFF_LE = { 0x49, 0x49, 0x2A, 0x00 };
    private static readonly byte[] TIFF_BE = { 0x4D, 0x4D, 0x00, 0x2A };
    private static readonly byte[] RIFF_MAGIC = { 0x52, 0x49, 0x46, 0x46 };
    private static readonly byte[] BINHEX_MAGIC = Encoding.ASCII.GetBytes("(This file must be converted with BinHex");
    private static readonly byte[] MACHO_MAGIC = { 0xFE, 0xED, 0xFA, 0xCE };
    private static readonly byte[] MACHO_CIGAM = { 0xCE, 0xFA, 0xED, 0xFE };
    private static readonly byte[] MACHO_64 = { 0xFE, 0xED, 0xFA, 0xCF };
    private static readonly byte[] MACHO_CIGAM_64 = { 0xCF, 0xFA, 0xED, 0xFE };
    private static readonly byte[] MACHO_FAT = { 0xCA, 0xFE, 0xBA, 0xBE };
    private static readonly byte[] MACHO_FAT_CIGAM = { 0xBE, 0xBA, 0xFE, 0xCA };
    private static readonly byte[] ISO_MAGIC = { 0x43, 0x44, 0x30, 0x30, 0x31 };
    private static readonly byte[] LNK_MAGIC = { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 };

    public static ClamFileType DetectType(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return DetectTypeFromStream(fs, filePath);
        }
        catch
        {
            return ClamFileType.BINARY_DATA;
        }
    }

    public static ClamFileType DetectTypeFromStream(Stream stream, string? fileName = null)
    {
        if (stream.Length < 4)
            return ClamFileType.BINARY_DATA;

        long origPos = stream.Position;
        byte[] magic = new byte[Math.Min((int)stream.Length, 1024)];
        stream.ReadExactly(magic, 0, magic.Length);
        stream.Position = origPos;

        var result = DetectByMagic(magic);
        if (result != ClamFileType.ANY && result != ClamFileType.BINARY_DATA)
            return result;

        if (fileName != null)
        {
            result = DetectByExtension(fileName);
            if (result != ClamFileType.ANY)
                return result;
        }

        if (IsTextAscii(magic))
            return ClamFileType.TEXT_ASCII;

        return ClamFileType.BINARY_DATA;
    }

    private static ClamFileType DetectByMagic(byte[] magic)
    {
        if (magic.Length < 2) return ClamFileType.ANY;

        if (MagicMatch(magic, GZIP_MAGIC)) return ClamFileType.GZ;
        if (MagicMatch(magic, BZIP2_MAGIC)) return ClamFileType.BZ;
        if (magic.Length >= 6 && MagicMatch(magic, XZ_MAGIC)) return ClamFileType.XZ;
        if (magic.Length >= 8 && MagicMatch(magic, RAR5_MAGIC)) return ClamFileType.RAR;
        if (magic.Length >= 7 && MagicMatch(magic, RAR_MAGIC)) return ClamFileType.RAR;
        if (magic.Length >= 6 && MagicMatch(magic, S7Z_MAGIC)) return ClamFileType.S7Z;
        if (MagicMatch(magic, ZIP_MAGIC))
        {
            if (magic.Length > 30)
                return DetectZipType(magic);
            return ClamFileType.ZIP;
        }
        if (MagicMatch(magic, PE_MAGIC))
        {
            if (magic.Length > 64 && magic[0x3C] < 0xF0)
            {
                int peOffset = magic[0x3C];
                if (peOffset + 4 < magic.Length &&
                    magic[peOffset] == 0x50 && magic[peOffset + 1] == 0x45)
                    return ClamFileType.MSEXE;
            }
            return ClamFileType.MSEXE;
        }
        if (MagicMatch(magic, ELF_MAGIC)) return ClamFileType.ELF;
        if (MagicMatch(magic, PDF_MAGIC)) return ClamFileType.PDF;
        if (magic.Length >= 8 && MagicMatch(magic, OLE2_MAGIC)) return ClamFileType.MSOLE2;
        if (MagicMatch(magic, RTF_MAGIC)) return ClamFileType.RTF;
        if (MagicMatch(magic, SWF_CWS_MAGIC) || MagicMatch(magic, SWF_FWS_MAGIC)) return ClamFileType.SWF;
        if (MagicMatch(magic, JAVA_CLASS_MAGIC)) return ClamFileType.JAVA;
        if (MagicMatch(magic, CAB_MAGIC)) return ClamFileType.MSCAB;
        if (MagicMatch(magic, CHM_MAGIC)) return ClamFileType.MSCHM;
        if (MagicMatch(magic, ARJ_MAGIC)) return ClamFileType.ARJ;
        if (MagicMatch(magic, GIF_MAGIC)) return ClamFileType.GIF;
        if (MagicMatch(magic, PNG_MAGIC)) return ClamFileType.PNG;
        if (MagicMatch(magic, JPEG_MAGIC)) return ClamFileType.JPEG;
        if (MagicMatch(magic, TIFF_LE) || MagicMatch(magic, TIFF_BE)) return ClamFileType.TIFF;
        if (MagicMatch(magic, MACHO_MAGIC) || MagicMatch(magic, MACHO_CIGAM) ||
            MagicMatch(magic, MACHO_64) || MagicMatch(magic, MACHO_CIGAM_64)) return ClamFileType.MACHO;
        if (MagicMatch(magic, MACHO_FAT) || MagicMatch(magic, MACHO_FAT_CIGAM)) return ClamFileType.MACHO_UNIBIN;
        if (MagicMatch(magic, ISO_MAGIC)) return ClamFileType.ISO9660;
        if (magic.Length >= 4 && MagicMatch(magic, LNK_MAGIC)) return ClamFileType.LNK;

        if (magic.Length > 257)
        {
            byte[] tarCheck = new byte[5];
            Array.Copy(magic, 257, tarCheck, 0, 5);
            if (MagicMatch(tarCheck, TAR_MAGIC_USTAR))
                return ClamFileType.POSIX_TAR;
        }

        return ClamFileType.ANY;
    }

    private static ClamFileType DetectZipType(byte[] magic)
    {
        if (magic.Length < 512) return ClamFileType.ZIP;

        try
        {
            string preamble = Encoding.ASCII.GetString(magic, 0, Math.Min(512, magic.Length));

            if (preamble.Contains("MZ") || preamble.Contains("This program"))
                return ClamFileType.ZIPSFX;
            if (preamble.Contains("RAR") || preamble.Contains("rar"))
                return ClamFileType.RARSFX;
            if (preamble.Contains("7z"))
                return ClamFileType.S7ZSFX;
            if (preamble.StartsWith("MSCF"))
                return ClamFileType.CABSFX;
        }
        catch { }

        return ClamFileType.ZIP;
    }

    private static ClamFileType DetectByExtension(string fileName)
    {
        string ext = Path.GetExtension(fileName).ToLowerInvariant();
        return ext switch
        {
            ".exe" or ".dll" or ".sys" or ".ocx" or ".scr" => ClamFileType.MSEXE,
            ".elf" => ClamFileType.ELF,
            ".pdf" => ClamFileType.PDF,
            ".doc" or ".xls" or ".ppt" or ".ole" => ClamFileType.MSOLE2,
            ".docx" or ".xlsx" or ".pptx" => ClamFileType.ZIP,
            ".zip" or ".jar" or ".apk" or ".xapk" => ClamFileType.ZIP,
            ".rar" => ClamFileType.RAR,
            ".7z" => ClamFileType.S7Z,
            ".gz" or ".tgz" => ClamFileType.GZ,
            ".bz2" or ".tbz" => ClamFileType.BZ,
            ".xz" => ClamFileType.XZ,
            ".tar" => ClamFileType.POSIX_TAR,
            ".cab" => ClamFileType.MSCAB,
            ".arj" => ClamFileType.ARJ,
            ".html" or ".htm" or ".asp" or ".aspx" or ".php" => ClamFileType.HTML,
            ".eml" or ".msg" or ".mbox" => ClamFileType.MAIL,
            ".gif" => ClamFileType.GIF,
            ".png" => ClamFileType.PNG,
            ".jpg" or ".jpeg" => ClamFileType.JPEG,
            ".tiff" or ".tif" => ClamFileType.TIFF,
            ".swf" => ClamFileType.SWF,
            ".class" => ClamFileType.JAVA,
            ".iso" => ClamFileType.ISO9660,
            ".lnk" => ClamFileType.LNK,
            _ => ClamFileType.ANY
        };
    }

    private static bool MagicMatch(byte[] data, byte[] magic)
    {
        if (data.Length < magic.Length) return false;
        for (int i = 0; i < magic.Length; i++)
            if (data[i] != magic[i]) return false;
        return true;
    }

    private static bool IsTextAscii(byte[] data)
    {
        int len = Math.Min(data.Length, 512);
        int printable = 0;
        for (int i = 0; i < len; i++)
        {
            byte b = data[i];
            if (b == 0) return false;
            if (b >= 0x20 && b <= 0x7E) printable++;
            else if (b == '\t' || b == '\n' || b == '\r') printable++;
            else if (b >= 0x80) return false;
        }
        return printable > len * 0.8;
    }
}
