using System;
using System.IO;
using System.Security.Cryptography;

namespace clamshield_antivirus.Services.UpdateSvc;

public static class CvdVerifier
{
    private static readonly byte[] ClamavRsaModulus = Convert.FromHexString(
        "C1572E2B72E7FDC61B609166C363C31D89A557D5B9D8FCFDA5CEE14923C1F9D1" +
        "35936175C40991F4A1FDF1C4A9B68F38DF398E2A5390F4CBA56530AB6B5C79F6" +
        "939FA258B26B77C1BFA3273A6186CB9BB2B3A18BD68C6E1B993E8BEBEF5C6DD0" +
        "97730A0270D58C70EAC8F7D7A16F6D8F8B2D0C9DD87B8FB0E0630B636D51C716" +
        "638717A8F444E62FBC21CD3F6889AA5DA7168C50B89D7E45773A03D8E05437EE" +
        "AB0FA7521E7068B73DB91645AC8B3159B29CB21709B70A26DEED3A3E7DD0AEAE" +
        "B84A9BAB68ABD72242912B24361FE2E3C83F9D18955B4629A9BCFFB4E5C6B374" +
        "76B361241BB607C16A61873017F07BA5B1D9B27D3C0F5FFF3C0A8F38943529AB");

    private static readonly byte[] ClamavRsaExponent = new byte[] { 0x01, 0x00, 0x01 };

    public static bool VerifyCvdSignature(string cvdFilePath)
    {
        try
        {
            using var fs = new FileStream(cvdFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= 512)
                return false;

            byte[] headerBytes = new byte[512];
            fs.ReadExactly(headerBytes, 0, 512);

            string headerStr = System.Text.Encoding.ASCII.GetString(headerBytes);
            var parts = headerStr.Split(':');

            if (parts.Length <= 6)
                return false;

            string? storedSignature = parts[6]?.Trim('\0', ' ');
            if (string.IsNullOrEmpty(storedSignature) || storedSignature.Length < 20)
                return false;

            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromHexString(storedSignature);
            }
            catch
            {
                return false;
            }

            using var sha256 = SHA256.Create();
            using var md5 = MD5.Create();
            long bodyLen = fs.Length - 512;
            fs.Position = 512;

            byte[] bodyHash;
            byte[] bodyMd5;

            if (bodyLen <= 1024 * 1024 * 100)
            {
                byte[] body = new byte[bodyLen];
                int offset = 0;
                while (offset < body.Length)
                {
                    int read = fs.Read(body, offset, body.Length - offset);
                    if (read <= 0) break;
                    offset += read;
                }
                bodyHash = sha256.ComputeHash(body);
                bodyMd5 = md5.ComputeHash(body);
            }
            else
            {
                bodyHash = sha256.ComputeHash(fs);
                fs.Position = 512;
                bodyMd5 = md5.ComputeHash(fs);
            }

            using var rsa = new RSACryptoServiceProvider();
            var rsaParams = new RSAParameters
            {
                Modulus = ClamavRsaModulus,
                Exponent = ClamavRsaExponent
            };
            rsa.ImportParameters(rsaParams);

            try
            {
                if (rsa.VerifyHash(bodyMd5, CryptoConfig.MapNameToOID("MD5")!, signatureBytes))
                    return true;
            }
            catch { }

            try
            {
                if (rsa.VerifyHash(bodyHash, CryptoConfig.MapNameToOID("SHA256")!, signatureBytes))
                    return true;
            }
            catch { }

            return false;
        }
        catch
        {
            return false;
        }
    }

    public static string? GetSignatureFromCvd(string cvdFilePath)
    {
        try
        {
            using var fs = new FileStream(cvdFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= 512) return null;

            byte[] headerBytes = new byte[512];
            fs.ReadExactly(headerBytes, 0, 512);

            string headerStr = System.Text.Encoding.ASCII.GetString(headerBytes);
            var parts = headerStr.Split(':');
            if (parts.Length <= 6) return null;

            return parts[6]?.Trim('\0', ' ');
        }
        catch
        {
            return null;
        }
    }

    public static bool HasValidSignature(string cvdFilePath)
    {
        try
        {
            using var fs = new FileStream(cvdFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= 512) return false;

            byte[] headerBytes = new byte[512];
            fs.ReadExactly(headerBytes, 0, 512);

            string headerStr = System.Text.Encoding.ASCII.GetString(headerBytes);
            var parts = headerStr.Split(':');

            if (parts.Length <= 6) return false;

            string signature = parts[6]?.Trim('\0', ' ') ?? string.Empty;
            return signature.Length >= 20 && IsHexString(signature);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsHexString(string s)
    {
        foreach (char c in s)
        {
            if (!Uri.IsHexDigit(c))
                return false;
        }
        return true;
    }
}
