using System.Security.Cryptography;
using System.Text;

namespace WAF;

public class AesCryptor
{
    private static readonly int KeySizeInBytes = 32; // 256 bits for AES encryption
    private static readonly int IvSizeInBytes = 16; // 128 bits for AES encryption

    private readonly byte[] keyBytes;

    public AesCryptor(string EncryptionKey)
    {
        keyBytes = DeriveKeyBytes(EncryptionKey, KeySizeInBytes);
    }

    public string Encrypt(string sessionID)
    {
        using Aes aesAlg = Aes.Create();
        aesAlg.Key = keyBytes;
        aesAlg.GenerateIV();

        using ICryptoTransform encryptor = aesAlg.CreateEncryptor();
        using MemoryStream msEncrypt = new();
        using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (StreamWriter swEncrypt = new(csEncrypt))
        {
            swEncrypt.Write(sessionID);
        }

        byte[] cipherText = aesAlg.IV.Concat(msEncrypt.ToArray()).ToArray();
        return Convert.ToBase64String(cipherText);
    }

    public string Decrypt(string encryptedSessionID)
    {
        byte[] fullCipher = Convert.FromBase64String(encryptedSessionID);

        using Aes aesAlg = Aes.Create();
        aesAlg.Key = keyBytes;
        aesAlg.IV = fullCipher.Take(IvSizeInBytes).ToArray();
        byte[] cipherTextBytes = fullCipher.Skip(IvSizeInBytes).ToArray();

        using ICryptoTransform decryptor = aesAlg.CreateDecryptor();
        using MemoryStream msDecrypt = new(cipherTextBytes);
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
        using StreamReader srDecrypt = new(csDecrypt);
        return srDecrypt.ReadToEnd();
    }

    private static byte[] DeriveKeyBytes(string key, int keySizeInBytes)
    {
        using var sha256 = SHA256.Create();
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] hash = sha256.ComputeHash(keyBytes);

        // Truncate or pad the hash to the desired key size
        byte[] derivedKey = new byte[keySizeInBytes];
        Array.Copy(hash, derivedKey, Math.Min(keySizeInBytes, hash.Length));

        return derivedKey;
    }
}
