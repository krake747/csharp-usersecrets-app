using System.Security.Cryptography;
using System.Text;

namespace UserSecretsApp;

internal sealed class EncryptionService
{
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly int _iterations;
    private readonly int _keyLength;

    public EncryptionService(HashAlgorithmName hashAlgorithm, int iterations, int keyLength)
    {
        _hashAlgorithm = hashAlgorithm;
        _iterations = iterations;
        _keyLength = keyLength;
    }

    internal async Task<byte[]> EncryptAsync(string message, string secretKey, string salt)
    {
        using var aes = Aes.Create();
        aes.Key = CreateDerivedKey(secretKey, Array.Empty<byte>(), _hashAlgorithm, _iterations, _keyLength);
        aes.IV = BitConverterToBytes(salt);
        var encryptor = aes.CreateEncryptor();
        using var output = new MemoryStream();
        await using var cryptoStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write);
        await cryptoStream.WriteAsync(Encoding.Unicode.GetBytes(message));
        await cryptoStream.FlushFinalBlockAsync();
        return output.ToArray();
    }

    internal async Task<string> DecryptAsync(byte[] encrypted, string secretKey, string salt)
    {
        using var aes = Aes.Create();
        aes.Key = CreateDerivedKey(secretKey, Array.Empty<byte>(), _hashAlgorithm, _iterations, _keyLength);
        aes.IV = BitConverterToBytes(salt);
        var decryptor = aes.CreateDecryptor();
        using var input = new MemoryStream(encrypted);
        await using var cryptoStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read);
        using var output = new MemoryStream();
        await cryptoStream.CopyToAsync(output);
        return Encoding.Unicode.GetString(output.ToArray());
    }

    private static byte[] CreateDerivedKey(string secretKey, byte[] salt, HashAlgorithmName hashAlgorithm,
        int iterations, int keyLength)
    {
        var secret = Encoding.Unicode.GetBytes(secretKey);
        return Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, hashAlgorithm, keyLength);
    }

    internal (byte[] Hash, byte[] Salt) CreateHash(string secret)
    {
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var salt = RandomNumberGenerator.GetBytes(_keyLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secretBytes, salt, _iterations, _hashAlgorithm, _keyLength);
        return (hash, salt);
    }

    internal bool VerifyHash(string secret, byte[] hash, byte[] salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(secret, salt, _iterations, _hashAlgorithm, _keyLength);
        return hashToCompare.SequenceEqual(hash);
    }

    internal static string BitConverterToString(byte[] bytes)
    {
        return BitConverter.ToString(bytes);
    }

    internal static byte[] BitConverterToBytes(string str)
    {
        return str.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();
    }
}