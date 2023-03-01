using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using TextCopy;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddUserSecrets<Program>()
    .Build();

var hashAlgorithm = new HashAlgorithmName(config["HashAlgorithm"]);
var iterations = Convert.ToInt32(config["Iterations"]);
var keyLength = Convert.ToInt32(config["KeyLength"]);
var encryptionService = new EncryptionService(hashAlgorithm, iterations, keyLength);

var s = new Secret("kk", "hh");
try
{
    Console.WriteLine(s.ToString());
}
catch (Exception ex)
{
    // ignored
}

if (config["MasterHash"] == string.Empty)
{
    var newMasterSecret = ReadLine("Enter new Master Password: ", Console.Write);
    var (newHash, newSalt) = encryptionService.CreateHash(newMasterSecret);

    Console.WriteLine($"New Master Secret Hash: {EncryptionService.BitConverterToString(newHash)}");
    Console.WriteLine($"New Master Secret Salt: {EncryptionService.BitConverterToString(newSalt)}");
    Console.WriteLine("Store them safely.");
    Environment.Exit(0);
}

Console.WriteLine("Welcome to the UserSecrets Vault!");
Console.WriteLine();
var masterSecret = ReadLine("Enter Master password: ", Console.Write);

var masterHash = EncryptionService.BitConverterToBytes(config["MasterHash"]!);
var masterSalt = EncryptionService.BitConverterToBytes(config["MasterSalt"]!);

var verifiedMasterSecret = encryptionService.VerifyHash(masterSecret, masterHash, masterSalt);

if (!verifiedMasterSecret)
{
    Console.WriteLine("Unable to verify Master Secret!");
    Environment.Exit(0);
}

var currentDir = new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Vault\"));
var userSecretsFileInfo = new FileInfo(Path.Combine(currentDir.FullName, "secrets-container.json"));

if (!userSecretsFileInfo.Exists)
{
    userSecretsFileInfo.Create().Dispose();
}

var json = await File.ReadAllTextAsync(userSecretsFileInfo.FullName);
var secretContainers = json != string.Empty
    ? JsonSerializer.Deserialize<List<SecretContainer>>(json)! 
    : new List<SecretContainer>();

var exit = false;
while (verifiedMasterSecret && userSecretsFileInfo.Exists && !exit)
{
    var key = ReadLine("Enter User Key: ", Console.Write);
    var secretContainer = secretContainers.FirstOrDefault(u => u.Key == key);

    if (secretContainer is null)
    {
        Console.WriteLine();
        Console.WriteLine($"User key - {key} - not found.");
        var newKey = ReadLine("Enter New User Key: ", Console.Write);
        var newName = ReadLine("Enter New User Name: ", Console.Write);
        var newPassword = ReadLine("Enter New User Password: ", Console.Write);
        var newSecret = new Secret(newName, newPassword);
        var newJsonSecret = JsonSerializer.Serialize(newSecret); 

        var rngSalt = RandomNumberGenerator.GetBytes(keyLength);
        var salt = EncryptionService.BitConverterToString(rngSalt);
        var encrypted = await encryptionService.EncryptAsync(newJsonSecret, newKey, salt);
        var newEncryptedSecret = EncryptionService.BitConverterToString(encrypted);
        var newSecretContainer = new SecretContainer(newKey, salt, newEncryptedSecret);
        Console.WriteLine("New Secret Container added...");
        Console.WriteLine();
        //Console.WriteLine($"Encrypted data: {newEncryptedSecret}");

        secretContainers.Add(newSecretContainer);
        continue;
    }

    var decryptedSecret = EncryptionService.BitConverterToBytes(secretContainer.EncryptedSecret);
    var decrypted = await encryptionService.DecryptAsync(decryptedSecret, secretContainer.Key, secretContainer.Salt);
    var secret = JsonSerializer.Deserialize<Secret>(decrypted);
    //Console.WriteLine($"Decrypted data: {decrypted}");

    if (secret is not null)
    {
        await ClipboardService.SetTextAsync(secret.Password);
    }
    
    Console.WriteLine("Exit: (y/n)");
    exit = Console.ReadKey(true).Key is ConsoleKey.Y;
}

var options = new JsonSerializerOptions 
{ 
    WriteIndented = true
};

var jsonString = JsonSerializer.Serialize(secretContainers, options);

await Task.Run(() => File.WriteAllText(userSecretsFileInfo.FullName, jsonString));

Console.WriteLine("Saving file...");

Console.WriteLine();

static string ReadLine(string? message, Action<string> writer)
{
    if (message is not null)
    {
        writer(message);
    }

    return Console.ReadLine() ?? string.Empty;
}

internal class EncryptionService
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

internal record Secret(string User, string Password);

internal record SecretContainer(string Key, string Salt, string EncryptedSecret);