using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using TextCopy;

using UserSecretsApp;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddUserSecrets<Program>()
    .Build();

var hashAlgorithm = new HashAlgorithmName(config["HashAlgorithm"]);
var iterations = Convert.ToInt32(config["Iterations"]);
var keyLength = Convert.ToInt32(config["KeyLength"]);
var encryptionService = new EncryptionService(hashAlgorithm, iterations, keyLength);

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
while (!exit)
{
    var key = ReadLine("Enter User Key: ", Console.Write);
    var secretContainer = secretContainers.FirstOrDefault(u => u.Key == key);

    if (secretContainer is null)
    {
        Console.WriteLine();
        Console.WriteLine($"User key - {key} - not found...");
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
        Console.WriteLine("Secret was found...");
        await ClipboardService.SetTextAsync(secret.Password);
    }
    
    Console.Write("Exit: (y/n)");
    exit = Console.ReadKey(true).Key is ConsoleKey.Y;
}

var options = new JsonSerializerOptions 
{ 
    WriteIndented = true
};

var jsonString = JsonSerializer.Serialize(secretContainers, options);

await ClipboardService.SetTextAsync("");
await Task.Run(() => File.WriteAllText(userSecretsFileInfo.FullName, jsonString));

Console.WriteLine();
Console.WriteLine("Saving file...");
Console.WriteLine("Goodbye");


static string ReadLine(string? message, Action<string> writer)
{
    if (message is not null)
    {
        writer(message);
    }

    return Console.ReadLine() ?? string.Empty;
}

internal record Secret(string User, string Password);

internal record SecretContainer(string Key, string Salt, string EncryptedSecret);