using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Serilog;
using TextCopy;
using UserSecretsApp;

var config = CreateConfig();
var log = CreateLogger(config);

log.Information("Hello, UserSecretsApp!");

var hashAlgorithm = new HashAlgorithmName(config["HashAlgorithm"]);
var iterations = Convert.ToInt32(config["Iterations"]);
var keyLength = Convert.ToInt32(config["KeyLength"]);
var encryptionService = new EncryptionService(hashAlgorithm, iterations, keyLength);

if (config["MasterHash"] == string.Empty)
{
    log.Information("Creating new Master Hash");
    var newMasterSecret = ReadLine("Enter new Master Password: ", Console.Write);
    var (newHash, newSalt) = encryptionService.CreateHash(newMasterSecret);

    Console.WriteLine($"New Master Secret Hash: {EncryptionService.BitConverterToString(newHash)}");
    Console.WriteLine($"New Master Secret Salt: {EncryptionService.BitConverterToString(newSalt)}");
    Console.WriteLine("Store them safely.");
    Environment.Exit(0);
}

log.Information("Master Hash was found");

var masterSecret = ReadLine("Enter Master password: ", Console.Write);

var masterHash = EncryptionService.BitConverterToBytes(config["MasterHash"]!);
var masterSalt = EncryptionService.BitConverterToBytes(config["MasterSalt"]!);

var verifiedMasterSecret = encryptionService.VerifyHash(masterSecret, masterHash, masterSalt);

if (!verifiedMasterSecret)
{
    log.Information("Master Secret was not able to be verified");
    Console.WriteLine("Unable to verify Master Secret!");
    Environment.Exit(0);
}

log.Information("Master Secret was able to be verified");
Console.WriteLine("Welcome to the UserSecrets Vault!");

var currentDir = new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Vault\"));

if (!currentDir.Exists)
{
    log.Information("Vault directory was created");
    currentDir.Create();
}

log.Information("Vault directory exists");
var userSecretsFileInfo = new FileInfo(Path.Combine(currentDir.FullName, "sample-secrets-container.json"));

if (!userSecretsFileInfo.Exists)
{
    log.Information("Secret container JSON file was created");
    userSecretsFileInfo.Create().Dispose();
}

log.Information("Secret container JSON file exists");
var json = await File.ReadAllTextAsync(userSecretsFileInfo.FullName);
var secretContainers = json != string.Empty
    ? JsonSerializer.Deserialize<List<SecretContainer>>(json)!
    : new List<SecretContainer>();

var exit = false;
do
{
    var key = ReadLine("Enter User Key: ", Console.Write);
    var secretContainer = secretContainers.FirstOrDefault(u => u.Key == key);

    if (secretContainer is null)
    {
        log.Information("Secret container was not found");
        Console.WriteLine($"User key - {key} - not found...");
        var newKey = ReadLine("Enter New User Key: ", Console.Write);
        var newName = ReadLine("Enter New User Name: ", Console.Write);
        var newPassword = ReadLine("Enter New User Password: ", Console.Write);

        log.Information("New Secret was created");
        var newSecret = new Secret(newName, newPassword);
        var newJsonSecret = JsonSerializer.Serialize(newSecret);

        var rngSalt = RandomNumberGenerator.GetBytes(keyLength);
        var salt = EncryptionService.BitConverterToString(rngSalt);
        var encrypted = await encryptionService.EncryptAsync(newJsonSecret, newKey, salt);
        var newEncryptedSecret = EncryptionService.BitConverterToString(encrypted);
        var newSecretContainer = new SecretContainer(newKey, salt, newEncryptedSecret);

        log.Information("New Secret container was added");
        Console.WriteLine("New Secret container added...");

        secretContainers.Add(newSecretContainer);
        continue;
    }

    log.Information("Secret container was found");
    var decryptedSecret = EncryptionService.BitConverterToBytes(secretContainer.EncryptedSecret);
    var decrypted = await encryptionService.DecryptAsync(decryptedSecret, secretContainer.Key, secretContainer.Salt);
    var secret = JsonSerializer.Deserialize<Secret>(decrypted);

    if (secret is not null)
    {
        log.Information("Secret was found and copied to clipboard");
        Console.WriteLine("Secret was found...");
        await ClipboardService.SetTextAsync(secret.Password);
    }

    Console.WriteLine("Exit: (y/n)");
    exit = Console.ReadKey(true).Key is ConsoleKey.Y;
} while (!exit);

var options = new JsonSerializerOptions
{
    WriteIndented = true
};

var jsonString = JsonSerializer.Serialize(secretContainers, options);

log.Information("Clearing clipboard");
await ClipboardService.SetTextAsync("");

Console.WriteLine("Saving file...");
File.WriteAllText(userSecretsFileInfo.FullName, jsonString);

log.Information("Goodbye - END");
Console.WriteLine("Goodbye");


static IConfiguration CreateConfig()
{
    return new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .AddUserSecrets<Program>()
        .Build();
}

static ILogger CreateLogger(IConfiguration config)
{
    return new LoggerConfiguration()
        .ReadFrom.Configuration(config)
        .CreateLogger();
}

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