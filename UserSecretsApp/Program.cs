using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddUserSecrets<Program>()
    .Build();

var hashAlgorithm = new HashAlgorithmName(config["HashAlgorithm"]);
var keySize = Convert.ToInt32(config["KeySize"]);
var iterations = Convert.ToInt32(config["Iterations"]);

Console.WriteLine("Enter Password: ");

var input = Console.ReadLine() ?? string.Empty;
var password = new Password(input);

var (hash, salt) = password.Hash(hashAlgorithm, keySize, iterations);

Console.WriteLine($"Password hash: {hash}");
Console.WriteLine($"Generated salt: {Convert.ToHexString(salt)}");

var verified = password.Verify(hash, salt, hashAlgorithm, keySize, iterations);

Console.WriteLine($"Password is {(verified ? "verified" : "not verified")}");

Console.WriteLine("Bye User Secrets App!");


internal record Password(string Value)
{
    internal (string Hash, byte[] Salt) Hash(HashAlgorithmName hashAlgorithm, int keySize, int iterations)
    {
        var password = Encoding.UTF8.GetBytes(Value);
        var salt = RandomNumberGenerator.GetBytes(keySize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
        return (Convert.ToHexString(hash), salt);
    }

    internal bool Verify(string hash, byte[] salt, HashAlgorithmName hashAlgorithm, int keySize, int iterations)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(Value, salt, iterations, hashAlgorithm, keySize);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }
}

internal record UserSecret(string Name, Password Password);