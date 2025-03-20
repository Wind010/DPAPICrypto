
using System.Security.Cryptography;
using System.Text;

public class WindowEncryptionUtility
{
    public static string EncryptPassword(string password, DataProtectionScope scope, byte[]? entropyBytes = null)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] encryptedBytes = ProtectedData.Protect(passwordBytes, entropyBytes, scope);
        return Convert.ToBase64String(encryptedBytes);
    }

    public static string DecryptPassword(string encryptedPassword, DataProtectionScope scope, byte[]? entropyBytes = null)
    {
        try
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedPassword);
            byte[] decryptedBytes = ProtectedData.Unprotect(encryptedBytes, entropyBytes, scope);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
        catch (FormatException)
        {
            throw new Exception("The encrypted password is not a valid Base64 string.");
        }
        catch (CryptographicException)
        {
            throw new Exception("The data is invalid or was encrypted with a different scope or user account.");
        }
        catch (Exception ex)
        {
            throw new Exception("An error occurred while decrypting the password: " + ex.Message);
        }
    }

    private static DataProtectionScope DetermineScope(string scope)
    {
        if (string.IsNullOrEmpty(scope))
        {
            throw new ArgumentException("Scope cannot be null or empty.");
        }

        switch (scope.ToLower())
        {
            case "currentuser":
            case "user":
                return DataProtectionScope.CurrentUser;
            case "localmachine":
            case "machine":
                return DataProtectionScope.LocalMachine;
            default:
                throw new ArgumentException("Invalid scope. Use 'currentUser' or 'localMachine'.");
        }
    }

    public static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("Usage: SecurePass.exe <operation> <data> <scope> [entropy]");
            Console.WriteLine("Operations: encrypt | decrypt");
            Console.WriteLine("Scopes: currentUser | localMachine");
            Console.WriteLine("Entropy: (optional) additional entropy string");
            return;
        }

        string operation = args[0].ToLower();
        string scopeArg = args[1];
        string data = args[2];
        string? entropy = args.Length > 3 ? args[3] : null;
        byte[]? entropyBytes = entropy == null ? null : Encoding.UTF8.GetBytes(entropy);

        DataProtectionScope scope = DetermineScope(scopeArg);

        try
        {
            switch (operation)
            {
                case "encrypt":
                    string encryptedPassword = EncryptPassword(data, scope, entropyBytes);
                    Console.WriteLine("Encrypted Password: " + encryptedPassword);
                    break;
                case "decrypt":
                    string decryptedPassword = DecryptPassword(data, scope, entropyBytes);
                    Console.WriteLine("Decrypted Password: " + decryptedPassword);
                    break;
                default:
                    Console.WriteLine("Invalid operation. Use 'encrypt' or 'decrypt'.");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}