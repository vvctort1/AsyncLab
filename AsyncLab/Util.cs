using System.Security.Cryptography;
using System.Text;

public static class Util
{
    // Sanitiza campos para CSV simples
    public static string San(string s) => (s ?? "").Replace("\"", "").Trim();

    // Constrói um salt determinístico a partir do IBGE + um “pepper” fixo (opcional)
    public static byte[] BuildSalt(string ibge)
    {
        // Inclui um pepper fixo para fortalecer; mantém determinismo.
        const string pepper = "PBKDF2_DEMOSYNC_V1";
        return Encoding.UTF8.GetBytes($"{ibge}|{pepper}");
    }

    public static string DeriveHashHex(string password, byte[] salt, int iterations, int sizeBytes)
    {
        using var pbk = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        var bytes = pbk.GetBytes(sizeBytes);
        return ToHex(bytes);
    }

    public static string ToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (var b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
