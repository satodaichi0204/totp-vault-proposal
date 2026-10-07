using System.Security.Cryptography;

namespace TotpCore;

/// <summary>QR コードから読み取った otpauth URI の内容。</summary>
public sealed class OtpAuthEntry : IDisposable
{
    internal OtpAuthEntry(string issuer, string accountName, byte[] secret, TotpParameters parameters, bool issuerMismatch)
    {
        Issuer = issuer;
        AccountName = accountName;
        Secret = secret;
        Parameters = parameters;
        IssuerMismatch = issuerMismatch;
    }

    public string Issuer { get; }
    public string AccountName { get; }

    /// <summary>復号済みの秘密鍵。Dispose で 0 埋めされる。</summary>
    public byte[] Secret { get; }

    public TotpParameters Parameters { get; }

    /// <summary>ラベルの発行元と issuer パラメーターが食い違う。登録前に利用者へ確認を促す。</summary>
    public bool IssuerMismatch { get; }

    public void Dispose() => CryptographicOperations.ZeroMemory(Secret);

    // 秘密鍵をデバッガーやログに出さない
    public override string ToString() => $"{Issuer}:{AccountName} ({Parameters.Algorithm}, {Parameters.Digits}桁, {Parameters.Period}秒)";
}

/// <summary>
/// otpauth://totp/ の URI を解析する（Google Authenticator の Key Uri Format に準拠）。
/// 例: otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&amp;issuer=Example&amp;algorithm=SHA256&amp;digits=8&amp;period=60
/// </summary>
public static class OtpAuthUri
{
    private const string Scheme = "otpauth://";

    public static OtpAuthEntry Parse(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        uri = uri.Trim();

        if (uri.StartsWith("otpauth-migration://", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Google Authenticator のエクスポート形式です。一括取り込み機能で読み込んでください。");
        if (!uri.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            throw new FormatException("otpauth:// で始まる URI ではありません。");

        string rest = uri[Scheme.Length..];
        int slash = rest.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
            throw new FormatException("種類（totp）の後にラベルがありません。");

        string type = rest[..slash];
        if (type.Equals("hotp", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("HOTP（カウンター方式）は対象外です。TOTP の QR コードを使ってください。");
        if (!type.Equals("totp", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("未対応の種類です。");

        rest = rest[(slash + 1)..];
        int question = rest.IndexOf('?', StringComparison.Ordinal);
        string rawLabel = question < 0 ? rest : rest[..question];
        string query = question < 0 ? string.Empty : rest[(question + 1)..];

        // ラベルは「発行元:アカウント名」。区切りの ':' は %3A と書かれることもあるので、デコード後に分ける
        string label = Uri.UnescapeDataString(rawLabel);
        string labelIssuer = string.Empty;
        string accountName = label;
        int colon = label.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            labelIssuer = label[..colon].Trim();
            accountName = label[(colon + 1)..].Trim();
        }

        string? secretText = null;
        string? issuerParam = null;
        var parameters = TotpParameters.Default;

        foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            string key = eq < 0 ? pair : pair[..eq];
            string value = eq < 0 ? string.Empty : DecodeQueryValue(pair[(eq + 1)..]);

            switch (key.ToLowerInvariant())
            {
                case "secret":
                    secretText = value;
                    break;
                case "issuer":
                    issuerParam = value.Trim();
                    break;
                case "algorithm":
                    parameters = parameters with { Algorithm = ParseAlgorithm(value) };
                    break;
                case "digits":
                    parameters = parameters with { Digits = ParseInt(value, "digits") };
                    break;
                case "period":
                    parameters = parameters with { Period = ParseInt(value, "period") };
                    break;
                // counter（HOTP 用）や image など未知のパラメーターは無視する
            }
        }

        if (string.IsNullOrEmpty(secretText))
            throw new FormatException("secret パラメーターがありません。");

        parameters.Validate();

        bool mismatch = !string.IsNullOrEmpty(issuerParam)
                        && !string.IsNullOrEmpty(labelIssuer)
                        && !string.Equals(issuerParam, labelIssuer, StringComparison.OrdinalIgnoreCase); // 大文字小文字の違いだけなら警告しない
        string issuer = !string.IsNullOrEmpty(issuerParam) ? issuerParam : labelIssuer;

        byte[] secret = Base32.Decode(secretText);
        return new OtpAuthEntry(issuer, accountName, secret, parameters, mismatch);
    }

    private static string DecodeQueryValue(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

    private static OtpAlgorithm ParseAlgorithm(string value) => value.ToUpperInvariant() switch
    {
        "SHA1" or "SHA-1" => OtpAlgorithm.Sha1,
        "SHA256" or "SHA-256" => OtpAlgorithm.Sha256,
        "SHA512" or "SHA-512" => OtpAlgorithm.Sha512,
        _ => throw new FormatException("未対応のアルゴリズムです（SHA1 / SHA256 / SHA512 のみ）。"),
    };

    private static int ParseInt(string value, string name) =>
        int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int n)
            ? n
            : throw new FormatException($"{name} が数値ではありません。");
}
