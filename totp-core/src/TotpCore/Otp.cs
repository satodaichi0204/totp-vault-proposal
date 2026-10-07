using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TotpCore;

/// <summary>HMAC に使うハッシュ関数。otpauth URI の algorithm パラメーターに対応する。</summary>
public enum OtpAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
}

/// <summary>TOTP の計算条件。既定値は otpauth URI の既定（SHA-1 / 6桁 / 30秒）と同じ。</summary>
public readonly record struct TotpParameters(OtpAlgorithm Algorithm = OtpAlgorithm.Sha1, int Digits = 6, int Period = 30)
{
    public const int MinDigits = 6;
    public const int MaxDigits = 8;
    public const int MinPeriod = 1;
    public const int MaxPeriod = 3600;

    public static TotpParameters Default => new(OtpAlgorithm.Sha1, 6, 30);

    public void Validate()
    {
        if (!Enum.IsDefined(Algorithm))
            throw new ArgumentOutOfRangeException(nameof(Algorithm), Algorithm, "未対応のアルゴリズムです。");
        if (Digits is < MinDigits or > MaxDigits)
            throw new ArgumentOutOfRangeException(nameof(Digits), Digits, $"桁数は {MinDigits}〜{MaxDigits} で指定してください。");
        if (Period is < MinPeriod or > MaxPeriod)
            throw new ArgumentOutOfRangeException(nameof(Period), Period, $"有効期間は {MinPeriod}〜{MaxPeriod} 秒で指定してください。");
    }
}

/// <summary>
/// HOTP（RFC 4226）。TOTP はこのカウンターに時刻を入れたもの。
/// 秘密鍵は呼び出し側が所有する Span で受け取り、このクラスはコピーを残さない。
/// </summary>
public static class Hotp
{
    private static readonly int[] PowersOfTen = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];

    public static string Generate(ReadOnlySpan<byte> secret, long counter, int digits, OtpAlgorithm algorithm)
    {
        if (secret.IsEmpty)
            throw new ArgumentException("秘密鍵が空です。", nameof(secret));
        if (counter < 0)
            throw new ArgumentOutOfRangeException(nameof(counter), counter, "カウンターは 0 以上です。");
        new TotpParameters(algorithm, digits).Validate();

        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);

        // HMAC の出力も秘密鍵から導かれた値なので、使い終わったら消す
        Span<byte> mac = stackalloc byte[HMACSHA512.HashSizeInBytes];
        try
        {
            int macLength = algorithm switch
            {
                // SHA-1 の衝突攻撃は HMAC の安全性には影響しない（RFC 6194）。RFC 4226 の既定で、多くのサービスが使うため必須
#pragma warning disable CA5350
                OtpAlgorithm.Sha1 => HMACSHA1.HashData(secret, message, mac),
#pragma warning restore CA5350
                OtpAlgorithm.Sha256 => HMACSHA256.HashData(secret, message, mac),
                OtpAlgorithm.Sha512 => HMACSHA512.HashData(secret, message, mac),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
            };

            // RFC 4226 5.3 Dynamic Truncation
            int offset = mac[macLength - 1] & 0x0F;
            int binary = ((mac[offset] & 0x7F) << 24)
                       | (mac[offset + 1] << 16)
                       | (mac[offset + 2] << 8)
                       | mac[offset + 3];

            int code = binary % PowersOfTen[digits];
            return code.ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(digits, '0');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mac);
        }
    }
}

/// <summary>TOTP（RFC 6238）。</summary>
public static class Totp
{
    /// <summary>時刻ステップ T = floor((Unix 時刻 - T0) / X)。64bit で扱うので 2038 年問題の影響を受けない。</summary>
    public static long GetTimeStep(DateTimeOffset time, int period)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(period, TotpParameters.MinPeriod);
        long unixSeconds = time.ToUnixTimeSeconds();
        if (unixSeconds < 0)
            throw new ArgumentOutOfRangeException(nameof(time), time, "1970年より前の時刻は扱えません。");
        return unixSeconds / period;
    }

    public static string Generate(ReadOnlySpan<byte> secret, DateTimeOffset time, TotpParameters parameters)
    {
        parameters.Validate();
        return Hotp.Generate(secret, GetTimeStep(time, parameters.Period), parameters.Digits, parameters.Algorithm);
    }

    /// <summary>現在のコードが切り替わるまでの残り秒数（1〜period）。</summary>
    public static int SecondsRemaining(DateTimeOffset time, int period)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(period, TotpParameters.MinPeriod);
        return period - (int)(time.ToUnixTimeSeconds() % period);
    }
}
