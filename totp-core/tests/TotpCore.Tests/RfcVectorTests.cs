using System.Text;

namespace TotpCore.Tests;

/// <summary>
/// RFC に掲載された正解値（テストベクター）との照合。
/// 注意：RFC 6238 Appendix B の秘密鍵は、アルゴリズムごとに長さが違う
/// （SHA-1 = 20 バイト、SHA-256 = 32 バイト、SHA-512 = 64 バイト）。本文ではなく付録のコードに合わせている。
/// </summary>
public class RfcVectorTests
{
    private static readonly byte[] SeedSha1 = Encoding.ASCII.GetBytes("12345678901234567890");
    private static readonly byte[] SeedSha256 = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
    private static readonly byte[] SeedSha512 = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");

    public static TheoryData<long, string, string, string> Rfc6238AppendixB => new()
    {
        // Unix 時刻,       SHA-1,      SHA-256,    SHA-512
        { 59L,            "94287082", "46119246", "90693936" },
        { 1111111109L,    "07081804", "68084774", "25091201" },
        { 1111111111L,    "14050471", "67062674", "99943326" },
        { 1234567890L,    "89005924", "91819424", "93441116" },
        { 2000000000L,    "69279037", "90698825", "38618901" }, // 2033年
        { 20000000000L,   "65353130", "77737706", "47863826" }, // 2603年（32bit の時刻では扱えない値）
    };

    [Theory(DisplayName = "RFC 6238 Appendix B / SHA-1 / 8桁")]
    [MemberData(nameof(Rfc6238AppendixB))]
    public void Rfc6238_Sha1(long unixTime, string sha1, string sha256, string sha512)
    {
        _ = (sha256, sha512);
        Assert.Equal(sha1, Totp.Generate(SeedSha1, DateTimeOffset.FromUnixTimeSeconds(unixTime), new(OtpAlgorithm.Sha1, 8, 30)));
    }

    [Theory(DisplayName = "RFC 6238 Appendix B / SHA-256 / 8桁")]
    [MemberData(nameof(Rfc6238AppendixB))]
    public void Rfc6238_Sha256(long unixTime, string sha1, string sha256, string sha512)
    {
        _ = (sha1, sha512);
        Assert.Equal(sha256, Totp.Generate(SeedSha256, DateTimeOffset.FromUnixTimeSeconds(unixTime), new(OtpAlgorithm.Sha256, 8, 30)));
    }

    [Theory(DisplayName = "RFC 6238 Appendix B / SHA-512 / 8桁")]
    [MemberData(nameof(Rfc6238AppendixB))]
    public void Rfc6238_Sha512(long unixTime, string sha1, string sha256, string sha512)
    {
        _ = (sha1, sha256);
        Assert.Equal(sha512, Totp.Generate(SeedSha512, DateTimeOffset.FromUnixTimeSeconds(unixTime), new(OtpAlgorithm.Sha512, 8, 30)));
    }

    [Theory(DisplayName = "RFC 4226 Appendix D / HOTP / SHA-1 / 6桁")]
    [InlineData(0, "755224")]
    [InlineData(1, "287082")]
    [InlineData(2, "359152")]
    [InlineData(3, "969429")]
    [InlineData(4, "338314")]
    [InlineData(5, "254676")]
    [InlineData(6, "287922")]
    [InlineData(7, "162583")]
    [InlineData(8, "399871")]
    [InlineData(9, "520489")]
    public void Rfc4226_Hotp(long counter, string expected)
    {
        Assert.Equal(expected, Hotp.Generate(SeedSha1, counter, 6, OtpAlgorithm.Sha1));
    }

    [Theory(DisplayName = "RFC 4648 10章 / Base32 の符号化と復号")]
    [InlineData("", "")]
    [InlineData("f", "MY======")]
    [InlineData("fo", "MZXQ====")]
    [InlineData("foo", "MZXW6===")]
    [InlineData("foob", "MZXW6YQ=")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI======")]
    public void Rfc4648_Base32(string plain, string encoded)
    {
        Assert.Equal(encoded, Base32.Encode(Encoding.ASCII.GetBytes(plain)));
        if (plain.Length > 0)
            Assert.Equal(plain, Encoding.ASCII.GetString(Base32.Decode(encoded)));
    }
}
