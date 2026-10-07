using System.Text;

namespace TotpCore.Tests;

public class TotpBehaviorTests
{
    private static readonly byte[] Seed = Encoding.ASCII.GetBytes("12345678901234567890");

    [Fact(DisplayName = "6桁のコードは 8桁のコードの下6桁と一致する")]
    public void SixDigitsIsSuffixOfEightDigits()
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(1111111109);
        string eight = Totp.Generate(Seed, time, new(OtpAlgorithm.Sha1, 8, 30));
        string six = Totp.Generate(Seed, time, new(OtpAlgorithm.Sha1, 6, 30));
        Assert.Equal(eight[^6..], six);
        Assert.Equal("081804", six); // 先頭の 0 が欠けないこと
    }

    [Fact(DisplayName = "有効期間 60秒：同じ 60秒の区間では同じコード、区間をまたぐと変わる")]
    public void SixtySecondPeriod()
    {
        var p = new TotpParameters(OtpAlgorithm.Sha1, 6, 60);
        string a = Totp.Generate(Seed, DateTimeOffset.FromUnixTimeSeconds(1_800_000_000), p);
        string b = Totp.Generate(Seed, DateTimeOffset.FromUnixTimeSeconds(1_800_000_059), p);
        string c = Totp.Generate(Seed, DateTimeOffset.FromUnixTimeSeconds(1_800_000_060), p);
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    [Theory(DisplayName = "残り秒数の表示（30秒周期）")]
    [InlineData(1_800_000_000L, 30)] // 区間の先頭
    [InlineData(1_800_000_001L, 29)]
    [InlineData(1_800_000_029L, 1)]  // 区間の最後
    public void SecondsRemaining(long unixTime, int expected)
    {
        Assert.Equal(expected, Totp.SecondsRemaining(DateTimeOffset.FromUnixTimeSeconds(unixTime), 30));
    }

    [Theory(DisplayName = "範囲外の桁数・周期は拒否する")]
    [InlineData(5, 30)]
    [InlineData(9, 30)]
    [InlineData(6, 0)]
    public void RejectsInvalidParameters(int digits, int period)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Totp.Generate(Seed, DateTimeOffset.UtcNow, new(OtpAlgorithm.Sha1, digits, period)));
    }

    [Fact(DisplayName = "空の秘密鍵は拒否する")]
    public void RejectsEmptySecret()
    {
        Assert.Throws<ArgumentException>(() => Totp.Generate([], DateTimeOffset.UtcNow, TotpParameters.Default));
    }
}

public class Base32InputTests
{
    [Fact(DisplayName = "手入力の揺れ（小文字・空白・ハイフン・パディングなし）を許容する")]
    public void AcceptsHumanFormatting()
    {
        byte[] expected = Base32.Decode("JBSWY3DPEHPK3PXP");
        Assert.Equal(expected, Base32.Decode("jbsw y3dp ehpk 3pxp"));
        Assert.Equal(expected, Base32.Decode("JBSW-Y3DP-EHPK-3PXP"));
        Assert.Equal(Base32.Decode("MZXW6YQ"), Base32.Decode("MZXW6YQ="));
        Assert.Equal("Hello!Þ­¾ï", Encoding.Latin1.GetString(expected));
    }

    [Theory(DisplayName = "Base32 で使えない文字は拒否し、エラーに秘密鍵の文字を含めない")]
    [InlineData("JBSWY3DP0HPK3PXP")]  // 数字の 0
    [InlineData("JBSWY3DP1HPK3PXP")]  // 数字の 1
    [InlineData("ＪＢＳＷＹ３ＤＰ")]    // 全角
    [InlineData("JBSWY3DP!HPK3PXP")]
    public void RejectsInvalidCharacters(string input)
    {
        var ex = Assert.Throws<FormatException>(() => Base32.Decode(input));
        Assert.DoesNotContain("JBSW", ex.Message);
    }

    [Theory(DisplayName = "不正な長さ・パディングを拒否する")]
    [InlineData("A")]
    [InlineData("ABC")]
    [InlineData("ABCDEF")]
    [InlineData("MY==A===")]
    [InlineData("   ")]
    public void RejectsInvalidLength(string input)
    {
        Assert.Throws<FormatException>(() => Base32.Decode(input));
    }
}
