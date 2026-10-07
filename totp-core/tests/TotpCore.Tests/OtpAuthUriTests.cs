namespace TotpCore.Tests;

public class OtpAuthUriTests
{
    [Fact(DisplayName = "QR コードの URI：既定値（SHA-1 / 6桁 / 30秒）")]
    public void ParsesMinimalUri()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        Assert.Equal("Example", e.Issuer);
        Assert.Equal("alice@example.com", e.AccountName);
        Assert.Equal(TotpParameters.Default, e.Parameters);
        Assert.Equal(Base32.Decode("JBSWY3DPEHPK3PXP"), e.Secret);
        Assert.False(e.IssuerMismatch);
    }

    [Fact(DisplayName = "QR コードの URI：SHA-512 / 8桁 / 60秒")]
    public void ParsesAllParameters()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60");
        Assert.Equal("ACME Co", e.Issuer);
        Assert.Equal("john.doe@email.com", e.AccountName);
        Assert.Equal(new TotpParameters(OtpAlgorithm.Sha512, 8, 60), e.Parameters);
    }

    [Fact(DisplayName = "区切りの ':' が %3A、空白が '+' で書かれた URI")]
    public void ParsesEncodedSeparators()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/My%20Bank%3Ataro?secret=JBSWY3DPEHPK3PXP&issuer=My+Bank&algorithm=sha256");
        Assert.Equal("My Bank", e.Issuer);
        Assert.Equal("taro", e.AccountName);
        Assert.Equal(OtpAlgorithm.Sha256, e.Parameters.Algorithm);
    }

    [Fact(DisplayName = "ラベルに発行元がない場合は issuer パラメーターを使う")]
    public void UsesIssuerParameterWhenLabelHasNone()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=Service");
        Assert.Equal("Service", e.Issuer);
        Assert.Equal("alice", e.AccountName);
    }

    [Fact(DisplayName = "ラベルと issuer が食い違う場合は登録前に確認できるよう印を付ける")]
    public void FlagsIssuerMismatch()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/RealBank:alice?secret=JBSWY3DPEHPK3PXP&issuer=OtherBank");
        Assert.True(e.IssuerMismatch);
        Assert.Equal("OtherBank", e.Issuer);
    }

    [Fact(DisplayName = "大文字小文字の違いだけなら食い違いとして警告しない")]
    public void IgnoresCaseOnlyIssuerDifference()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        Assert.False(e.IssuerMismatch);
        Assert.Equal("Example", e.Issuer);
    }

    [Fact(DisplayName = "Dispose で秘密鍵を 0 埋めする")]
    public void DisposeZeroesSecret()
    {
        var e = OtpAuthUri.Parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP");
        byte[] secret = e.Secret;
        e.Dispose();
        Assert.All(secret, b => Assert.Equal(0, b));
    }

    [Fact(DisplayName = "ToString に秘密鍵を含めない（ログ出力対策）")]
    public void ToStringDoesNotLeakSecret()
    {
        using var e = OtpAuthUri.Parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP");
        Assert.DoesNotContain("JBSWY3DP", e.ToString());
    }

    [Theory(DisplayName = "不正な URI は拒否する")]
    [InlineData("https://example.com/?secret=JBSWY3DPEHPK3PXP")]
    [InlineData("otpauth://totp/Example:alice?issuer=Example")]                       // secret なし
    [InlineData("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")] // 未対応
    [InlineData("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=abc")]
    [InlineData("otpauth://xotp/Example:alice?secret=JBSWY3DPEHPK3PXP")]
    public void RejectsMalformedUri(string uri)
    {
        Assert.Throws<FormatException>(() => OtpAuthUri.Parse(uri));
    }

    [Theory(DisplayName = "範囲外の桁数・周期は拒否する")]
    [InlineData("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=10")]
    [InlineData("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0")]
    public void RejectsOutOfRangeParameters(string uri)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => OtpAuthUri.Parse(uri));
    }

    [Theory(DisplayName = "HOTP と Google Authenticator のエクスポート形式は、理由を示して対象外にする")]
    [InlineData("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=0")]
    [InlineData("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8")]
    public void RejectsUnsupportedTypesWithReason(string uri)
    {
        Assert.Throws<NotSupportedException>(() => OtpAuthUri.Parse(uri));
    }
}
