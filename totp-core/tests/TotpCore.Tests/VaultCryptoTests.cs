using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Xunit.Abstractions;

namespace TotpCore.Tests;

public class VaultCryptoTests(ITestOutputHelper output)
{
    // テストを速くするため KDF のコストを下げている（本番の既定値は KdfParameters.Default）
    private static readonly KdfParameters Fast = new(1024, 1, 1);
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("""[{"issuer":"Example","account":"alice","secret":"JBSWY3DPEHPK3PXP"}]""");

    [Fact(DisplayName = "Argon2id の実装が RFC 9106 5.3 のテストベクターと一致する")]
    public void Argon2idMatchesRfc9106()
    {
        using var argon2 = new Argon2id(Enumerable.Repeat((byte)0x01, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)0x02, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)0x03, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray(),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };
        Assert.Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", Convert.ToHexStringLower(argon2.GetBytes(32)));
    }

    [Fact(DisplayName = "正しいマスターパスワードで復号できる")]
    public void RoundTrip()
    {
        byte[] file = VaultCrypto.Create("correct horse battery staple", Payload, VaultKind.Vault, Fast);
        Assert.Equal(Payload, VaultCrypto.Open("correct horse battery staple", file, VaultKind.Vault));
    }

    [Fact(DisplayName = "保存ファイルに秘密鍵やアカウント名が平文で含まれない")]
    public void FileContainsNoPlaintext()
    {
        byte[] file = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        string asLatin1 = Encoding.Latin1.GetString(file);
        Assert.DoesNotContain("JBSWY3DP", asLatin1);
        Assert.DoesNotContain("alice", asLatin1);
    }

    [Fact(DisplayName = "同じ内容を2回保存しても、暗号文は毎回変わる（nonce・salt の再利用なし）")]
    public void EncryptionIsRandomized()
    {
        byte[] a = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        byte[] b = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        Assert.NotEqual(a, b);

        using var session = VaultSession.Unlock("pw", a, VaultKind.Vault, out _);
        Assert.NotEqual(session.Seal(Payload)[VaultCrypto.HeaderSize..], session.Seal(Payload)[VaultCrypto.HeaderSize..]);
    }

    [Fact(DisplayName = "パスワードが違うと復号できない")]
    public void WrongPasswordFails()
    {
        byte[] file = VaultCrypto.Create("right", Payload, VaultKind.Vault, Fast);
        Assert.Throws<CryptographicException>(() => VaultCrypto.Open("wrong", file, VaultKind.Vault));
    }

    [Theory(DisplayName = "ファイルのどこを1ビット書き換えても検知する")]
    [InlineData(10)]   // vaultId
    [InlineData(30)]   // KDF の条件
    [InlineData(40)]   // salt
    [InlineData(70)]   // 包んだ DEK
    [InlineData(100)]  // DEK のタグ
    [InlineData(115)]  // データの nonce
    [InlineData(130)]  // データのタグ
    [InlineData(-1)]   // 暗号文の末尾
    public void DetectsTampering(int position)
    {
        byte[] file = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        int index = position < 0 ? file.Length + position : position;
        file[index] ^= 0x01;
        Assert.ThrowsAny<Exception>(() => VaultCrypto.Open("pw", file, VaultKind.Vault));
    }

    [Fact(DisplayName = "別の保管庫のデータ部への差し替えを検知する")]
    public void DetectsSwappedDataSection()
    {
        byte[] a = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        byte[] b = VaultCrypto.Create("pw", "other"u8, VaultKind.Vault, Fast);
        byte[] spliced = [.. a[..VaultCrypto.HeaderSize], .. b[VaultCrypto.HeaderSize..]];
        Assert.Throws<CryptographicException>(() => VaultCrypto.Open("pw", spliced, VaultKind.Vault));
    }

    [Fact(DisplayName = "マスターパスワード変更：データ部は変えずに鍵だけ包み直す")]
    public void ChangePasswordRewrapsKeyOnly()
    {
        byte[] before = VaultCrypto.Create("old", Payload, VaultKind.Vault, Fast);
        byte[] after = VaultCrypto.ChangePassword("old", "new", before, VaultKind.Vault, Fast);

        Assert.Equal(before[VaultCrypto.HeaderSize..], after[VaultCrypto.HeaderSize..]);
        Assert.Equal(Payload, VaultCrypto.Open("new", after, VaultKind.Vault));
        Assert.Throws<CryptographicException>(() => VaultCrypto.Open("old", after, VaultKind.Vault));
    }

    [Fact(DisplayName = "バックアップは保管庫と別のパスワードで守られ、取り違えを検知する")]
    public void BackupIsSeparate()
    {
        byte[] backup = VaultCrypto.Create("backup-pass", Payload, VaultKind.Backup, Fast);
        Assert.Equal(Payload, VaultCrypto.Open("backup-pass", backup, VaultKind.Backup));
        Assert.Throws<CryptographicException>(() => VaultCrypto.Open("vault-pass", backup, VaultKind.Backup));
        Assert.Throws<InvalidDataException>(() => VaultCrypto.Open("backup-pass", backup, VaultKind.Vault));
    }

    [Fact(DisplayName = "ロック（Dispose）後は保存できない")]
    public void LockedSessionCannotSeal()
    {
        var session = VaultSession.CreateNew("pw", VaultKind.Vault, Fast);
        session.Dispose();
        Assert.True(session.IsLocked);
        Assert.Throws<ObjectDisposedException>(() => session.Seal(Payload));
    }

    [Fact(DisplayName = "細工したファイルで過大なメモリを要求されても処理しない")]
    public void RejectsHostileKdfParameters()
    {
        byte[] file = VaultCrypto.Create("pw", Payload, VaultKind.Vault, Fast);
        file[24] = 0x7F; // メモリ量を約 2 TiB に書き換える
        Assert.Throws<CryptographicException>(() => VaultCrypto.Open("pw", file, VaultKind.Vault));
    }

    [Fact(DisplayName = "本番の既定値（64 MiB / 3回 / 並列4）での鍵導出時間")]
    public void DefaultKdfCost()
    {
        var sw = Stopwatch.StartNew();
        byte[] file = VaultCrypto.Create("pw", Payload, VaultKind.Vault);
        long createMs = sw.ElapsedMilliseconds;
        sw.Restart();
        Assert.Equal(Payload, VaultCrypto.Open("pw", file, VaultKind.Vault));
        // 利用者が待てる範囲（目安 2 秒以内）。実測値はテスト結果に記録する
        Assert.True(sw.ElapsedMilliseconds < 5000, $"ロック解除に {sw.ElapsedMilliseconds} ms かかりました");
        output.WriteLine($"KDF 既定値: 作成 {createMs} ms / ロック解除 {sw.ElapsedMilliseconds} ms");
    }
}

public class AtomicFileTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("totp-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact(DisplayName = "上書き保存：新しい内容になり、1世代前が .bak に残り、一時ファイルが残らない")]
    public void ReplacesAndKeepsBackup()
    {
        string path = Path.Combine(_dir, "vault.dat");
        AtomicFile.WriteAllBytes(path, [1, 2, 3]);
        AtomicFile.WriteAllBytes(path, [4, 5, 6]);

        Assert.Equal([4, 5, 6], File.ReadAllBytes(path));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(path + ".bak"));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }
}
