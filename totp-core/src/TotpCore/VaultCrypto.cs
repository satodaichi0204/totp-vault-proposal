using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace TotpCore;

/// <summary>保存ファイルの種類。保管庫とバックアップは別のパスワードで守り、取り違えを検知する。</summary>
public enum VaultKind
{
    Vault,
    Backup,
}

/// <summary>Argon2id のコスト。既定は 64 MiB / 3 回 / 並列 4（OWASP の推奨最小値 19 MiB / 2 回より強い）。</summary>
public sealed record KdfParameters(int MemoryKiB, int Iterations, int Parallelism)
{
    public static KdfParameters Default { get; } = new(64 * 1024, 3, 4);

    internal void Validate()
    {
        // 上限は、細工したファイルで大量のメモリを確保させる攻撃を防ぐため
        if (MemoryKiB is < 8 or > 2 * 1024 * 1024)
            throw new CryptographicException("KDF のメモリ量が範囲外です。");
        if (Iterations is < 1 or > 100)
            throw new CryptographicException("KDF の反復回数が範囲外です。");
        if (Parallelism is < 1 or > 64 || MemoryKiB < 8 * Parallelism)
            throw new CryptographicException("KDF の並列数が範囲外です。");
    }
}

/// <summary>
/// 保管庫ファイルの暗号化（エンベロープ暗号化）。
///
///   マスターパスワード ─Argon2id─▶ KEK（鍵暗号化鍵）─AES-256-GCM─▶ DEK を包む
///   DEK（データ暗号化鍵, 乱数 256bit）─AES-256-GCM─▶ アカウント一覧
///
/// ファイル形式（すべてビッグエンディアン）:
///   [0]   magic 8B ("TOTPVLT1" / "TOTPBAK1")
///   [8]   vaultId 16B（乱数。データ部の AAD に使い、別ファイルとの差し替えを検知）
///   [24]  m(KiB) 4B, t 4B, p 4B, salt 16B
///   [52]  DEK 用 nonce 12B, 包んだ DEK 32B, tag 16B
///   [112] データ用 nonce 12B, tag 16B, 暗号文 nB
/// </summary>
public static class VaultCrypto
{
    public const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int SaltSize = 16;
    private const int VaultIdSize = 16;

    private const int MagicOffset = 0;
    private const int VaultIdOffset = 8;
    private const int KdfOffset = VaultIdOffset + VaultIdSize;       // 24
    private const int SaltOffset = KdfOffset + 12;                   // 36
    private const int DekNonceOffset = SaltOffset + SaltSize;        // 52
    private const int WrappedDekOffset = DekNonceOffset + NonceSize; // 64
    private const int DekTagOffset = WrappedDekOffset + KeySize;     // 96
    public const int HeaderSize = DekTagOffset + TagSize;            // 112
    private const int DataNonceOffset = HeaderSize;
    private const int DataTagOffset = DataNonceOffset + NonceSize;
    private const int DataOffset = DataTagOffset + TagSize;          // 140

    private static ReadOnlySpan<byte> VaultMagic => "TOTPVLT1"u8;
    private static ReadOnlySpan<byte> BackupMagic => "TOTPBAK1"u8;

    /// <summary>新しい保管庫（またはバックアップ）を作り、最初の内容を暗号化したファイルを返す。</summary>
    public static byte[] Create(ReadOnlySpan<char> password, ReadOnlySpan<byte> plaintext, VaultKind kind, KdfParameters? kdf = null)
    {
        using var session = VaultSession.CreateNew(password, kind, kdf ?? KdfParameters.Default);
        return session.Seal(plaintext);
    }

    /// <summary>復号して内容を返す。パスワード違いと改ざんは区別せず同じ例外にする（手がかりを与えない）。</summary>
    public static byte[] Open(ReadOnlySpan<char> password, ReadOnlySpan<byte> file, VaultKind kind)
    {
        using var session = VaultSession.Unlock(password, file, kind, out byte[] plaintext);
        return plaintext;
    }

    /// <summary>
    /// マスターパスワードを変更する。DEK を包み直すだけで、データ部は1バイトも変えない。
    /// （全データの再暗号化が不要。途中で電源が落ちても、データ部が壊れることはない）
    /// </summary>
    public static byte[] ChangePassword(ReadOnlySpan<char> oldPassword, ReadOnlySpan<char> newPassword, ReadOnlySpan<byte> file, VaultKind kind, KdfParameters? kdf = null)
    {
        byte[] dek = UnwrapDek(oldPassword, file, kind);
        try
        {
            byte[] result = file.ToArray();
            WriteKeyHeader(result, newPassword, dek, kdf ?? KdfParameters.Default);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    internal static byte[] UnwrapDek(ReadOnlySpan<char> password, ReadOnlySpan<byte> file, VaultKind kind)
    {
        if (file.Length < DataOffset || !file[..8].SequenceEqual(MagicFor(kind)))
        {
            // 種類違いは利用者の操作ミスなので、別のメッセージにしてよい
            if (file.Length >= 8 && file[..8].SequenceEqual(MagicFor(kind == VaultKind.Vault ? VaultKind.Backup : VaultKind.Vault)))
                throw new InvalidDataException(kind == VaultKind.Vault ? "これはバックアップファイルです。復元の画面から開いてください。" : "これはバックアップファイルではありません。");
            throw new InvalidDataException("保管庫ファイルの形式が正しくありません。");
        }

        var kdf = new KdfParameters(
            BinaryPrimitives.ReadInt32BigEndian(file[KdfOffset..]),
            BinaryPrimitives.ReadInt32BigEndian(file[(KdfOffset + 4)..]),
            BinaryPrimitives.ReadInt32BigEndian(file[(KdfOffset + 8)..]));
        kdf.Validate();

        byte[] kek = DeriveKek(password, file.Slice(SaltOffset, SaltSize), kdf);
        byte[] dek = GC.AllocateArray<byte>(KeySize, pinned: true);
        try
        {
            using var aes = new AesGcm(kek, TagSize);
            aes.Decrypt(
                file.Slice(DekNonceOffset, NonceSize),
                file.Slice(WrappedDekOffset, KeySize),
                file.Slice(DekTagOffset, TagSize),
                dek,
                file[..(SaltOffset + SaltSize)]);// magic・vaultId・KDF 条件・salt を改ざん検知の対象にする
            return dek;
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new CryptographicException("パスワードが違うか、ファイルが改ざんされています。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    internal static void WriteKeyHeader(byte[] header, ReadOnlySpan<char> password, ReadOnlySpan<byte> dek, KdfParameters kdf)
    {
        kdf.Validate();
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(KdfOffset), kdf.MemoryKiB);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(KdfOffset + 4), kdf.Iterations);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(KdfOffset + 8), kdf.Parallelism);
        RandomNumberGenerator.Fill(header.AsSpan(SaltOffset, SaltSize));
        RandomNumberGenerator.Fill(header.AsSpan(DekNonceOffset, NonceSize));

        byte[] kek = DeriveKek(password, header.AsSpan(SaltOffset, SaltSize), kdf);
        try
        {
            using var aes = new AesGcm(kek, TagSize);
            aes.Encrypt(
                header.AsSpan(DekNonceOffset, NonceSize),
                dek,
                header.AsSpan(WrappedDekOffset, KeySize),
                header.AsSpan(DekTagOffset, TagSize),
                header.AsSpan(0, SaltOffset + SaltSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    internal static byte[] NewHeader(VaultKind kind)
    {
        byte[] header = new byte[HeaderSize];
        MagicFor(kind).CopyTo(header.AsSpan(MagicOffset));
        RandomNumberGenerator.Fill(header.AsSpan(VaultIdOffset, VaultIdSize));
        return header;
    }

    internal static byte[] SealData(ReadOnlySpan<byte> header, ReadOnlySpan<byte> dek, ReadOnlySpan<byte> plaintext)
    {
        byte[] file = new byte[DataOffset + plaintext.Length];
        header[..HeaderSize].CopyTo(file);
        Span<byte> nonce = file.AsSpan(DataNonceOffset, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(dek, TagSize);
        aes.Encrypt(nonce, plaintext, file.AsSpan(DataOffset), file.AsSpan(DataTagOffset, TagSize), DataAad(header));
        return file;
    }

    internal static byte[] OpenData(ReadOnlySpan<byte> file, ReadOnlySpan<byte> dek)
    {
        byte[] plaintext = new byte[file.Length - DataOffset];
        try
        {
            using var aes = new AesGcm(dek, TagSize);
            aes.Decrypt(file.Slice(DataNonceOffset, NonceSize), file[DataOffset..], file.Slice(DataTagOffset, TagSize), plaintext, DataAad(file));
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("パスワードが違うか、ファイルが改ざんされています。");
        }
    }

    /// <summary>データ部の AAD は magic と vaultId のみ。DEK の包み直し（パスワード変更）でデータ部を変えずに済む。</summary>
    private static ReadOnlySpan<byte> DataAad(ReadOnlySpan<byte> header) => header[..(VaultIdOffset + VaultIdSize)];

    private static ReadOnlySpan<byte> MagicFor(VaultKind kind) => kind == VaultKind.Vault ? VaultMagic : BackupMagic;

    private static byte[] DeriveKek(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, KdfParameters kdf)
    {
        if (password.IsEmpty)
            throw new ArgumentException("パスワードが空です。", nameof(password));

        byte[] passwordBytes = GC.AllocateArray<byte>(Encoding.UTF8.GetByteCount(password), pinned: true);
        try
        {
            Encoding.UTF8.GetBytes(password, passwordBytes);
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt.ToArray(),
                MemorySize = kdf.MemoryKiB,
                Iterations = kdf.Iterations,
                DegreeOfParallelism = kdf.Parallelism,
            };
            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}

/// <summary>
/// ロック解除中の保管庫。DEK をメモリ上で固定（pinned）して保持し、Dispose（＝ロック）で 0 埋めする。
/// GC によるコピーが残らないよう、pinned 配列を使う。
/// </summary>
public sealed class VaultSession : IDisposable
{
    private readonly byte[] _header;
    private readonly byte[] _dek;
    private bool _disposed;

    private VaultSession(byte[] header, byte[] dek)
    {
        _header = header;
        _dek = dek;
    }

    public bool IsLocked => _disposed;

    public static VaultSession CreateNew(ReadOnlySpan<char> password, VaultKind kind, KdfParameters kdf)
    {
        byte[] header = VaultCrypto.NewHeader(kind);
        byte[] dek = GC.AllocateArray<byte>(VaultCrypto.KeySize, pinned: true);
        RandomNumberGenerator.Fill(dek);
        VaultCrypto.WriteKeyHeader(header, password, dek, kdf);
        return new VaultSession(header, dek);
    }

    public static VaultSession Unlock(ReadOnlySpan<char> password, ReadOnlySpan<byte> file, VaultKind kind, out byte[] plaintext)
    {
        byte[] dek = VaultCrypto.UnwrapDek(password, file, kind);
        try
        {
            plaintext = VaultCrypto.OpenData(file, dek);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(dek);
            throw;
        }
        return new VaultSession(file[..VaultCrypto.HeaderSize].ToArray(), dek);
    }

    /// <summary>内容を暗号化してファイルの中身を返す。保存のたびに新しい nonce を使う。</summary>
    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return VaultCrypto.SealData(_header, _dek, plaintext);
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_dek);
        _disposed = true;
    }
}
