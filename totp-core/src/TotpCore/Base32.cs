namespace TotpCore;

/// <summary>
/// Base32（RFC 4648 6章）の復号。TOTP の秘密鍵の表記に使われる。
/// 手入力を想定し、大文字小文字の違い、空白、ハイフン、末尾の '=' を許容する。
/// </summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// 復号する。戻り値の配列は秘密鍵そのものなので、呼び出し側が使い終わったら
    /// CryptographicOperations.ZeroMemory で消すこと。
    /// </summary>
    public static byte[] Decode(ReadOnlySpan<char> input)
    {
        // 1文字 = 5bit。区切り文字を除いた文字数から出力の長さを決める
        int symbolCount = 0;
        bool paddingStarted = false;
        foreach (char c in input)
        {
            if (IsSeparator(c))
                continue;
            if (c == '=')
            {
                paddingStarted = true;
                continue;
            }
            if (paddingStarted)
                throw new FormatException("'=' の後に文字があります。");
            if (ValueOf(c) < 0)
                throw new FormatException($"Base32 で使えない文字が含まれています（{DescribeChar(c)}）。");
            symbolCount++;
        }

        if (symbolCount == 0)
            throw new FormatException("秘密鍵が空です。");

        // 5bit 単位で余った端数（8bit に満たない部分）は捨てる。
        // 1〜2文字目のように 1 バイトに満たない長さは不正。
        int remainder = symbolCount % 8;
        if (remainder is 1 or 3 or 6)
            throw new FormatException("Base32 の文字数が不正です。");

        byte[] output = new byte[symbolCount * 5 / 8];
        int buffer = 0;
        int bitsInBuffer = 0;
        int index = 0;
        foreach (char c in input)
        {
            if (IsSeparator(c) || c == '=')
                continue;
            buffer = (buffer << 5) | ValueOf(c);
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                output[index++] = (byte)(buffer >> bitsInBuffer);
                buffer &= (1 << bitsInBuffer) - 1;
            }
        }
        return output;
    }

    public static string Encode(ReadOnlySpan<byte> data, bool padding = true)
    {
        var chars = new System.Text.StringBuilder((data.Length + 4) / 5 * 8);
        int buffer = 0;
        int bitsInBuffer = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5)
            {
                bitsInBuffer -= 5;
                chars.Append(Alphabet[(buffer >> bitsInBuffer) & 0x1F]);
            }
            buffer &= (1 << bitsInBuffer) - 1;
        }
        if (bitsInBuffer > 0)
            chars.Append(Alphabet[(buffer << (5 - bitsInBuffer)) & 0x1F]);
        if (padding)
            while (chars.Length % 8 != 0)
                chars.Append('=');
        return chars.ToString();
    }

    private static bool IsSeparator(char c) => c is ' ' or '-' or '\t' or '　';

    private static int ValueOf(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a',
        >= '2' and <= '7' => c - '2' + 26,
        _ => -1,
    };

    // 例外メッセージに秘密鍵の文字そのものを出さない（ログへの機密情報出力防止）
    private static string DescribeChar(char c) => c switch
    {
        '0' or '1' or '8' or '9' => "数字の 0・1・8・9 は使えません",
        >= '！' and <= '～' => "全角文字が含まれています",
        _ => "記号または対象外の文字",
    };
}
