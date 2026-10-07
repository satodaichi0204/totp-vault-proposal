namespace TotpCore;

/// <summary>
/// 保存中に電源が落ちても、保管庫ファイルが「書きかけ」にならないように書き込む。
/// 同じフォルダーの一時ファイルに書き、ディスクへの書き込み完了を待ってから置き換える。
/// 置き換え前のファイルは .bak として1世代残す（暗号化されたまま）。
/// </summary>
public static class AtomicFile
{
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> data)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
                           ?? throw new ArgumentException("保存先のフォルダーが不正です。", nameof(path));
        string tempPath = Path.Combine(directory, $"{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");

        try
        {
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(fullPath))
                File.Replace(tempPath, fullPath, fullPath + ".bak", ignoreMetadataErrors: true);
            else
                File.Move(tempPath, fullPath);
        }
        catch
        {
            File.Delete(tempPath);
            throw;
        }
    }
}
