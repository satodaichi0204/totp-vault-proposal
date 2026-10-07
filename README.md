# TOTP Vault — Windows 向け 2段階認証アプリ ご提案資料

Windows 10 / 11 向けの TOTP（ワンタイムパスワード）管理アプリの提案用資料です。本番アプリは .NET 10 + WPF で開発する想定で、このリポジトリには、その中核部分の試作と提案資料が入っています。

**公開ページ：https://totp-vault-proposal.vercel.app/**

| 内容 | 場所 |
|---|---|
| 操作デモ（ブラウザで動作。外部と通信せず、何も保存しない） | [`site/index.html`](site/index.html) |
| 技術構成とセキュリティ設計 | [`site/security.html`](site/security.html) |
| テスト結果（91 件合格） | [`site/tests.html`](site/tests.html) |
| C# の中核部分（TOTP・Base32・otpauth URI・暗号化保存） | [`totp-core/src/TotpCore`](totp-core/src/TotpCore) |
| 自動テスト（RFC 6238 / 4226 / 4648 / 9106 の正解値を含む） | [`totp-core/tests/TotpCore.Tests`](totp-core/tests/TotpCore.Tests) |

## テストの実行

.NET 10 SDK が必要です。

```
cd totp-core
dotnet test
```

結果のページを作り直す場合：

```
dotnet test -c Release --logger "trx;LogFileName=results.trx" --results-directory TestResults
node ../tools/make-test-report.mjs TestResults/results.trx "<実行環境>"
```

## 中核部分の構成

- `Otp.cs` — HOTP（RFC 4226）と TOTP（RFC 6238）。SHA-1/256/512、6〜8桁、任意の周期。時刻は 64bit。
- `Base32.cs` — 秘密鍵の復号。手入力の揺れを許容し、エラーに入力値を含めない。
- `OtpAuthUri.cs` — QR コードの中身（`otpauth://totp/...`）の解析。サービス名の食い違いを検出。
- `VaultCrypto.cs` — マスターパスワード → Argon2id → KEK → AES-256-GCM で DEK を包み、DEK でデータを暗号化する。パスワード変更は DEK の包み直しのみ。
- `AtomicFile.cs` — 一時ファイルに書いてから置き換える保存（電源断でも壊れない）。

## 操作デモについて

- `site/` をそのまま静的ホスティングで公開できます（`site/vercel.json` に CSP などのヘッダーを設定）。
- CSP（`connect-src 'none'`）で外部への通信を禁止しています。
- 表示している秘密鍵・アカウントはすべて架空のテスト用の値です。

## 同梱ライブラリ

- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 — MIT（QR コードの表示）
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0 — Apache-2.0（QR コードの読み取り）
- [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) 1.3.1 — MIT（C# の Argon2id）
