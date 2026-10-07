// dotnet test の結果（TRX）から site/tests.html を作る。
// 使い方: node tools/make-test-report.mjs totp-core/TestResults/results.trx "<実行環境の説明>"
import { readFileSync, writeFileSync } from 'node:fs';

const [trxPath, envNote = ''] = process.argv.slice(2);
if (!trxPath) {
  console.error('usage: node tools/make-test-report.mjs <results.trx> [environment]');
  process.exit(1);
}
const trx = readFileSync(trxPath, 'utf8');

const unescapeXml = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const attr = (tag, name) => (tag.match(new RegExp(`${name}="([^"]*)"`)) || [])[1];

// testId -> クラス名
const classOf = new Map();
for (const m of trx.matchAll(/<UnitTest name="[^"]*"[^>]*id="([^"]+)">[\s\S]*?<TestMethod [^>]*className="([^"]+)"/g)) {
  classOf.set(m[1], m[2].replace(/^.*\./, ''));
}

const results = [];
for (const m of trx.matchAll(/<UnitTestResult ([^>]*?)(\/>|>([\s\S]*?)<\/UnitTestResult>)/g)) {
  const head = m[1];
  const body = m[3] || '';
  const stdout = (body.match(/<StdOut>([\s\S]*?)<\/StdOut>/) || [])[1];
  results.push({
    name: unescapeXml(attr(head, 'testName')),
    outcome: attr(head, 'outcome'),
    duration: attr(head, 'duration'),
    cls: classOf.get(attr(head, 'testId')) || '',
    stdout: stdout ? unescapeXml(stdout).trim() : '',
  });
}

const counters = trx.match(/<Counters [^>]*>/)[0];
const total = +attr(counters, 'total');
const passed = +attr(counters, 'passed');
const failed = +attr(counters, 'failed');
const start = attr(trx.match(/<Times [^>]*>/)[0], 'start');
const runDate = new Date(start);
const runDateText = `${runDate.getFullYear()}年${runDate.getMonth() + 1}月${runDate.getDate()}日`;

const GROUPS = [
  ['RfcVectorTests', 'RFC の正解値との照合', 'RFC 6238 付録B（SHA-1/256/512・8桁、6つの時刻）、RFC 4226 付録D（HOTP）、RFC 4648（Base32）'],
  ['TotpBehaviorTests', 'TOTP の動作', '6桁・8桁の関係、60秒周期、残り秒数、範囲外の値の拒否'],
  ['Base32InputTests', 'シークレットキーの入力', '手入力の揺れの許容、使えない文字の拒否、エラーに秘密鍵を含めないこと'],
  ['OtpAuthUriTests', 'QR コードの中身（otpauth URI）の解析', '各パラメーター、符号化の揺れ、サービス名の食い違い、不正・対象外の URI'],
  ['VaultCryptoTests', '暗号化保存', 'Argon2id（RFC 9106）、暗号化と復号、改ざん検知、パスワード変更、バックアップの取り違え'],
  ['AtomicFileTests', '壊れにくい保存', '一時ファイルからの置き換え、1世代前の保持'],
];

const seconds = (d) => {
  const [h, mi, s] = d.split(':');
  return (+h) * 3600 + (+mi) * 60 + parseFloat(s);
};
const ms = (d) => {
  const v = seconds(d) * 1000;
  return v < 1 ? '1 ms 未満' : `${Math.round(v).toLocaleString('ja-JP')} ms`;
};

// 理論値の名前（"名前(引数)"）を、名前と引数に分ける
const split = (name) => {
  const i = name.indexOf('(');
  return i < 0 ? [name, ''] : [name.slice(0, i), name.slice(i + 1, -1)];
};

const naturalCmp = new Intl.Collator('ja', { numeric: true }).compare;

let sections = '';
for (const [cls, title, desc] of GROUPS) {
  const items = results.filter((r) => r.cls === cls).sort((a, b) => naturalCmp(a.name, b.name));
  if (!items.length) continue;
  const ok = items.filter((r) => r.outcome === 'Passed').length;
  const rows = items.map((r) => {
    const [n, args] = split(r.name);
    const pass = r.outcome === 'Passed';
    const note = r.stdout ? `<div class="out">${esc(r.stdout)}</div>` : '';
    return `<tr><td>${esc(n)}${args ? `<div class="args">${esc(args)}</div>` : ''}${note}</td><td class="${pass ? 'pass' : 'fail'}">${pass ? '合格' : esc(r.outcome)}</td><td class="num">${ms(r.duration)}</td></tr>`;
  }).join('\n');
  sections += `
  <h2>${esc(title)} <span class="count">${ok} / ${items.length}</span></h2>
  <p class="desc">${esc(desc)}（<code>${esc(cls)}.cs</code>）</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>テスト</th><th>結果</th><th>時間</th></tr></thead>
      <tbody>
${rows}
      </tbody>
    </table>
  </div>`;
}

const kdf = results.find((r) => r.stdout.startsWith('KDF'));

const html = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TOTP Vault テスト結果</title>
<meta name="description" content="C# (.NET 10) の TOTP・暗号化の中核部分の自動テスト結果。">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<link rel="icon" href="assets/icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/doc.css">
<link rel="stylesheet" href="assets/tests.css">
</head>
<body>

<header class="site-header">
  <div class="site-header-inner">
    <a class="brand" href="./">
      <img class="brand-mark" src="assets/icon.svg" alt="">
      <span class="brand-name">TOTP Vault<span class="brand-sub">Windows 向け 2段階認証アプリ ご提案資料</span></span>
    </a>
    <nav class="site-nav" aria-label="資料">
      <a href="./">操作デモ</a>
      <a href="security.html">セキュリティ設計</a>
      <a href="tests.html" aria-current="page">テスト結果</a>
    </nav>
  </div>
</header>

<main class="page doc">
  <button type="button" class="btn print-btn" id="print">印刷・PDF で保存</button>
  <h1>テスト結果（C# / .NET 10）</h1>
  <p class="meta">実行日：${runDateText} ／ 対象：試作した中核部分（TOTP の計算、QR コードの中身の解析、暗号化保存）</p>

  <div class="stat-row">
    <div class="stat ${failed === 0 ? 'good' : ''}"><b>${passed} / ${total}</b><span>合格</span></div>
    <div class="stat"><b>${failed}</b><span>不合格</span></div>
    <div class="stat"><b>28 / 28</b><span>RFC の TOTP・HOTP 正解値と一致</span></div>
    ${kdf ? `<div class="stat"><b>${esc(kdf.stdout.match(/ロック解除 (\d+) ms/)?.[1] ?? '-')} ms</b><span>ロック解除の時間（Argon2id 既定値）</span></div>` : ''}
  </div>

  <div class="note">
    <p>本番のアプリで使う、<strong>画面に依存しない中核部分</strong>を先に試作し、自動テストを行いました。ソースコードは<a href="https://github.com/satodaichi0204/totp-vault-proposal">GitHub</a>で公開しています。次のコマンドで、どなたでも同じテストを実行できます。</p>
    <pre><code>cd totp-core
dotnet test</code></pre>
  </div>

  <h2>実行環境</h2>
  <dl class="kv">
    <dt>OS</dt><dd>${esc(envNote || 'Windows')}</dd>
    <dt>.NET</dt><dd>.NET SDK 10.0.401 / ランタイム 10.0.12（Release ビルド）</dd>
    <dt>テスト</dt><dd>xUnit 2.9.3</dd>
    <dt>外部ライブラリ</dt><dd>Konscious.Security.Cryptography.Argon2 1.3.1（Argon2id のみ。それ以外は .NET 標準）</dd>
  </dl>
${sections}

  <h2>このテストに含まれないもの</h2>
  <ul>
    <li>画面（WPF）の操作、Windows Hello、クリップボード、画面キャプチャの除外、ロックの検知：本番の開発で、実機の確認項目として行います（<a href="security.html#tests">設計書 15章</a>）。</li>
    <li>ブラウザ版の計算は、<a href="./">操作デモ</a>の「RFC テスト」タブで、お使いのブラウザ上で確かめられます。</li>
  </ul>
</main>

<footer class="site-footer">
  このページは dotnet test の結果ファイル（TRX）から自動で作成しています（tools/make-test-report.mjs）。
</footer>
<script src="assets/print.js"></script>
</body>
</html>
`;

writeFileSync(new URL('../site/tests.html', import.meta.url), html);
console.log(`site/tests.html: ${passed}/${total} passed`);
