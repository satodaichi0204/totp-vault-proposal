/*
 * TOTP（RFC 6238）/ HOTP（RFC 4226）/ Base32（RFC 4648）/ otpauth URI の解析。
 * C# 版（totp-core/src/TotpCore）と同じ規則で実装している。
 * HMAC はブラウザ標準の Web Crypto API を使い、秘密鍵は「取り出し不可」の CryptoKey として保持する。
 */
(function () {
  'use strict';

  var ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var HASH = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
  var LABEL = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

  function isSeparator(c) { return c === ' ' || c === '-' || c === '\t' || c === '　'; }

  function valueOf(c) {
    var code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) return code - 65;        // A-Z
    if (code >= 97 && code <= 122) return code - 97;       // a-z
    if (code >= 50 && code <= 55) return code - 50 + 26;   // 2-7
    return -1;
  }

  // エラーに秘密鍵の文字そのものを含めない
  function describeChar(c) {
    if ('0189'.indexOf(c) >= 0) return '数字の 0・1・8・9 は使えません';
    var code = c.charCodeAt(0);
    if (code >= 0xFF01 && code <= 0xFF5E) return '全角文字が含まれています';
    return '記号または対象外の文字';
  }

  function base32Decode(input) {
    var count = 0, padding = false, i, c;
    for (i = 0; i < input.length; i++) {
      c = input[i];
      if (isSeparator(c)) continue;
      if (c === '=') { padding = true; continue; }
      if (padding) throw new Error("'=' の後に文字があります。");
      if (valueOf(c) < 0) throw new Error('Base32 で使えない文字が含まれています（' + describeChar(c) + '）。');
      count++;
    }
    if (count === 0) throw new Error('秘密鍵が空です。');
    var rem = count % 8;
    if (rem === 1 || rem === 3 || rem === 6) throw new Error('Base32 の文字数が不正です。');

    var out = new Uint8Array(Math.floor(count * 5 / 8));
    var buffer = 0, bits = 0, index = 0;
    for (i = 0; i < input.length; i++) {
      c = input[i];
      if (isSeparator(c) || c === '=') continue;
      buffer = (buffer << 5) | valueOf(c);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out[index++] = (buffer >> bits) & 0xFF;
        buffer &= (1 << bits) - 1;
      }
    }
    return out;
  }

  function base32Encode(bytes, padding) {
    var out = '', buffer = 0, bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      buffer = (buffer << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        out += ALPHABET[(buffer >> bits) & 31];
      }
      buffer &= (1 << bits) - 1;
    }
    if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
    if (padding !== false) while (out.length % 8 !== 0) out += '=';
    return out;
  }

  function validate(p) {
    if (!HASH[p.algorithm]) throw new Error('未対応のアルゴリズムです（SHA1 / SHA256 / SHA512 のみ）。');
    if (!(p.digits >= 6 && p.digits <= 8)) throw new Error('桁数は 6〜8 で指定してください。');
    if (!(p.period >= 1 && p.period <= 3600)) throw new Error('有効期間は 1〜3600 秒で指定してください。');
  }

  /** 秘密鍵を取り出し不可の CryptoKey にし、元のバイト列は 0 で埋める。 */
  function importSecret(bytes, algorithm) {
    if (!bytes.length) return Promise.reject(new Error('秘密鍵が空です。'));
    return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: HASH[algorithm] }, false, ['sign'])
      .then(function (key) { bytes.fill(0); return key; });
  }

  function hotp(key, counter, digits) {
    var msg = new ArrayBuffer(8);
    var view = new DataView(msg);
    // 2^53 未満のカウンターを 64bit ビッグエンディアンで書く
    view.setUint32(0, Math.floor(counter / 4294967296));
    view.setUint32(4, counter >>> 0);
    return crypto.subtle.sign('HMAC', key, msg).then(function (sig) {
      var mac = new Uint8Array(sig);
      var off = mac[mac.length - 1] & 0x0F;
      var bin = ((mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
      var code = String(bin % Math.pow(10, digits));
      while (code.length < digits) code = '0' + code;
      mac.fill(0);
      return code;
    });
  }

  function timeStep(unixMs, period) { return Math.floor(unixMs / 1000 / period); }
  function secondsRemaining(unixMs, period) { return period - (Math.floor(unixMs / 1000) % period); }

  function decodeComponent(s) {
    try { return decodeURIComponent(s); } catch (e) { throw new Error('URI の文字の符号化が不正です。'); }
  }

  /** otpauth://totp/ の URI を解析する。戻り値の secret はバイト列（呼び出し側で消す）。 */
  function parseOtpAuth(uri) {
    uri = String(uri || '').trim();
    if (/^otpauth-migration:\/\//i.test(uri))
      throw new Error('Google Authenticator のエクスポート形式です。本番アプリでは一括取り込みに対応する予定です（このデモでは未対応）。');
    if (!/^otpauth:\/\//i.test(uri)) throw new Error('otpauth:// で始まる URI ではありません。');

    var rest = uri.slice('otpauth://'.length);
    var slash = rest.indexOf('/');
    if (slash < 0) throw new Error('種類（totp）の後にラベルがありません。');
    var type = rest.slice(0, slash).toLowerCase();
    if (type === 'hotp') throw new Error('HOTP（カウンター方式）は対象外です。TOTP の QR コードを使ってください。');
    if (type !== 'totp') throw new Error('未対応の種類です。');

    rest = rest.slice(slash + 1);
    var q = rest.indexOf('?');
    var label = decodeComponent(q < 0 ? rest : rest.slice(0, q));
    var query = q < 0 ? '' : rest.slice(q + 1);

    var labelIssuer = '', account = label, colon = label.indexOf(':');
    if (colon >= 0) { labelIssuer = label.slice(0, colon).trim(); account = label.slice(colon + 1).trim(); }

    var secretText = null, issuerParam = null;
    var p = { algorithm: 'SHA1', digits: 6, period: 30 };
    query.split('&').forEach(function (pair) {
      if (!pair) return;
      var eq = pair.indexOf('=');
      var key = (eq < 0 ? pair : pair.slice(0, eq)).toLowerCase();
      var value = eq < 0 ? '' : decodeComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
      if (key === 'secret') secretText = value;
      else if (key === 'issuer') issuerParam = value.trim();
      else if (key === 'algorithm') {
        var a = value.toUpperCase().replace('-', '');
        if (!HASH[a]) throw new Error('未対応のアルゴリズムです（SHA1 / SHA256 / SHA512 のみ）。');
        p.algorithm = a;
      }
      else if (key === 'digits' || key === 'period') {
        if (!/^\d+$/.test(value)) throw new Error(key + ' が数値ではありません。');
        p[key] = parseInt(value, 10);
      }
    });

    if (!secretText) throw new Error('secret パラメーターがありません。');
    validate(p);

    // 大文字小文字の違いだけなら警告しない
    var mismatch = !!issuerParam && !!labelIssuer && issuerParam.toLowerCase() !== labelIssuer.toLowerCase();
    return {
      issuer: issuerParam || labelIssuer,
      account: account,
      secret: base32Decode(secretText),
      algorithm: p.algorithm,
      digits: p.digits,
      period: p.period,
      issuerMismatch: mismatch
    };
  }

  function buildOtpAuth(a, secretB32) {
    var label = encodeURIComponent(a.issuer) + ':' + encodeURIComponent(a.account);
    return 'otpauth://totp/' + label + '?secret=' + secretB32.replace(/=+$/, '') +
      '&issuer=' + encodeURIComponent(a.issuer) + '&algorithm=' + a.algorithm +
      '&digits=' + a.digits + '&period=' + a.period;
  }

  window.TotpLib = {
    ALGORITHM_LABEL: LABEL,
    base32Decode: base32Decode,
    base32Encode: base32Encode,
    validate: validate,
    importSecret: importSecret,
    hotp: hotp,
    timeStep: timeStep,
    secondsRemaining: secondsRemaining,
    parseOtpAuth: parseOtpAuth,
    buildOtpAuth: buildOtpAuth
  };
})();
