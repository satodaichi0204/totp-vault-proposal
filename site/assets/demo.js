/*
 * 操作デモの画面処理。何も保存せず（Cookie・localStorage 不使用）、外部と通信しない。
 * 秘密鍵は取り込み直後に「取り出し不可」の CryptoKey にし、元のバイト列は 0 で埋める。
 */
(function () {
  'use strict';

  var T = window.TotpLib;
  var CLIPBOARD_CLEAR_SECONDS = 20;
  var DEMO_PASSWORD = 'demo';
  var GROUPS = ['業務', '開発', '個人'];

  // すべて架空のテスト用の値。秘密鍵の長さは RFC 6238 の推奨どおり、ハッシュの出力長に合わせている
  var DEMO_ACCOUNTS = [
    { issuer: '社内ポータル', account: 'tanaka@example.co.jp', secret: 'DK6TLFN24RUJAB7VP4AT5OGABBDWFS6F', algorithm: 'SHA1', digits: 6, period: 30, group: '業務', fav: true },
    { issuer: '経理クラウド', account: 'keiri@example.co.jp', secret: 'GLBPCNI25ZWSLZMRCDCQ35C2MHQGICKZWQ43G4BWFM6DMYD7JQKA', algorithm: 'SHA256', digits: 8, period: 30, group: '業務', fav: true },
    { issuer: '開発用 Git', account: 'tanaka-dev', secret: 'HB4BIQT4HMV46FXSQ44UXMW6ZWPJOQJX', algorithm: 'SHA1', digits: 6, period: 30, group: '開発', fav: false },
    { issuer: '社外 VPN', account: 'tanaka', secret: '3LUMSXTHLYNKSZBTQNIK5CPBFK7V5IJIVGGGCI7O63K44YGA6SFZEFOFTXAQATKOPRWQS242GJ4AK3JYM6PCOB5KYZKGKKYJIWNVRHI', algorithm: 'SHA512', digits: 8, period: 60, group: '業務', fav: false },
    { issuer: 'クラウドサーバー管理', account: 'admin@example.com', secret: 'ZNE7VAQABNCEN3YLQALCW7OXOASYPXS674VBJO57YTTTIIKLZHDA', algorithm: 'SHA256', digits: 6, period: 30, group: '開発', fav: false },
    { issuer: '個人メール', account: 'taro@example.net', secret: 'H5XIS3KHDR2BXWAHCWITTKVRUM74DLSZ', algorithm: 'SHA1', digits: 6, period: 30, group: '個人', fav: false }
  ];

  var state = {
    accounts: [],
    filter: 'all',
    query: '',
    sort: 'manual',
    mask: false,
    locked: false,
    lastActivity: Date.now(),
    nextId: 1
  };
  var rows = new Map(); // id -> { li, code, ring, ringText }

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function hueOf(s) {
    var h = 0;
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return h % 360;
  }

  function formatCode(code) {
    if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
    if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
    if (code.length === 7) return code.slice(0, 3) + ' ' + code.slice(3);
    return code;
  }

  function maskCode(digits) {
    return formatCode(new Array(digits + 1).join('•'));
  }

  function isDefaultParams(a) { return a.algorithm === 'SHA1' && a.digits === 6 && a.period === 30; }

  function paramLabel(a) {
    return T.ALGORITHM_LABEL[a.algorithm] + '・' + a.digits + '桁・' + a.period + '秒';
  }

  function normalize(s) { return (s || '').normalize('NFKC').toLowerCase(); }

  // ---------------------------------------------------------------- アカウント

  function addAccount(info, key, qrUri) {
    var a = {
      id: state.nextId++,
      issuer: info.issuer || '（名称なし）',
      account: info.account || '',
      algorithm: info.algorithm,
      digits: info.digits,
      period: info.period,
      group: info.group || '',
      fav: !!info.fav,
      key: key,
      qrUri: qrUri || null, // デモ用アカウントだけ照合用に QR を出せる
      lastUsed: 0,
      code: '',
      step: -1,
      pending: false
    };
    state.accounts.push(a);
    return a;
  }

  function findAccount(id) {
    for (var i = 0; i < state.accounts.length; i++) if (state.accounts[i].id === id) return state.accounts[i];
    return null;
  }

  function visibleAccounts() {
    var q = normalize(state.query.trim());
    var list = state.accounts.filter(function (a) {
      if (state.filter === 'fav' && !a.fav) return false;
      if (state.filter !== 'all' && state.filter !== 'fav' && a.group !== state.filter) return false;
      if (q && normalize(a.issuer + ' ' + a.account).indexOf(q) < 0) return false;
      return true;
    });
    var order = new Map(state.accounts.map(function (a, i) { return [a.id, i]; }));
    list.sort(function (x, y) {
      if (x.fav !== y.fav) return x.fav ? -1 : 1; // お気に入りを先頭に
      if (state.sort === 'issuer') return x.issuer.localeCompare(y.issuer, 'ja') || x.account.localeCompare(y.account, 'ja');
      if (state.sort === 'recent' && x.lastUsed !== y.lastUsed) return y.lastUsed - x.lastUsed;
      return order.get(x.id) - order.get(y.id);
    });
    return list;
  }

  // ---------------------------------------------------------------- 描画

  function renderChips() {
    var chips = $('chips');
    chips.textContent = '';
    var defs = [{ key: 'all', label: 'すべて', n: state.accounts.length },
                { key: 'fav', label: '★ お気に入り', n: state.accounts.filter(function (a) { return a.fav; }).length }];
    GROUPS.forEach(function (g) {
      var n = state.accounts.filter(function (a) { return a.group === g; }).length;
      if (n) defs.push({ key: g, label: g, n: n });
    });
    if (!defs.some(function (d) { return d.key === state.filter; })) state.filter = 'all';
    defs.forEach(function (d) {
      var b = el('button', 'chip', d.label);
      b.type = 'button';
      b.setAttribute('aria-pressed', String(state.filter === d.key));
      b.appendChild(el('span', 'n', String(d.n)));
      b.addEventListener('click', function () { state.filter = d.key; render(); });
      chips.appendChild(b);
    });
  }

  function render() {
    renderChips();
    var list = $('list');
    list.textContent = '';
    rows.clear();
    var items = visibleAccounts();
    var manual = state.sort === 'manual';
    list.classList.toggle('no-drag', !manual);

    var showSections = state.filter === 'all' && items.some(function (a) { return a.fav; }) && items.some(function (a) { return !a.fav; });
    var lastFav = null;
    items.forEach(function (a) {
      if (showSections && a.fav !== lastFav) {
        var label = el('li', 'section-label', a.fav ? 'お気に入り' : 'その他');
        label.setAttribute('aria-hidden', 'true');
        list.appendChild(label);
        lastFav = a.fav;
      }
      list.appendChild(buildRow(a, manual));
    });

    var empty = $('empty');
    if (!items.length) {
      empty.hidden = false;
      empty.textContent = state.accounts.length ? '条件に合うアカウントがありません。' : 'アカウントがありません。「追加」から登録してください。';
    } else {
      empty.hidden = true;
    }
    tick();
  }

  function buildRow(a, manual) {
    var li = el('li', 'row');
    li.dataset.id = String(a.id);
    li.draggable = manual;

    var grip = el('span', 'grip', '⋮⋮');
    grip.setAttribute('aria-hidden', 'true');
    grip.title = 'ドラッグで並べ替え';

    var avatar = el('span', 'avatar', Array.from(a.issuer)[0] || '?');
    avatar.style.setProperty('--hue', String(hueOf(a.issuer)));
    avatar.setAttribute('aria-hidden', 'true');

    var who = el('div', 'who');
    who.appendChild(el('div', 'issuer', a.issuer));
    var acct = el('div', 'acct');
    acct.appendChild(el('span', 'acct-name', a.account));
    if (!isDefaultParams(a)) acct.appendChild(el('span', 'badge', paramLabel(a)));
    who.appendChild(acct);

    var code = el('button', 'code');
    code.type = 'button';
    code.setAttribute('aria-label', a.issuer + ' のコードをコピー');
    code.addEventListener('click', function () { copyCode(a, code); });

    var ring = el('span', 'ring');
    var ringText = el('span');
    ring.appendChild(ringText);
    ring.title = 'コードが切り替わるまでの秒数';

    var star = el('button', 'star', a.fav ? '★' : '☆');
    star.type = 'button';
    star.setAttribute('aria-pressed', String(a.fav));
    star.setAttribute('aria-label', 'お気に入り');
    star.addEventListener('click', function () { a.fav = !a.fav; render(); });

    var more = el('button', 'more', '⋮');
    more.type = 'button';
    more.setAttribute('aria-label', a.issuer + ' のメニュー');
    more.setAttribute('aria-haspopup', 'menu');
    more.addEventListener('click', function (e) { e.stopPropagation(); openMenu(a, more); });

    [grip, avatar, who, code, ring, star, more].forEach(function (n) { li.appendChild(n); });
    if (manual) wireDrag(li, a);
    rows.set(a.id, { li: li, code: code, ring: ring, ringText: ringText });
    return li;
  }

  // ---------------------------------------------------------------- コードの更新

  function tick() {
    var now = Date.now();
    state.accounts.forEach(function (a) {
      var r = rows.get(a.id);
      var remaining = T.secondsRemaining(now, a.period);
      if (state.locked) {
        if (r) {
          r.code.textContent = maskCode(a.digits);
          r.code.classList.add('locked');
        }
        return;
      }
      var step = T.timeStep(now, a.period);
      if (step !== a.step && !a.pending) {
        a.pending = true;
        T.hotp(a.key, step, a.digits).then(function (c) {
          a.pending = false;
          if (state.locked) return;
          a.code = c;
          a.step = step;
          paintCode(a);
        }, function () { a.pending = false; });
      }
      if (r) {
        r.ring.style.setProperty('--p', String(remaining / a.period));
        r.ring.classList.toggle('low', remaining <= 5);
        r.ringText.textContent = String(remaining);
        paintCode(a);
      }
    });
    updateStatus(now);
  }

  function paintCode(a) {
    var r = rows.get(a.id);
    if (!r) return;
    r.code.classList.toggle('locked', !a.code);
    var text = !a.code ? maskCode(a.digits) : state.mask ? maskCode(a.digits) : formatCode(a.code);
    if (r.code.textContent !== text) r.code.textContent = text;
  }

  // ---------------------------------------------------------------- コピーとクリップボードの消去

  var copyToken = 0;
  var toastTimer = null;
  var clearTimer = null;

  function copyCode(a, button) {
    if (state.locked || !a.code) return;
    var token = ++copyToken;
    var code = a.code;
    writeClipboard(code).then(function () {
      lastCopied = code;
      leftSinceCopy = false;
      a.lastUsed = Date.now();
      button.classList.add('copied');
      setTimeout(function () { button.classList.remove('copied'); }, 900);
      showToast('コピーしました。' + CLIPBOARD_CLEAR_SECONDS + '秒後にクリップボードから消去します', CLIPBOARD_CLEAR_SECONDS);
      clearTimeout(clearTimer);
      clearTimer = setTimeout(function () { clearClipboard(token); }, CLIPBOARD_CLEAR_SECONDS * 1000);
      if (state.sort === 'recent') render();
    }, function () {
      showToast('コピーできませんでした（ブラウザの設定でクリップボードが禁止されています）', 0);
    });
  }

  function writeClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = el('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'visually-hidden';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('copy failed'));
    });
  }

  // コピーの後にページを離れたか。離れた間に、他のアプリで別のものをコピーした可能性がある
  var leftSinceCopy = false;
  var lastCopied = '';
  window.addEventListener('blur', function () { leftSinceCopy = true; });

  function clearClipboard(token) {
    // 後から別のコピーをしていたら消さない（本番は Windows のクリップボードの更新番号で確実に判定する）
    if (token !== copyToken) return;
    var copied = lastCopied;
    lastCopied = '';
    if (!document.hasFocus()) {
      showToast('ブラウザが前面にないため、クリップボードを消去できませんでした。本番アプリは Windows の機能で確実に消去します', 0, 6000);
      return;
    }
    if (!leftSinceCopy) { doClear(); return; }

    // ページを離れていた場合は、中身がまだこのコードかを確かめられるときだけ消す
    stillOurCode(copied).then(function (same) {
      if (same) doClear();
      else showToast('他のアプリでコピーした内容を消さないよう、消去を見送りました。本番アプリはクリップボードの更新番号で判定し、コードだけを確実に消去します', 0, 7000);
    });
  }

  function stillOurCode(copied) {
    if (!copied || !navigator.permissions || !navigator.clipboard || !navigator.clipboard.readText) return Promise.resolve(false);
    // 読み取りの許可をすでに得ている場合だけ確かめる（許可を求める画面は出さない）
    return navigator.permissions.query({ name: 'clipboard-read' }).then(function (p) {
      if (p.state !== 'granted') return false;
      return navigator.clipboard.readText().then(function (t) { return t === copied; });
    }).catch(function () { return false; });
  }

  function doClear() {
    writeClipboard('').then(function () {
      showToast('クリップボードからコードを消去しました', 0, 2500);
    }, function () {
      showToast('ブラウザの制限でクリップボードを消去できませんでした。本番アプリは Windows の機能で確実に消去します', 0, 6000);
    });
  }

  function showToast(text, countdownSeconds, holdMs) {
    var t = $('toast');
    $('toast-text').textContent = text;
    t.hidden = false;
    t.classList.toggle('no-bar', !countdownSeconds);
    var bar = $('toast-progress');
    clearTimeout(toastTimer);
    if (countdownSeconds) {
      bar.style.transition = 'none';
      bar.style.transform = 'scaleX(1)';
      void bar.offsetWidth;
      bar.style.transition = 'transform ' + countdownSeconds + 's linear';
      bar.style.transform = 'scaleX(0)';
      toastTimer = setTimeout(function () { t.hidden = true; }, countdownSeconds * 1000);
    } else {
      toastTimer = setTimeout(function () { t.hidden = true; }, holdMs || 4000);
    }
  }

  // ---------------------------------------------------------------- 並べ替え

  var dragId = null;

  function sameSection(a, b) { return a.fav === b.fav; }

  function moveRelative(srcId, targetId, after) {
    if (srcId === targetId) return;
    var src = findAccount(srcId), target = findAccount(targetId);
    if (!src || !target || !sameSection(src, target)) return;
    state.accounts.splice(state.accounts.indexOf(src), 1);
    var idx = state.accounts.indexOf(target) + (after ? 1 : 0);
    state.accounts.splice(idx, 0, src);
    render();
  }

  function wireDrag(li, a) {
    li.addEventListener('dragstart', function (e) {
      dragId = a.id;
      li.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', ''); // Firefox ではデータがないとドラッグが始まらない
    });
    li.addEventListener('dragend', function () {
      dragId = null;
      document.querySelectorAll('.row').forEach(function (r) { r.classList.remove('dragging', 'drop-before', 'drop-after'); });
    });
    li.addEventListener('dragover', function (e) {
      if (dragId == null) return;
      var src = findAccount(dragId);
      if (!src || !sameSection(src, a)) return;
      e.preventDefault();
      var rect = li.getBoundingClientRect();
      var after = e.clientY > rect.top + rect.height / 2;
      li.classList.toggle('drop-after', after);
      li.classList.toggle('drop-before', !after);
    });
    li.addEventListener('dragleave', function () { li.classList.remove('drop-before', 'drop-after'); });
    li.addEventListener('drop', function (e) {
      e.preventDefault();
      var after = li.classList.contains('drop-after');
      if (dragId != null) moveRelative(dragId, a.id, after);
    });
  }

  function neighbor(a, dir) {
    var items = visibleAccounts();
    var i = items.indexOf(a);
    var n = items[i + dir];
    return n && sameSection(a, n) ? n : null;
  }

  // ---------------------------------------------------------------- メニュー

  var menuAccount = null;

  function openMenu(a, anchor) {
    menuAccount = a;
    var menu = $('menu');
    menu.hidden = false;
    menu.querySelector('[data-act="qr"]').disabled = !a.qrUri;
    menu.querySelector('[data-act="qr"]').title = a.qrUri ? '' : '本番と同じく、登録後は秘密鍵を再表示しません';
    var manual = state.sort === 'manual';
    menu.querySelector('[data-act="up"]').disabled = !manual || !neighbor(a, -1);
    menu.querySelector('[data-act="down"]').disabled = !manual || !neighbor(a, 1);
    var r = anchor.getBoundingClientRect();
    var w = menu.offsetWidth, h = menu.offsetHeight;
    var left = Math.min(r.right - w, window.innerWidth - w - 8);
    var top = r.bottom + 4 + h > window.innerHeight ? r.top - h - 4 : r.bottom + 4;
    menu.style.left = Math.max(8, left) + 'px';
    menu.style.top = Math.max(8, top) + 'px';
    var first = menu.querySelector('button:not(:disabled)');
    if (first) first.focus();
  }

  function closeMenu() {
    $('menu').hidden = true;
    menuAccount = null;
  }

  $('menu').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-act]');
    if (!b || b.disabled || !menuAccount) return;
    var a = menuAccount;
    closeMenu();
    var act = b.dataset.act;
    if (act === 'qr') openQr(a);
    else if (act === 'edit') openEdit(a);
    else if (act === 'up' || act === 'down') {
      var n = neighbor(a, act === 'up' ? -1 : 1);
      if (n) moveRelative(a.id, n.id, act === 'down');
    }
  });
  document.addEventListener('click', function (e) {
    if (!$('menu').hidden && !e.target.closest('#menu')) closeMenu();
  });

  // ---------------------------------------------------------------- QR 表示

  function qrSvg(text) {
    var qr = window.qrcode(0, 'M');
    qr.addData(unescape(encodeURIComponent(text))); // UTF-8 のバイト列として格納する
    qr.make();
    var n = qr.getModuleCount(), quiet = 4, size = n + quiet * 2;
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
    svg.setAttribute('shape-rendering', 'crispEdges');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'otpauth URI の QR コード');
    var bg = document.createElementNS(ns, 'rect');
    bg.setAttribute('width', size); bg.setAttribute('height', size); bg.setAttribute('fill', '#fff');
    svg.appendChild(bg);
    var d = '';
    for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (qr.isDark(r, c)) d += 'M' + (c + quiet) + ' ' + (r + quiet) + 'h1v1h-1z';
    var path = document.createElementNS(ns, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#000');
    svg.appendChild(path);
    return { svg: svg, modules: n, quiet: quiet, qr: qr };
  }

  function openQr(a) {
    var box = $('qr-box');
    box.textContent = '';
    box.appendChild(qrSvg(a.qrUri).svg);
    $('qr-name').textContent = a.issuer + '（' + a.account + '）';
    var compat = $('qr-compat');
    if (isDefaultParams(a)) {
      compat.hidden = true;
    } else {
      compat.hidden = false;
      compat.textContent = 'このアカウントは ' + paramLabel(a) + ' です。認証アプリによっては、これらの指定を読み取らずに SHA-1・6桁・30秒として扱うものがあり、その場合は数字が一致しません。照合には「社内ポータル」など標準設定のアカウントをお使いください。';
    }
    $('dlg-qr').showModal();
  }

  // ---------------------------------------------------------------- 追加

  var pending = null; // { info, key }

  function openAdd() {
    resetAdd();
    setAddMode('image');
    $('dlg-add').showModal();
  }

  function resetAdd() {
    pending = null;
    $('add-error').textContent = '';
    $('add-preview').hidden = true;
    $('uri').value = '';
    $('manual-form').reset();
    var drop = $('drop');
    var c = drop.querySelector('canvas');
    if (c) c.remove();
  }

  function setAddMode(mode) {
    document.querySelectorAll('#dlg-add .seg button').forEach(function (b) {
      b.setAttribute('aria-selected', String(b.dataset.mode === mode));
    });
    document.querySelectorAll('#dlg-add .add-pane').forEach(function (p) { p.hidden = p.dataset.pane !== mode; });
    $('add-error').textContent = '';
    $('add-preview').hidden = true;
  }

  function addError(msg) {
    $('add-error').textContent = msg;
    $('add-preview').hidden = true;
  }

  function decodeQrFromBlob(blob) {
    if (!window.createImageBitmap) return Promise.reject(new Error('このブラウザは画像の読み取りに対応していません。'));
    return createImageBitmap(blob).then(function (bmp) {
      return decodeQrFromSource(bmp, bmp.width, bmp.height);
    });
  }

  function decodeQrFromSource(src, w, h) {
    // 大きなスクリーンショットは縮小して読み取り、だめなら原寸で再試行する
    var attempts = [];
    var scale = Math.min(1, 1200 / Math.max(w, h));
    attempts.push(scale);
    if (scale < 1) attempts.push(1);
    for (var i = 0; i < attempts.length; i++) {
      var cw = Math.max(1, Math.round(w * attempts[i])), ch = Math.max(1, Math.round(h * attempts[i]));
      var canvas = document.createElement('canvas');
      canvas.width = cw; canvas.height = ch;
      var ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, cw, ch);
      ctx.drawImage(src, 0, 0, cw, ch);
      var img = ctx.getImageData(0, 0, cw, ch);
      var res = window.jsQR(img.data, cw, ch, { inversionAttempts: 'attemptBoth' });
      img.data.fill(0);
      if (res && res.data) return res.binaryData ? utf8(res.binaryData) : res.data;
    }
    throw new Error('QR コードが見つかりませんでした。QR コード全体が入るように切り取ってください。');
  }

  function utf8(bytes) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes)); }
    catch (e) { return String.fromCharCode.apply(null, bytes); }
  }

  function handleUri(uri) {
    var info;
    try { info = T.parseOtpAuth(uri); }
    catch (e) { addError(e.message); return; }
    preparePreview(info);
  }

  function preparePreview(info) {
    var bytes = info.secret;
    delete info.secret;
    if (bytes.length < 10) {
      // RFC 4226 は 128bit 以上を必須、160bit を推奨としている
      info.weakKey = true;
    }
    T.importSecret(bytes, info.algorithm).then(function (key) {
      var step = T.timeStep(Date.now(), info.period);
      return T.hotp(key, step, info.digits).then(function (code) {
        pending = { info: info, key: key };
        return duplicateOf(info, step, code).then(function (dup) { showPreview(info, code, dup); });
      });
    }).catch(function (e) { addError(e.message || '読み取りに失敗しました。'); });
  }

  // 秘密鍵は取り出せないので、同じ時刻のコードが一致するかで重複を判定する
  function duplicateOf(info, step, code) {
    var same = state.accounts.filter(function (a) {
      return a.algorithm === info.algorithm && a.digits === info.digits && a.period === info.period;
    });
    return Promise.all(same.map(function (a) {
      return T.hotp(a.key, step, a.digits).then(function (c) { return c === code ? a : null; });
    })).then(function (r) { return r.filter(Boolean)[0] || null; });
  }

  function showPreview(info, code, dup) {
    $('add-error').textContent = '';
    var dl = $('add-preview-list');
    dl.textContent = '';
    function row(k, v, cls) {
      dl.appendChild(el('dt', null, k));
      var dd = el('dd', cls || null, v);
      dl.appendChild(dd);
      return dd;
    }
    row('サービス名', info.issuer || '（なし）');
    row('アカウント名', info.account || '（なし）');
    row('方式', paramLabel(info) + (isDefaultParams(info) ? '（標準）' : ''));
    row('現在のコード', formatCode(code), 'now-code');
    var gdd = row('グループ', '');
    var sel = el('select');
    sel.id = 'p-group';
    [''].concat(GROUPS).forEach(function (g) {
      var o = el('option', null, g || 'なし');
      o.value = g;
      sel.appendChild(o);
    });
    sel.value = GROUPS.indexOf(state.filter) >= 0 ? state.filter : '';
    gdd.appendChild(sel);
    if (dup) row('注意', '「' + dup.issuer + '」と同じ秘密鍵です（すでに登録済み）。');
    if (info.weakKey) row('注意', '秘密鍵が 80bit 未満です。サービス側の設定を確認してください。');
    $('add-mismatch').hidden = !info.issuerMismatch;
    $('add-preview').hidden = false;
    $('btn-add-confirm').focus();
  }

  function confirmAdd() {
    if (!pending) return;
    var info = pending.info;
    info.group = $('p-group').value;
    var a = addAccount(info, pending.key, null);
    pending = null;
    $('dlg-add').close();
    state.filter = 'all';
    state.query = '';
    $('search').value = '';
    render();
    var r = rows.get(a.id);
    if (r) {
      r.li.classList.add('flash');
      r.li.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  function sampleQr() {
    // その場で乱数の秘密鍵を作り、QR 画像にしてから、読み取り処理に通す
    var bytes = crypto.getRandomValues(new Uint8Array(32));
    var uri = T.buildOtpAuth({ issuer: 'サンプル', account: 'sample' + (state.nextId) + '@example.com', algorithm: 'SHA256', digits: 8, period: 30 }, T.base32Encode(bytes, false));
    bytes.fill(0);
    var q = qrSvg(uri);
    var scale = 4, size = (q.modules + q.quiet * 2) * scale;
    var canvas = document.createElement('canvas');
    canvas.width = size; canvas.height = size;
    var ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000';
    for (var r = 0; r < q.modules; r++) for (var c = 0; c < q.modules; c++)
      if (q.qr.isDark(r, c)) ctx.fillRect((c + q.quiet) * scale, (r + q.quiet) * scale, scale, scale);
    var drop = $('drop');
    var old = drop.querySelector('canvas');
    if (old) old.remove();
    drop.insertBefore(canvas, drop.firstChild);
    try { handleUri(decodeQrFromSource(canvas, size, size)); }
    catch (e) { addError(e.message); }
  }

  function handleImageFile(file) {
    if (!file || !/^image\//.test(file.type)) { addError('画像ファイルを選んでください。'); return; }
    var drop = $('drop');
    var old = drop.querySelector('canvas');
    if (old) old.remove();
    decodeQrFromBlob(file).then(handleUri, function (e) { addError(e.message); });
  }

  function manualSubmit(e) {
    e.preventDefault();
    var info = {
      issuer: $('m-issuer').value.trim(),
      account: $('m-account').value.trim(),
      algorithm: $('m-alg').value,
      digits: parseInt($('m-digits').value, 10),
      period: parseInt($('m-period').value, 10),
      issuerMismatch: false
    };
    if (!info.issuer) { addError('サービス名を入力してください。'); return; }
    try {
      T.validate(info);
      info.secret = T.base32Decode($('m-secret').value);
    } catch (err) { addError(err.message); return; }
    $('m-secret').value = '';
    preparePreview(info);
  }

  // ---------------------------------------------------------------- 編集・削除

  var editing = null;

  function openEdit(a) {
    editing = a;
    $('e-issuer').value = a.issuer;
    $('e-account').value = a.account;
    var sel = $('e-group');
    sel.textContent = '';
    [''].concat(GROUPS).forEach(function (g) {
      var o = el('option', null, g || 'なし');
      o.value = g;
      sel.appendChild(o);
    });
    sel.value = a.group;
    $('dlg-edit').showModal();
  }

  $('edit-form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (!editing) return;
    var issuer = $('e-issuer').value.trim();
    if (!issuer) return;
    editing.issuer = issuer;
    editing.account = $('e-account').value.trim();
    editing.group = $('e-group').value;
    $('dlg-edit').close();
    render();
  });

  $('btn-delete').addEventListener('click', function () {
    if (!editing) return;
    $('delete-name').textContent = editing.issuer + '（' + editing.account + '）';
    $('dlg-edit').close();
    $('dlg-delete').showModal();
  });

  $('btn-delete-confirm').addEventListener('click', function () {
    if (editing) {
      state.accounts.splice(state.accounts.indexOf(editing), 1);
      editing = null;
    }
    $('dlg-delete').close();
    render();
  });

  // ---------------------------------------------------------------- ロック

  function lock(reason) {
    if (state.locked) return;
    state.locked = true;
    // 本番では DEK を 0 埋めし、復号済みのアカウント一覧も破棄する
    state.accounts.forEach(function (a) { a.code = ''; a.step = -1; });
    closeMenu();
    document.querySelectorAll('dialog[open]').forEach(function (d) { d.close(); });
    $('toast').hidden = true;
    $('lock-reason').textContent = reason;
    $('lock-error').textContent = '';
    $('lock-pass').value = '';
    $('lock').hidden = false;
    tick();
    if (document.visibilityState === 'visible') $('lock-pass').focus({ preventScroll: true });
  }

  var unlockBusy = false;
  $('lock-form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (unlockBusy) return;
    var input = $('lock-pass');
    if (input.value === DEMO_PASSWORD) {
      input.value = '';
      state.locked = false;
      state.lastActivity = Date.now();
      $('lock').hidden = true;
      tick();
      return;
    }
    input.value = '';
    // 本番では Argon2id の計算時間（約0.5〜1秒）が、総当たりへの主な歯止めになる
    unlockBusy = true;
    $('lock-error').textContent = 'パスワードが違います（デモでは demo）';
    setTimeout(function () { unlockBusy = false; }, 800);
  });

  $('btn-lock').addEventListener('click', function () { lock('手動でロックしました'); });

  function updateStatus(now) {
    var d = new Date(now);
    var off = -d.getTimezoneOffset();
    var tz = 'UTC' + (off >= 0 ? '+' : '-') + Math.floor(Math.abs(off) / 60) + (Math.abs(off) % 60 ? ':' + String(Math.abs(off) % 60).padStart(2, '0') : '');
    $('clock').textContent = '端末時刻 ' + d.toLocaleTimeString('ja-JP', { hour12: false }) + '（' + tz + '）';

    var limit = parseInt($('idle-minutes').value, 10) * 60 * 1000;
    var left = Math.max(0, limit - (now - state.lastActivity));
    if (state.locked) {
      $('idle-left').textContent = 'ロック中';
    } else {
      var s = Math.ceil(left / 1000);
      $('idle-left').textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
      if (left <= 0) lock('一定時間操作がなかったため、自動でロックしました');
    }
  }

  ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'].forEach(function (type) {
    document.addEventListener(type, function () { if (!state.locked) state.lastActivity = Date.now(); }, { passive: true });
  });

  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden' && $('lock-on-hide').checked)
      lock('画面を離れたため、ロックしました（本番では Windows のロック・スリープ・ユーザー切り替え時）');
  });

  // ---------------------------------------------------------------- その他の操作

  $('search').addEventListener('input', function (e) { state.query = e.target.value; render(); });
  $('search').addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { e.target.value = ''; state.query = ''; render(); }
  });
  $('sort').addEventListener('change', function (e) { state.sort = e.target.value; render(); });
  $('mask').addEventListener('change', function (e) { state.mask = e.target.checked; tick(); });
  $('idle-minutes').addEventListener('change', function () { state.lastActivity = Date.now(); });
  $('btn-add').addEventListener('click', openAdd);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !$('menu').hidden) { closeMenu(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f' && !state.locked && !document.querySelector('dialog[open]')
        && !$('panel-app').hidden) {
      e.preventDefault();
      $('search').focus();
      $('search').select();
    }
  });

  document.querySelectorAll('[data-close]').forEach(function (b) {
    b.addEventListener('click', function () { b.closest('dialog').close(); });
  });
  $('dlg-add').addEventListener('close', function () { pending = null; });

  document.querySelectorAll('#dlg-add .seg button').forEach(function (b) {
    b.addEventListener('click', function () { setAddMode(b.dataset.mode); });
  });
  $('btn-sample-qr').addEventListener('click', sampleQr);
  $('btn-parse-uri').addEventListener('click', function () { handleUri($('uri').value); });
  $('manual-form').addEventListener('submit', manualSubmit);
  $('btn-add-back').addEventListener('click', function () { pending = null; $('add-preview').hidden = true; });
  $('btn-add-confirm').addEventListener('click', confirmAdd);
  $('file').addEventListener('change', function (e) { handleImageFile(e.target.files[0]); e.target.value = ''; });

  var drop = $('drop');
  ['dragenter', 'dragover'].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (t) {
    drop.addEventListener(t, function () { drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (e) {
    e.preventDefault();
    handleImageFile(e.dataTransfer.files[0]);
  });

  document.addEventListener('paste', function (e) {
    if (!$('dlg-add').open) return;
    var items = e.clipboardData ? Array.from(e.clipboardData.items) : [];
    var img = items.find(function (i) { return i.kind === 'file' && /^image\//.test(i.type); });
    if (img) {
      e.preventDefault();
      setAddMode('image');
      handleImageFile(img.getAsFile());
      return;
    }
    var text = e.clipboardData.getData('text/plain');
    if (/^\s*otpauth(-migration)?:\/\//i.test(text) && document.activeElement !== $('uri')) {
      e.preventDefault();
      setAddMode('uri');
      $('uri').value = text.trim();
      handleUri(text);
    }
  });

  // ---------------------------------------------------------------- 表示の切り替え（アプリ画面 / RFC テスト）

  var rfcDone = false;
  function selectTab(tab) {
    document.querySelectorAll('.view-tabs [role="tab"]').forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    });
    if (tab.id === 'tab-rfc' && !rfcDone) { rfcDone = true; runRfc(); }
  }
  document.querySelectorAll('.view-tabs [role="tab"]').forEach(function (t, i, all) {
    t.addEventListener('click', function () { selectTab(t); });
    t.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      var n = all[(i + (e.key === 'ArrowRight' ? 1 : all.length - 1)) % all.length];
      n.focus();
      selectTab(n);
    });
  });

  // ---------------------------------------------------------------- RFC テスト

  function runRfc() {
    var enc = new TextEncoder();
    var seeds = {
      SHA1: '12345678901234567890',
      SHA256: '12345678901234567890123456789012',
      SHA512: '1234567890123456789012345678901234567890123456789012345678901234'
    };
    var totp = [
      [59, '94287082', '46119246', '90693936'],
      [1111111109, '07081804', '68084774', '25091201'],
      [1111111111, '14050471', '67062674', '99943326'],
      [1234567890, '89005924', '91819424', '93441116'],
      [2000000000, '69279037', '90698825', '38618901'],
      [20000000000, '65353130', '77737706', '47863826']
    ];
    var hotp = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    var b32 = [['f', 'MY======'], ['fo', 'MZXQ===='], ['foo', 'MZXW6==='], ['foob', 'MZXW6YQ='], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI======']];

    var cases = [];
    ['SHA1', 'SHA256', 'SHA512'].forEach(function (alg, k) {
      totp.forEach(function (v) {
        cases.push({
          spec: 'RFC 6238 付録B',
          input: 'T = ' + v[0] + '（' + new Date(v[0] * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') + '）',
          alg: T.ALGORITHM_LABEL[alg] + '・8桁',
          expected: v[k + 1],
          run: function () {
            return T.importSecret(enc.encode(seeds[alg]), alg).then(function (key) { return T.hotp(key, T.timeStep(v[0] * 1000, 30), 8); });
          }
        });
      });
    });
    hotp.forEach(function (exp, i) {
      cases.push({
        spec: 'RFC 4226 付録D', input: 'カウンター ' + i, alg: 'HOTP SHA-1・6桁', expected: exp,
        run: function () { return T.importSecret(enc.encode(seeds.SHA1), 'SHA1').then(function (key) { return T.hotp(key, i, 6); }); }
      });
    });
    b32.forEach(function (v) {
      cases.push({
        spec: 'RFC 4648 10章', input: '"' + v[0] + '"', alg: 'Base32 符号化', expected: v[1],
        run: function () { return Promise.resolve(T.base32Encode(enc.encode(v[0]))); }
      });
      cases.push({
        spec: 'RFC 4648 10章', input: '"' + v[1] + '"', alg: 'Base32 復号', expected: v[0],
        run: function () { return Promise.resolve(new TextDecoder().decode(T.base32Decode(v[1]))); }
      });
    });

    var body = $('rfc-body');
    Promise.all(cases.map(function (c) {
      return c.run().then(function (r) { return r; }, function (e) { return 'エラー: ' + e.message; });
    })).then(function (results) {
      var ok = 0;
      body.textContent = '';
      cases.forEach(function (c, i) {
        var pass = results[i] === c.expected;
        if (pass) ok++;
        var tr = el('tr');
        [c.spec, c.input, c.alg, c.expected, results[i]].forEach(function (t) { tr.appendChild(el('td', null, t)); });
        tr.appendChild(el('td', pass ? 'pass' : 'fail', pass ? '一致' : '不一致'));
        body.appendChild(tr);
      });
      var sum = $('rfc-summary');
      sum.textContent = cases.length + ' 件中 ' + ok + ' 件が一致' + (ok === cases.length ? '（すべて一致）' : '');
      sum.classList.toggle('pass-all', ok === cases.length);
    });
  }

  // ---------------------------------------------------------------- 通信テスト

  var cspBlocked = false;
  document.addEventListener('securitypolicyviolation', function (e) {
    if (/^connect-src/.test(e.effectiveDirective || e.violatedDirective || '')) cspBlocked = true;
  });

  $('net-test').addEventListener('click', function () {
    var out = $('net-result');
    out.className = 'net-result';
    out.textContent = '試しています…';
    cspBlocked = false;
    var done = function (sent) {
      setTimeout(function () {
        if (cspBlocked) {
          out.classList.add('ok');
          out.textContent = '送信がブロックされました（CSP: connect-src \'none\'）。このページから外部へは送信できません。';
        } else if (sent) {
          out.classList.add('ng');
          out.textContent = '送信できてしまいました。この環境では CSP が適用されていません（ファイルを直接開いた場合など）。';
        } else {
          out.textContent = '送信に失敗しました（ネットワークの状態による可能性があります）。';
        }
      }, 80);
    };
    // no-cors にすることで、CSP がなければ実際に送信が成功する条件で試す
    fetch('https://example.com/', { mode: 'no-cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
      .then(function () { done(true); }, function () { done(false); });
  });

  // ---------------------------------------------------------------- 起動

  Promise.all(DEMO_ACCOUNTS.map(function (d) {
    var bytes = T.base32Decode(d.secret);
    var uri = T.buildOtpAuth(d, d.secret);
    return T.importSecret(bytes, d.algorithm).then(function (key) { return { d: d, key: key, uri: uri }; });
  })).then(function (list) {
    list.forEach(function (x) { addAccount(x.d, x.key, x.uri); });
    render();
    setInterval(tick, 250);
  }).catch(function (e) {
    $('empty').hidden = false;
    $('empty').textContent = 'このブラウザでは TOTP を計算できません（' + e.message + '）。最新の Chrome / Edge / Firefox / Safari でお試しください。';
  });
})();
