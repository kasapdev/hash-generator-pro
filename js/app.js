/* =====================================================================
   Hash Generator Pro — app.js
   Generate MD5 (pure JS), SHA-1/256/384/512 (Web Crypto), and compare
   hashes. Classic script (no modules). Depends on window.WUS (core.js).
   ===================================================================== */
(function () {
  'use strict';

  var WUS = window.WUS;
  var STORE_KEY = 'hashgen.state';

  /* ============================= MD5 =================================
     Pure-JS MD5 (RFC 1321), operating on a Uint8Array of raw bytes.
     Verified against known test vectors:
       md5("")    = d41d8cd98f00b204e9800998ecf8427e
       md5("abc") = 900150983cd24fb0d6963f7d28e17f72
       md5("a" x 1000000) = 7707d6ae4e027c70eea2a935c2296f21
     ================================================================= */
  var MD5_T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  ];

  function md5Rotl(x, s) { return ((x << s) | (x >>> (32 - s))) >>> 0; }
  function md5Add() {
    var sum = 0;
    for (var i = 0; i < arguments.length; i++) sum = (sum + arguments[i]) >>> 0;
    return sum;
  }
  function md5F(b, c, d) { return (b & c) | (~b & d); }
  function md5G(b, c, d) { return (b & d) | (c & ~d); }
  function md5H(b, c, d) { return b ^ c ^ d; }
  function md5I(b, c, d) { return c ^ (b | ~d); }

  function md5Hex(bytes) {
    var origLenBits = bytes.length * 8;
    var withOne = bytes.length + 1;
    var totalLen = withOne;
    while (totalLen % 64 !== 56) totalLen++;
    totalLen += 8;

    var buf = new Uint8Array(totalLen);
    buf.set(bytes, 0);
    buf[bytes.length] = 0x80;

    var lo = origLenBits >>> 0;
    var hi = Math.floor(origLenBits / 0x100000000) >>> 0;
    var lenOffset = totalLen - 8;
    buf[lenOffset] = lo & 0xff;
    buf[lenOffset + 1] = (lo >>> 8) & 0xff;
    buf[lenOffset + 2] = (lo >>> 16) & 0xff;
    buf[lenOffset + 3] = (lo >>> 24) & 0xff;
    buf[lenOffset + 4] = hi & 0xff;
    buf[lenOffset + 5] = (hi >>> 8) & 0xff;
    buf[lenOffset + 6] = (hi >>> 16) & 0xff;
    buf[lenOffset + 7] = (hi >>> 24) & 0xff;

    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (var chunk = 0; chunk < totalLen; chunk += 64) {
      var x = new Array(16);
      for (var j = 0; j < 16; j++) {
        var o = chunk + j * 4;
        x[j] = (buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24)) >>> 0;
      }

      var a = a0, b = b0, c = c0, d = d0;

      function FF(a, b, c, d, xk, s, t) { a = md5Add(a, md5F(b, c, d), xk, t); return md5Add(md5Rotl(a, s), b); }
      function GG(a, b, c, d, xk, s, t) { a = md5Add(a, md5G(b, c, d), xk, t); return md5Add(md5Rotl(a, s), b); }
      function HH(a, b, c, d, xk, s, t) { a = md5Add(a, md5H(b, c, d), xk, t); return md5Add(md5Rotl(a, s), b); }
      function II(a, b, c, d, xk, s, t) { a = md5Add(a, md5I(b, c, d), xk, t); return md5Add(md5Rotl(a, s), b); }

      a = FF(a, b, c, d, x[0], 7, MD5_T[0]);  d = FF(d, a, b, c, x[1], 12, MD5_T[1]);  c = FF(c, d, a, b, x[2], 17, MD5_T[2]);  b = FF(b, c, d, a, x[3], 22, MD5_T[3]);
      a = FF(a, b, c, d, x[4], 7, MD5_T[4]);  d = FF(d, a, b, c, x[5], 12, MD5_T[5]);  c = FF(c, d, a, b, x[6], 17, MD5_T[6]);  b = FF(b, c, d, a, x[7], 22, MD5_T[7]);
      a = FF(a, b, c, d, x[8], 7, MD5_T[8]);  d = FF(d, a, b, c, x[9], 12, MD5_T[9]);  c = FF(c, d, a, b, x[10], 17, MD5_T[10]); b = FF(b, c, d, a, x[11], 22, MD5_T[11]);
      a = FF(a, b, c, d, x[12], 7, MD5_T[12]); d = FF(d, a, b, c, x[13], 12, MD5_T[13]); c = FF(c, d, a, b, x[14], 17, MD5_T[14]); b = FF(b, c, d, a, x[15], 22, MD5_T[15]);

      a = GG(a, b, c, d, x[1], 5, MD5_T[16]);  d = GG(d, a, b, c, x[6], 9, MD5_T[17]);  c = GG(c, d, a, b, x[11], 14, MD5_T[18]); b = GG(b, c, d, a, x[0], 20, MD5_T[19]);
      a = GG(a, b, c, d, x[5], 5, MD5_T[20]);  d = GG(d, a, b, c, x[10], 9, MD5_T[21]); c = GG(c, d, a, b, x[15], 14, MD5_T[22]); b = GG(b, c, d, a, x[4], 20, MD5_T[23]);
      a = GG(a, b, c, d, x[9], 5, MD5_T[24]);  d = GG(d, a, b, c, x[14], 9, MD5_T[25]); c = GG(c, d, a, b, x[3], 14, MD5_T[26]);  b = GG(b, c, d, a, x[8], 20, MD5_T[27]);
      a = GG(a, b, c, d, x[13], 5, MD5_T[28]); d = GG(d, a, b, c, x[2], 9, MD5_T[29]);  c = GG(c, d, a, b, x[7], 14, MD5_T[30]);  b = GG(b, c, d, a, x[12], 20, MD5_T[31]);

      a = HH(a, b, c, d, x[5], 4, MD5_T[32]);  d = HH(d, a, b, c, x[8], 11, MD5_T[33]);  c = HH(c, d, a, b, x[11], 16, MD5_T[34]); b = HH(b, c, d, a, x[14], 23, MD5_T[35]);
      a = HH(a, b, c, d, x[1], 4, MD5_T[36]);  d = HH(d, a, b, c, x[4], 11, MD5_T[37]);  c = HH(c, d, a, b, x[7], 16, MD5_T[38]);  b = HH(b, c, d, a, x[10], 23, MD5_T[39]);
      a = HH(a, b, c, d, x[13], 4, MD5_T[40]); d = HH(d, a, b, c, x[0], 11, MD5_T[41]);  c = HH(c, d, a, b, x[3], 16, MD5_T[42]);  b = HH(b, c, d, a, x[6], 23, MD5_T[43]);
      a = HH(a, b, c, d, x[9], 4, MD5_T[44]);  d = HH(d, a, b, c, x[12], 11, MD5_T[45]); c = HH(c, d, a, b, x[15], 16, MD5_T[46]); b = HH(b, c, d, a, x[2], 23, MD5_T[47]);

      a = II(a, b, c, d, x[0], 6, MD5_T[48]);  d = II(d, a, b, c, x[7], 10, MD5_T[49]);  c = II(c, d, a, b, x[14], 15, MD5_T[50]); b = II(b, c, d, a, x[5], 21, MD5_T[51]);
      a = II(a, b, c, d, x[12], 6, MD5_T[52]); d = II(d, a, b, c, x[3], 10, MD5_T[53]);  c = II(c, d, a, b, x[10], 15, MD5_T[54]); b = II(b, c, d, a, x[1], 21, MD5_T[55]);
      a = II(a, b, c, d, x[8], 6, MD5_T[56]);  d = II(d, a, b, c, x[15], 10, MD5_T[57]); c = II(c, d, a, b, x[6], 15, MD5_T[58]);  b = II(b, c, d, a, x[13], 21, MD5_T[59]);
      a = II(a, b, c, d, x[4], 6, MD5_T[60]);  d = II(d, a, b, c, x[11], 10, MD5_T[61]); c = II(c, d, a, b, x[2], 15, MD5_T[62]);  b = II(b, c, d, a, x[9], 21, MD5_T[63]);

      a0 = md5Add(a0, a); b0 = md5Add(b0, b); c0 = md5Add(c0, c); d0 = md5Add(d0, d);
    }

    function toHexLE(n) {
      var out = '';
      for (var i = 0; i < 4; i++) {
        var byte = (n >>> (i * 8)) & 0xff;
        out += byte.toString(16).padStart(2, '0');
      }
      return out;
    }

    return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
  }

  /* =================================================================
     Web Crypto SHA family
     ================================================================= */
  function bufferToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function shaHex(algo, bytes) {
    return crypto.subtle.digest(algo, bytes).then(bufferToHex);
  }

  var ALGOS = [
    { key: 'md5', label: 'MD5', len: 32 },
    { key: 'sha1', label: 'SHA-1', subtle: 'SHA-1', len: 40 },
    { key: 'sha256', label: 'SHA-256', subtle: 'SHA-256', len: 64 },
    { key: 'sha384', label: 'SHA-384', subtle: 'SHA-384', len: 96 },
    { key: 'sha512', label: 'SHA-512', subtle: 'SHA-512', len: 128 }
  ];

  /* ----------------------------- DOM refs ---------------------------- */
  var tabText = document.getElementById('tabText');
  var tabFile = document.getElementById('tabFile');
  var textPane = document.getElementById('textPane');
  var filePane = document.getElementById('filePane');
  var textInput = document.getElementById('textInput');
  var inputMeta = document.getElementById('inputMeta');

  var btnUpload = document.getElementById('btnUpload');
  var fileInput = document.getElementById('fileInput');
  var fileMeta = document.getElementById('fileMeta');
  var btnClear = document.getElementById('btnClear');

  var resultsPanel = document.getElementById('resultsPanel');
  var hashList = document.getElementById('hashList');
  var emptyState = document.getElementById('emptyState');

  var compareInput = document.getElementById('compareInput');
  var compareResult = document.getElementById('compareResult');
  var compareHint = document.getElementById('compareHint');

  var statusBadge = document.getElementById('statusBadge');
  var statusText = document.getElementById('statusText');

  var mode = 'text'; // 'text' | 'file'
  var currentFile = null;
  var lastHashes = {}; // { md5: '...', sha1: '...', ... }
  var runToken = 0; // guards against out-of-order async completions

  /* =================================================================
     STATUS
     ================================================================= */
  function setStatus(state, text) {
    statusBadge.classList.remove('is-valid', 'is-busy');
    if (state === 'valid') statusBadge.classList.add('is-valid');
    else if (state === 'busy') statusBadge.classList.add('is-busy');
    statusText.textContent = text;
  }

  /* =================================================================
     RESULTS RENDERING
     ================================================================= */
  function ensureRows() {
    if (hashList.children.length) return;
    var html = '';
    ALGOS.forEach(function (a) {
      html += '<div class="hash-row" data-algo="' + a.key + '">' +
        '<span class="hash-algo">' + a.label + '</span>' +
        '<span class="hash-value is-pending" id="val-' + a.key + '">—</span>' +
        '<button class="btn btn--sm" data-copy="' + a.key + '" title="Copy ' + a.label + '">Copy</button>' +
        '</div>';
    });
    hashList.innerHTML = html;
    hashList.querySelectorAll('[data-copy]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var key = btn.getAttribute('data-copy');
        var val = lastHashes[key];
        if (val) WUS.copy(val, ALGOS.filter(function (a) { return a.key === key; })[0].label + ' copied');
      });
    });
  }

  function setRowValue(key, value, pending) {
    var el = document.getElementById('val-' + key);
    if (!el) return;
    el.textContent = value;
    el.classList.toggle('is-pending', !!pending);
  }

  function clearResults() {
    lastHashes = {};
    resultsPanel.hidden = true;
    emptyState.hidden = false;
    updateCompare();
  }

  /* =================================================================
     HASHING PIPELINE
     ================================================================= */
  function hashBytes(bytes) {
    var token = ++runToken;
    ensureRows();
    resultsPanel.hidden = false;
    emptyState.hidden = true;
    lastHashes = {};
    ALGOS.forEach(function (a) { setRowValue(a.key, 'Computing…', true); });
    setStatus('busy', 'Hashing…');

    // MD5 runs synchronously (pure JS); run it first so it doesn't block SHA promises.
    try {
      var md5Val = md5Hex(bytes);
      if (token === runToken) {
        lastHashes.md5 = md5Val;
        setRowValue('md5', md5Val, false);
        updateCompare();
      }
    } catch (e) {
      if (token === runToken) setRowValue('md5', 'Error computing MD5', false);
    }

    var shaAlgos = ALGOS.filter(function (a) { return a.subtle; });
    var promises = shaAlgos.map(function (a) {
      return shaHex(a.subtle, bytes).then(function (hex) {
        if (token !== runToken) return;
        lastHashes[a.key] = hex;
        setRowValue(a.key, hex, false);
        updateCompare();
      }).catch(function () {
        if (token === runToken) setRowValue(a.key, 'Error computing ' + a.label, false);
      });
    });

    Promise.all(promises).then(function () {
      if (token === runToken) setStatus('valid', 'Done');
    });
  }

  function hashCurrentText() {
    var text = textInput.value;
    if (!text) { clearResults(); setStatus('', 'Ready'); return; }
    var bytes = new TextEncoder().encode(text);
    hashBytes(bytes);
  }

  function hashCurrentFile(file) {
    var reader = new FileReader();
    reader.onload = function () {
      hashBytes(new Uint8Array(reader.result));
    };
    reader.onerror = function () {
      WUS.toast('Could not read file', 'error');
      setStatus('', 'Ready');
    };
    reader.readAsArrayBuffer(file);
  }

  /* =================================================================
     COMPARE
     ================================================================= */
  function detectAlgoByLength(hex) {
    var clean = hex.trim().toLowerCase();
    var match = ALGOS.filter(function (a) { return a.len === clean.length; });
    return match.length ? match[0] : null;
  }

  function updateCompare() {
    var raw = compareInput.value.trim();
    if (!raw) { compareResult.hidden = true; compareHint.textContent = ''; return; }
    var clean = raw.replace(/\s+/g, '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(clean)) {
      compareResult.hidden = false;
      compareResult.className = 'badge badge--warning';
      compareResult.textContent = 'Not a hex hash';
      compareHint.textContent = '';
      return;
    }
    var algo = detectAlgoByLength(clean);
    if (!algo) {
      compareResult.hidden = false;
      compareResult.className = 'badge badge--warning';
      compareResult.textContent = 'Unrecognized hash length';
      compareHint.textContent = clean.length + ' hex chars doesn’t match MD5, SHA-1, SHA-256, SHA-384 or SHA-512.';
      return;
    }
    var computed = lastHashes[algo.key];
    compareResult.hidden = false;
    if (!computed) {
      compareResult.className = 'badge';
      compareResult.textContent = 'Waiting for ' + algo.label + '…';
      compareHint.textContent = 'Detected as ' + algo.label + ' by length (' + clean.length + ' hex chars).';
      return;
    }
    var isMatch = computed.toLowerCase() === clean;
    compareResult.className = 'badge ' + (isMatch ? 'badge--success' : 'badge--danger');
    compareResult.textContent = isMatch ? 'Match (' + algo.label + ')' : 'No match (' + algo.label + ')';
    compareHint.textContent = 'Detected as ' + algo.label + ' by length (' + clean.length + ' hex chars).';
  }

  /* =================================================================
     INPUT MODE (Text / File)
     ================================================================= */
  function setMode(next) {
    mode = next;
    var isText = mode === 'text';
    tabText.classList.toggle('is-active', isText);
    tabText.setAttribute('aria-selected', String(isText));
    tabFile.classList.toggle('is-active', !isText);
    tabFile.setAttribute('aria-selected', String(!isText));
    textPane.hidden = !isText;
    filePane.hidden = isText;
    if (isText) {
      hashCurrentText();
    } else if (currentFile) {
      hashCurrentFile(currentFile);
    } else {
      clearResults();
      setStatus('', 'Ready');
    }
    persist();
  }

  function updateInputMeta() {
    var len = textInput.value.length;
    inputMeta.textContent = mode === 'text' ? (len.toLocaleString() + (len === 1 ? ' char' : ' chars')) : '';
  }

  function humanBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(2) + ' MB';
  }

  /* =================================================================
     FILE HANDLING
     ================================================================= */
  function triggerUpload() { fileInput.click(); }

  fileInput.addEventListener('change', function () {
    var file = fileInput.files && fileInput.files[0];
    if (!file) return;
    currentFile = file;
    fileMeta.textContent = file.name + ' · ' + humanBytes(file.size);
    hashCurrentFile(file);
    fileInput.value = '';
  });

  /* =================================================================
     PERSISTENCE
     ================================================================= */
  function persist() {
    WUS.store.set(STORE_KEY, {
      mode: mode,
      text: textInput.value,
      compare: compareInput.value
    });
  }
  var persistDebounced = WUS.debounce(persist, 400);

  function restore() {
    var saved = WUS.store.get(STORE_KEY, null);
    if (!saved) { clearResults(); return; }
    if (typeof saved.text === 'string') textInput.value = saved.text;
    if (typeof saved.compare === 'string') compareInput.value = saved.compare;
    setMode('text'); // files aren't persisted across sessions
    updateInputMeta();
  }

  /* =================================================================
     CLEAR
     ================================================================= */
  function clearAll() {
    textInput.value = '';
    compareInput.value = '';
    currentFile = null;
    fileMeta.textContent = 'No file selected';
    clearResults();
    updateInputMeta();
    setStatus('', 'Ready');
    WUS.store.remove(STORE_KEY);
    if (mode === 'text') textInput.focus();
  }

  /* =================================================================
     SHORTCUTS HELP MODAL
     ================================================================= */
  var helpBackdrop = document.getElementById('helpBackdrop');
  var helpClose = document.getElementById('helpClose');
  var shortcutRows = document.getElementById('shortcutRows');

  var SHORTCUTS = [
    { keys: ['mod', 'Enter'], desc: 'Hash current text now' },
    { keys: ['?'], desc: 'Show this help' },
    { keys: ['Esc'], desc: 'Close dialog' }
  ];

  function buildShortcutTable() {
    var html = '';
    SHORTCUTS.forEach(function (s) {
      var kbds = s.keys.map(function (k) { return '<kbd>' + WUS.escapeHtml(k) + '</kbd>'; }).join('');
      html += '<tr><td>' + WUS.escapeHtml(s.desc) + '</td><td>' + kbds + '</td></tr>';
    });
    shortcutRows.innerHTML = html;
  }

  function openHelp() { helpBackdrop.hidden = false; helpClose.focus(); }
  function closeHelp() { helpBackdrop.hidden = true; }

  helpClose.addEventListener('click', closeHelp);
  helpBackdrop.addEventListener('click', function (e) { if (e.target === helpBackdrop) closeHelp(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !helpBackdrop.hidden) closeHelp();
  });
  var helpBtns = document.querySelectorAll('[data-shortcut-help]');
  for (var i = 0; i < helpBtns.length; i++) helpBtns[i].addEventListener('click', openHelp);

  /* =================================================================
     WIRING
     ================================================================= */
  tabText.addEventListener('click', function () { setMode('text'); });
  tabFile.addEventListener('click', function () { setMode('file'); });
  btnUpload.addEventListener('click', triggerUpload);
  btnClear.addEventListener('click', clearAll);

  var hashTextDebounced = WUS.debounce(hashCurrentText, 350);
  textInput.addEventListener('input', function () {
    updateInputMeta();
    persistDebounced();
    hashTextDebounced();
  });
  textInput.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      hashCurrentText();
    }
  });

  compareInput.addEventListener('input', function () {
    updateCompare();
    persistDebounced();
  });

  WUS.registerShortcut('mod+enter', function () { if (mode === 'text') hashCurrentText(); }, 'Hash current text');
  WUS.registerShortcut('?', function () { openHelp(); }, 'Show shortcuts');

  /* =================================================================
     INIT
     ================================================================= */
  buildShortcutTable();
  restore();
})();
