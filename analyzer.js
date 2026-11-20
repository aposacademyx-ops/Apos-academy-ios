/* ============================================================
   METHOD CHECK iOS — analysis engine
   Pure browser JavaScript, zero dependencies.
   Ported from the Python version with fixes:
     - ISO-8601 timestamps with .fraction / Z / ±hh:mm are parsed
     - all limits are enforced before text expansion
   ============================================================ */
(function () {
  'use strict';

  var MB = 1024 * 1024;

  var DEFAULTS = Object.freeze({
    maxUploadMB: 100,
    maxExpandedMB: 350,
    maxEntryMB: 60,
    maxFiles: 12000,
    maxTextMB: 100,
    maxResults: 500
  });

  var APP_NAMES = {
    'com.tigisoftware.filza': 'Filza',
    'com.dts.freefiremax': 'Free Fire MAX',
    'com.dts.freefireth': 'Free Fire',
    'com.ncs.gbox': 'GBox',
    'com.ncs.gboxts': 'GBox',
    'com.huami.trollfools': 'TrollFools',
    'com.opa334.dopamine1': 'Dopamine',
    'com.openai.chat': 'ChatGPT',
    'com.deepseek.chat': 'DeepSeek',
    'com.vpn.lat': 'VPN.lat',
    'com.apple.mobilesafari': 'Safari',
    'com.apple.Preferences': 'Settings',
    'com.discord': 'Discord',
    'com.burbn.instagram': 'Instagram',
    'com.zhiliaoapp.musically': 'TikTok',
    'com.google.ios.youtube': 'YouTube',
    'net.whatsapp.WhatsApp': 'WhatsApp'
  };

  var BUNDLE_SRC = '\\b(?:com|net|org|io|me|app|co|uk|edu|gov)\\.[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)+\\b';

  var DATE_SRCS = [
    '\\b20\\d{2}[-/]\\d{1,2}[-/]\\d{1,2}(?:[T ,]+\\d{2}:\\d{2}(?::\\d{2}(?:\\.\\d+)?)?(?:Z|[+-]\\d{2}:?\\d{2})?)?',
    '\\b\\d{1,2}[-/]\\d{1,2}[-/]20\\d{2}(?:[T ,]+\\d{2}:\\d{2}(?::\\d{2})?)?',
    '\\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+20\\d{2}\\b'
  ];

  var MONTHS = { Jan:1,Feb:2,Mar:3,Apr:4,May:5,Jun:6,Jul:7,Aug:8,Sep:9,Oct:10,Nov:11,Dec:12 };

  /* ------------------------------------------------------------
     Text helpers
     ------------------------------------------------------------ */

  var utf8 = new TextDecoder('utf-8');
  var utf16le = new TextDecoder('utf-16le');
  var utf16be = new TextDecoder('utf-16be');

  function printableRatio(s) {
    var n = Math.min(s.length, 10000);
    if (!n) return 0;
    var ok = 0;
    for (var i = 0; i < n; i++) {
      var c = s.charCodeAt(i);
      if ((c >= 32 && c !== 127) || c === 9 || c === 10 || c === 13) ok++;
    }
    return ok / n;
  }

  function toLatin1(u8) {
    var out = '';
    var CH = 0x8000;
    for (var i = 0; i < u8.length; i += CH) {
      out += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
    }
    return out;
  }

  function extractStrings(u8) {
    var capped = u8.length > 32 * MB ? u8.subarray(0, 32 * MB) : u8;
    var s = toLatin1(capped);
    var out = [];
    var a = s.match(/[\x20-\x7e]{5,}/g);
    if (a) out = out.concat(a);
    var b = s.match(/(?:[\x20-\x7e]\x00){5,}/g);
    if (b) {
      for (var i = 0; i < b.length; i++) out.push(b[i].replace(/\x00/g, ''));
    }
    if (out.length > 50000) out = out.slice(0, 50000);
    return out.join('\n');
  }

  function decodeText(u8) {
    var s = '';
    try { s = utf8.decode(u8); } catch (e) { s = ''; }
    if (printableRatio(s) > 0.72) return s;
    var s16 = '';
    try { s16 = utf16le.decode(u8); } catch (e) { s16 = ''; }
    if (printableRatio(s16) > 0.72) return s16;
    try { s16 = utf16be.decode(u8); } catch (e) { s16 = ''; }
    if (printableRatio(s16) > 0.72) return s16;
    return extractStrings(u8);
  }

  /* ------------------------------------------------------------
     SHA-256
     ------------------------------------------------------------ */

  var SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Hex(data) {
    var l = data.length;
    var padded = (((l + 9) + 63) >> 6) << 6;
    var buf = new Uint8Array(padded);
    buf.set(data);
    buf[l] = 0x80;
    var view = new DataView(buf.buffer);
    view.setUint32(padded - 8, Math.floor(l / 0x20000000), false);
    view.setUint32(padded - 4, (l << 3) >>> 0, false);

    var H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    var w = new Uint32Array(64);

    for (var off = 0; off < padded; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    var hex = '';
    for (i = 0; i < 8; i++) hex += ('00000000' + H[i].toString(16)).slice(-8);
    return hex;
  }

  function hasSubtle() {
    return typeof crypto !== 'undefined' && crypto && crypto.subtle && typeof crypto.subtle.digest === 'function';
  }

  async function sha256(u8) {
    if (hasSubtle()) {
      try {
        var d = await crypto.subtle.digest('SHA-256', u8);
        var bytes = new Uint8Array(d), out = '';
        for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
        return out;
      } catch (e) { /* fall through */ }
    }
    return sha256Hex(u8);
  }

  /* ------------------------------------------------------------
     Decompression
     ------------------------------------------------------------ */

  async function decompress(u8, format) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('DecompressionStream is not supported by this browser');
    }
    var stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream(format));
    var ab = await new Response(stream).arrayBuffer();
    return new Uint8Array(ab);
  }

  function endsWithAny(name, list) {
    for (var i = 0; i < list.length; i++) {
      if (name.slice(-list[i].length) === list[i]) return true;
    }
    return false;
  }

  /* ------------------------------------------------------------
     ZIP
     ------------------------------------------------------------ */

  function findEocd(u8) {
    var min = Math.max(0, u8.length - 65557);
    for (var i = u8.length - 22; i >= min; i--) {
      if (u8[i] === 0x50 && u8[i + 1] === 0x4b && u8[i + 2] === 0x05 && u8[i + 3] === 0x06) return i;
    }
    return -1;
  }

  function decodeEntryName(bytes, isUtf8) {
    try {
      return isUtf8 ? utf8.decode(bytes) : toLatin1(bytes);
    } catch (e) {
      return toLatin1(bytes);
    }
  }

  /* ------------------------------------------------------------
     TAR
     ------------------------------------------------------------ */

  function cstr(u8, start, len) {
    var end = start + len;
    if (end > u8.length) end = u8.length;
    var k = start;
    while (k < end && u8[k] !== 0) k++;
    return toLatin1(u8.subarray(start, k));
  }

  function isTar(u8) {
    if (u8.length < 512) return false;
    return cstr(u8, 257, 5) === 'ustar';
  }

  function parseOctal(str) {
    var s = String(str).replace(/[^0-7]/g, '');
    return s ? parseInt(s, 8) : 0;
  }

  /* ------------------------------------------------------------
     XML property list (DOMParser is unavailable in some contexts,
     so this is a tiny tag scanner)
     ------------------------------------------------------------ */

  function xmlUnescape(s) {
    return s
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); })
      .replace(/&#(\d+);/g, function (_, d) { return String.fromCodePoint(parseInt(d, 10)); })
      .replace(/&amp;/g, '&');
  }

  function tokenizeXml(xml) {
    var toks = [];
    var re = /<[^>]*>/g;
    var last = 0, m;
    while ((m = re.exec(xml)) !== null) {
      if (m.index > last) {
        var text = xml.slice(last, m.index);
        if (/\S/.test(text)) toks.push({ tag: null, text: text });
      }
      toks.push({ tag: m[0], text: null });
      last = re.lastIndex;
    }
    if (last < xml.length) {
      var tail = xml.slice(last);
      if (/\S/.test(tail)) toks.push({ tag: null, text: tail });
    }
    return toks;
  }

  function parseXmlPlist(xml) {
    var toks = tokenizeXml(xml);
    var i = 0;

    function nextTag() {
      while (i < toks.length) {
        var t = toks[i++];
        if (!t.tag) continue;
        if (t.tag.indexOf('<?') === 0 || t.tag.indexOf('<!') === 0) continue;
        var raw = t.tag;
        var closing = raw.indexOf('</') === 0;
        var selfClosing = /\/>$/.test(raw);
        var inner = raw.replace(/^<\/?/, '').replace(/\/?>$/, '').trim();
        var name = inner.split(/[\s>]/)[0];
        return { name: name, closing: closing, selfClosing: selfClosing, raw: raw };
      }
      return null;
    }

    function readTextUntilClose(name) {
      var parts = [];
      while (i < toks.length) {
        var t = toks[i];
        if (t.tag) {
          if (t.tag.indexOf('</' + name) === 0) { i++; return parts.join(''); }
          // Unexpected tag inside text: stop so the caller can continue.
          return parts.join('');
        }
        parts.push(t.text);
        i++;
      }
      return parts.join('');
    }

    function readValue() {
      var t = nextTag();
      if (!t) return undefined;
      if (t.closing) return undefined;

      var name = t.name;

      if (name === 'plist') {
        if (t.selfClosing) return null;
        return readValue();
      }

      if (name === 'dict') {
        var obj = {};
        if (t.selfClosing) return obj;
        while (true) {
          var kt = nextTag();
          if (!kt) break;
          if (kt.closing && kt.name === 'dict') break;
          if (kt.name !== 'key') continue;
          var key = kt.selfClosing ? '' : readTextUntilClose('key');
          var val = readValue();
          obj[xmlUnescape(key)] = (val === undefined ? '' : val);
        }
        return obj;
      }

      if (name === 'array') {
        var arr = [];
        if (t.selfClosing) return arr;
        while (true) {
          var save = i;
          var nt = nextTag();
          if (!nt) break;
          if (nt.closing && nt.name === 'array') break;
          i = save; // rewind, readValue consumes the tag itself
          var v = readValue();
          if (v === undefined) break;
          arr.push(v);
        }
        return arr;
      }

      var body = t.selfClosing ? '' : readTextUntilClose(name);
      if (name === 'true') return true;
      if (name === 'false') return false;
      if (name === 'string') return xmlUnescape(body);
      if (name === 'integer') {
        var iv = parseInt(body.trim(), 10);
        return isNaN(iv) ? 0 : iv;
      }
      if (name === 'real') {
        var rv = parseFloat(body.trim());
        return isNaN(rv) ? 0 : rv;
      }
      if (name === 'date') return body.trim();
      if (name === 'data') {
        var b64 = body.replace(/\s+/g, '');
        return '[base64 data: ' + Math.round(b64.length * 3 / 4) + ' bytes]';
      }
      return xmlUnescape(body);
    }

    try {
      return readValue();
    } catch (e) {
      return null;
    }
  }

  /* ------------------------------------------------------------
     Binary property list
     ------------------------------------------------------------ */

  function readUint(dv, at, size) {
    var v = 0;
    for (var i = 0; i < size; i++) v = v * 256 + dv.getUint8(at + i);
    return v;
  }

  function parseBinaryPlist(bytes) {
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 40) throw new Error('binary plist too short');

    var trailer = bytes.length - 32;
    var offsetSize = bytes[trailer + 6];
    var refSize = bytes[trailer + 7];
    var numObjects = readUint(dv, trailer + 8, 8);
    var topObject = readUint(dv, trailer + 16, 8);
    var offsetTableOffset = readUint(dv, trailer + 24, 8);

    if (!offsetSize || !refSize || !numObjects || offsetTableOffset >= bytes.length) {
      throw new Error('invalid binary plist trailer');
    }
    if (numObjects > 500000) throw new Error('binary plist too large');

    var offsets = new Array(numObjects);
    for (var i = 0; i < numObjects; i++) {
      offsets[i] = readUint(dv, offsetTableOffset + i * offsetSize, offsetSize);
    }

    function objectAt(idx, depth) {
      if (depth > 60 || idx < 0 || idx >= numObjects) return null;
      var off = offsets[idx];
      if (off >= bytes.length) return null;
      var marker = bytes[off];
      var type = marker >> 4;
      var info = marker & 0x0f;
      var pos = off + 1;
      var length = info;

      if (info === 0x0f) {
        var m2 = bytes[pos++];
        var exp = m2 & 0x0f;
        var size = 1 << exp;
        length = readUint(dv, pos, size);
        pos += size;
      }
      if (length > 50000000) return null;

      switch (type) {
        case 0x0:
          if (marker === 0x08) return false;
          if (marker === 0x09) return true;
          return null;

        case 0x1: {
          var nbytes = 1 << info;
          if (nbytes > 8) return 0;
          var iv = readUint(dv, pos, nbytes);
          if (nbytes === 8 && (bytes[pos] & 0x80)) iv -= 0x10000000000000000;
          return iv;
        }

        case 0x2: {
          if (info === 2) return dv.getFloat32(pos, false);
          if (info === 3) return dv.getFloat64(pos, false);
          return 0;
        }

        case 0x3: {
          var secs = dv.getFloat64(pos, false);
          var ms = Date.UTC(2001, 0, 1) + secs * 1000;
          try { return new Date(ms).toISOString(); } catch (e) { return String(secs); }
        }

        case 0x4: {
          // data blobs are bytes, not characters. Only show them when they are
          // genuinely valid UTF-8 text; otherwise show a clean size marker.
          var dlen = Math.min(length, 8192);
          var s = '';
          try { s = utf8.decode(bytes.subarray(pos, pos + dlen)); } catch (e) { s = ''; }
          if (s && s.indexOf('\ufffd') === -1 && printableRatio(s) > 0.9) return s;
          return '[binary data: ' + length + ' bytes]';
        }

        case 0x5:
          return utf8.decode(bytes.subarray(pos, pos + length));

        case 0x6: {
          var out = '';
          for (var k = 0; k < length; k++) {
            out += String.fromCharCode((bytes[pos + k * 2] << 8) | bytes[pos + k * 2 + 1]);
          }
          return out;
        }

        case 0x8:
          return readUint(dv, pos, info + 1);

        case 0xA:
        case 0xB: {
          var arr = [];
          for (var a = 0; a < length; a++) {
            arr.push(objectAt(readUint(dv, pos + a * refSize, refSize), depth + 1));
          }
          return arr;
        }

        case 0xC:
        case 0xD: {
          var obj = {};
          var keysBase = pos;
          var valsBase = pos + length * refSize;
          for (var q = 0; q < length; q++) {
            var key = objectAt(readUint(dv, keysBase + q * refSize, refSize), depth + 1);
            var val = objectAt(readUint(dv, valsBase + q * refSize, refSize), depth + 1);
            obj[String(key)] = val;
          }
          return obj;
        }

        default:
          return null;
      }
    }

    return objectAt(topObject, 0);
  }

  function safeObj(obj, depth) {
    depth = depth || 0;
    if (depth > 12) return '[depth limit]';
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') return obj.length > 2000 ? obj.slice(0, 2000) + '…' : obj;
    if (typeof obj === 'number' || typeof obj === 'boolean') return obj;
    if (Array.isArray(obj)) {
      var arr = [];
      var n = Math.min(obj.length, 5000);
      for (var i = 0; i < n; i++) arr.push(safeObj(obj[i], depth + 1));
      return arr;
    }
    if (typeof obj === 'object') {
      var out = {};
      var keys = Object.keys(obj);
      var limit = Math.min(keys.length, 5000);
      for (var k = 0; k < limit; k++) out[keys[k]] = safeObj(obj[keys[k]], depth + 1);
      return out;
    }
    return String(obj);
  }

  /* ------------------------------------------------------------
     Dates
     ------------------------------------------------------------ */

  function two(n) { return (n < 10 ? '0' : '') + n; }

  function fmtDate(y, mo, d, h, mi, se) {
    var out = y + '-' + two(+mo) + '-' + two(+d);
    if (h !== undefined && h !== null && h !== '') {
      out += ' ' + two(+h) + ':' + two(+mi);
      if (se !== undefined && se !== null && se !== '') out += ':' + two(+se);
    }
    return out;
  }

  function parseDateToken(raw) {
    var s = String(raw).replace(/[T,]/g, ' ').replace(/\s+/g, ' ').trim();
    var m = s.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?: (\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/);
    if (m) return fmtDate(m[1], m[2], m[3], m[4], m[5], m[6]);
    m = s.match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{4})(?: (\d{1,2}):(\d{2})(?::(\d{2}))?)?$/);
    if (m) return fmtDate(m[3], m[1], m[2], m[4], m[5], m[6]);
    return null;
  }

  function closestDate(text) {
    var hay = text.length > 4000 ? text.slice(0, 4000) : text;
    var best = null, bestIdx = Infinity;
    for (var r = 0; r < DATE_SRCS.length; r++) {
      var re = new RegExp(DATE_SRCS[r], 'g');
      var m;
      while ((m = re.exec(hay)) !== null) {
        var parsed = parseDateToken(m[0]);
        if (parsed && m.index < bestIdx) {
          bestIdx = m.index;
          best = parsed;
        }
        if (m.index > bestIdx) break;
      }
    }
    return best;
  }

  /* ------------------------------------------------------------
     Artifact rules
     ------------------------------------------------------------ */

  var RULES = [
    ['PROXY / DNS NETWORK', 'Proxy or DNS configuration',
      'proxy(?:\\.pac|settings|configuration|server)?|http_proxy|https_proxy|socks_proxy|dns',
      'Network configuration may be legitimate; this alone does not establish compromise or jailbreak.'],
    ['IPA / SIDELOADING', 'IPA / TIPA package',
      '\\.ipa\\b|\\.tipa\\b|embedded\\.mobileprovision',
      'A package reference does not prove that installation completed.'],
    ['FILE MANAGER', 'Filza',
      'filza|com\\.tigisoftware\\.filza',
      'A name or bundle reference requires a matching installation record.'],
    ['SIDELOAD / SIGNING', 'GBox',
      '\\bgbox\\b|com\\.ncs\\.gbox',
      'A tool reference is not proof it is installed or was used.'],
    ['SIDELOAD / SIGNING', 'eSign',
      '\\besign\\b|esigncert|khoindvn',
      'A name match alone is weak evidence.'],
    ['SIDELOAD / SIGNING', 'TrollStore',
      'trollstore|persistencehelper',
      'A reference does not prove an active installation.'],
    ['APP MODIFICATION', 'TrollFools',
      'troll.?fools|com\\.huami\\.trollfools',
      'Inspect exact source and event type.'],
    ['JAILBREAK INDICATOR', 'Dopamine / jailbreak ecosystem',
      'dopamine|ellekit|procursus|org\\.coolstar\\.sileo',
      'Ecosystem strings can occur in copied files or archives; corroborate independently.'],
    ['ICLOUD / FILE PROVIDER', 'brctl / iCloud Drive',
      'brctl|com\\.apple\\.brctl|fileprovider|ubiquity|cloudd',
      'These records often describe iCloud or file-provider activity, not app installation.'],
    ['APPLICATION DATA', 'MobileInstallation',
      'mobileinstallation|mobile_installed|applicationstate|applicationidentifier',
      'Interpret only with the specific Bundle ID, event and associated timestamp.']
  ];

  var RULE_RES = RULES.map(function (r) { return new RegExp(r[2], 'gi'); });

  /* ------------------------------------------------------------
     Analyzer
     ------------------------------------------------------------ */

  function Analyzer(options) {
    this.limits = Object.assign({}, DEFAULTS, options || {});
    this.maxUpload = this.limits.maxUploadMB * MB;
    this.maxExpanded = this.limits.maxExpandedMB * MB;
    this.maxEntry = this.limits.maxEntryMB * MB;
    this.maxFiles = this.limits.maxFiles;
    this.maxText = this.limits.maxTextMB * MB;
    this.maxResults = this.limits.maxResults;

    this.records = [];
    this.files = [];
    this.warnings = [];
    this.totalBytes = 0;
    this.fileCount = 0;
    this.onProgress = null;
    this._limitWarned = { files: false, bytes: false };
    this._lastTick = Date.now();
  }

  Analyzer.prototype._warn = function (msg) {
    if (this.warnings.length < 400) this.warnings.push(msg);
  };

  Analyzer.prototype._tick = async function () {
    this._lastTick = Date.now();
    if (this.onProgress) this.onProgress({ files: this.fileCount, bytes: this.totalBytes });
    // Yield to the UI thread so the page stays responsive.
    await new Promise(function (r) { setTimeout(r, 0); });
  };

  Analyzer.prototype._maybeTick = async function () {
    if (Date.now() - this._lastTick > 200) await this._tick();
  };

  Analyzer.prototype.addBytes = async function (name, u8) {
    if (this.fileCount >= this.maxFiles) {
      if (!this._limitWarned.files) {
        this._limitWarned.files = true;
        this._warn('Archive file-count limit reached (' + this.maxFiles + '); remaining entries were skipped.');
      }
      return;
    }
    if (u8.length > this.maxEntry) {
      this._warn(name + ': skipped; entry exceeds ' + this.limits.maxEntryMB + ' MB.');
      return;
    }
    this.totalBytes += u8.length;
    if (this.totalBytes > this.maxExpanded) {
      if (!this._limitWarned.bytes) {
        this._limitWarned.bytes = true;
        this._warn('Expanded-data limit reached (' + this.limits.maxExpandedMB + ' MB); remaining entries were skipped.');
      }
      return;
    }
    this.fileCount++;

    var hash = await sha256(u8);
    var lower = name.toLowerCase();
    var kind = 'binary';

    if (lower.slice(-6) === '.plist' || lower.slice(-13) === '.mobileconfig' ||
        (u8.length > 8 && u8[0] === 0x62 && u8[1] === 0x70 && u8[2] === 0x6c && u8[3] === 0x69)) {
      var pt = this.plistText(u8);
      if (pt) {
        kind = 'plist';
        this.files.push({ path: name, size: u8.length, sha256: hash, kind: kind });
        this._pushRecord(name, pt);
        return;
      }
    }

    if (lower.slice(-3) === '.db' || lower.indexOf('.sqlite') !== -1) {
      kind = 'sqlite';
      this._warn(name + ': SQLite binary detected — readable strings were extracted (full table parsing is not available in the browser build).');
      var st = extractStrings(u8);
      this.files.push({ path: name, size: u8.length, sha256: hash, kind: kind });
      this._pushRecord(name, st);
      return;
    }

    var text = decodeText(u8);
    kind = printableRatio(text) > 0.5 ? 'text' : 'binary';
    this.files.push({ path: name, size: u8.length, sha256: hash, kind: kind });
    if (text && /\S/.test(text)) {
      this._pushRecord(name, text);
    } else {
      this._warn(name + ': no readable text or supported structured data found.');
    }
  };

  Analyzer.prototype._pushRecord = function (name, text) {
    if (!text || !/\S/.test(text)) {
      this._warn(name + ': no readable text found.');
      return;
    }
    if (text.length > this.maxText) {
      this._warn(name + ': text truncated to ' + this.limits.maxTextMB + ' MB.');
      text = text.slice(0, this.maxText);
    }
    this.records.push({ name: name, text: text.replace(/\r\n?/g, '\n') });
  };

  Analyzer.prototype.plistText = function (u8) {
    try {
      var obj;
      var isBinary = u8.length > 6 && u8[0] === 0x62 && u8[1] === 0x70 && u8[2] === 0x6c && u8[3] === 0x69;
      if (isBinary) obj = parseBinaryPlist(u8);
      else obj = parseXmlPlist(utf8.decode(u8));
      if (obj === null || obj === undefined) return '';
      return JSON.stringify(safeObj(obj), null, 2);
    } catch (e) {
      return '';
    }
  };

  Analyzer.prototype.readZip = async function (u8, baseName, depth) {
    var eocd = findEocd(u8);
    if (eocd < 0) {
      this._warn(baseName + ': ZIP end-of-central-directory not found.');
      return;
    }
    var dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    var count = dv.getUint16(eocd + 10, true);
    var cdOffset = dv.getUint32(eocd + 16, true);

    if (count === 0xffff || cdOffset === 0xffffffff) {
      this._warn(baseName + ': ZIP64 archives are not supported by this build.');
      return;
    }
    if (cdOffset >= u8.length) {
      this._warn(baseName + ': invalid ZIP central directory offset.');
      return;
    }

    var p = cdOffset;
    for (var i = 0; i < count; i++) {
      if (this.fileCount >= this.maxFiles || this.totalBytes >= this.maxExpanded) break;
      if (p + 46 > u8.length) break;
      if (dv.getUint32(p, true) !== 0x02014b50) break;

      var flags = dv.getUint16(p + 8, true);
      var method = dv.getUint16(p + 10, true);
      var csize = dv.getUint32(p + 20, true);
      var usize = dv.getUint32(p + 24, true);
      var nameLen = dv.getUint16(p + 28, true);
      var extraLen = dv.getUint16(p + 30, true);
      var commentLen = dv.getUint16(p + 32, true);
      var localOff = dv.getUint32(p + 42, true);

      var nameBytes = u8.subarray(p + 46, p + 46 + nameLen);
      var entryName = decodeEntryName(nameBytes, !!(flags & 0x800));
      var entryPath = baseName + '/' + entryName;
      p += 46 + nameLen + extraLen + commentLen;

      // AppleDouble / resource-fork metadata is binary junk, not iOS evidence.
      if (/^__MACOSX\//i.test(entryName) || /(?:^|\/)\._/i.test(entryName)) continue;
      if (entryName.slice(-1) === '/' || usize === 0) continue;
      if (flags & 0x1) { this._warn(entryPath + ': encrypted entry skipped.'); continue; }
      if (usize > this.maxEntry) {
        this._warn(entryPath + ': skipped; entry exceeds ' + this.limits.maxEntryMB + ' MB.');
        continue;
      }
      if (localOff + 30 > u8.length) { this._warn(entryPath + ': invalid local header offset.'); continue; }
      if (dv.getUint32(localOff, true) !== 0x04034b50) { this._warn(entryPath + ': invalid local header.'); continue; }

      var lNameLen = dv.getUint16(localOff + 26, true);
      var lExtraLen = dv.getUint16(localOff + 28, true);
      var dataStart = localOff + 30 + lNameLen + lExtraLen;
      if (dataStart + csize > u8.length) { this._warn(entryPath + ': entry data out of bounds.'); continue; }

      var comp = u8.subarray(dataStart, dataStart + csize);
      var data;
      try {
        if (method === 0) data = comp;
        else if (method === 8) data = await decompress(comp, 'deflate-raw');
        else { this._warn(entryPath + ': unsupported compression method ' + method + '.'); continue; }
      } catch (e) {
        this._warn(entryPath + ': decompression failed (' + (e && e.message ? e.message : e) + ').');
        continue;
      }

      if (usize && data.length !== usize) {
        this._warn(entryPath + ': size mismatch after decompression (' + data.length + ' != ' + usize + ').');
      }
      try {
        await this.ingest(entryPath, data, depth + 1);
      } catch (e) {
        this._warn(entryPath + ': extraction failed (' + (e && e.message ? e.message : e) + ').');
      }
    }
  };

  Analyzer.prototype.readTar = async function (u8, baseName, depth) {
    var off = 0;
    while (off + 512 <= u8.length) {
      if (this.fileCount >= this.maxFiles) break;
      var header = u8.subarray(off, off + 512);
      var allZero = true;
      for (var z = 0; z < header.length; z++) { if (header[z] !== 0) { allZero = false; break; } }
      if (allZero) break;

      var name = cstr(header, 0, 100);
      var prefix = cstr(header, 345, 155);
      var size = parseOctal(cstr(header, 124, 12));
      var type = header[156] ? String.fromCharCode(header[156]) : '0';
      var full = prefix ? prefix + '/' + name : name;
      off += 512;

      if (!size || off + size > u8.length) {
        off += Math.ceil(size / 512) * 512;
        continue;
      }
      if (type === '0' || type === '\u0000' || type === '7') {
        if (size > this.maxEntry) {
          this._warn(baseName + '/' + full + ': skipped oversized entry.');
        } else {
          try { await this.ingest(baseName + '/' + full, u8.subarray(off, off + size), depth + 1); }
          catch (e) { this._warn(baseName + '/' + full + ': extraction failed.'); }
        }
      }
      off += Math.ceil(size / 512) * 512;
    }
  };

  Analyzer.prototype.ingest = async function (name, u8, depth) {
    depth = depth || 0;
    await this._maybeTick();
    if (depth > 4) { this._warn(name + ': nested archive depth limit reached.'); return; }
    if (depth === 0 && u8.length > this.maxUpload) {
      this._warn(name + ': upload exceeds configured limit (' + this.limits.maxUploadMB + ' MB).');
      return;
    }

    var lower = name.toLowerCase();
    var isZipMagic = u8.length > 4 && u8[0] === 0x50 && u8[1] === 0x4b &&
      (u8[2] === 0x03 || u8[2] === 0x05 || u8[2] === 0x07);

    if (isZipMagic || endsWithAny(lower, ['.zip', '.ipa', '.tipa'])) {
      await this.readZip(u8, name, depth);
      return;
    }

    if ((u8.length > 2 && u8[0] === 0x1f && u8[1] === 0x8b) || endsWithAny(lower, ['.gz', '.gzip'])) {
      try {
        var inner = await decompress(u8, 'gzip');
        var innerName = endsWithAny(lower, ['.gz']) ? name.slice(0, -3) : name + '.gunzipped';
        await this.ingest(innerName, inner, depth + 1);
        return;
      } catch (e) {
        this._warn(name + ': GZIP extraction failed (' + (e && e.message ? e.message : e) + ').');
      }
    }

    if (isTar(u8) || endsWithAny(lower, ['.tar'])) {
      await this.readTar(u8, name, depth);
      return;
    }

    await this.addBytes(name, u8);
  };

  /* ------------------------- analysis ------------------------- */

  Analyzer.prototype.analyze = function () {
    var self = this;
    var apps = new Map();
    var findings = [];
    var timeline = [];
    var dns = [], vpn = [], profiles = [], certs = [], icloud = [];
    var bundleRe = new RegExp(BUNDLE_SRC, 'gi');
    var max = this.maxResults;

    for (var ri = 0; ri < this.records.length; ri++) {
      var source = this.records[ri].name;
      var text = this.records[ri].text;

      var m;
      bundleRe.lastIndex = 0;
      while ((m = bundleRe.exec(text)) !== null) {
        var bundle = m[0].replace(/[.,;:]+$/, '');
        if (bundle.length > 220) continue;
        var ctx = this._context(text, m.index, m.index + m[0].length);
        var action = this._classify(ctx, source, bundle);
        var dt = closestDate(ctx);
        var status = action || 'EVIDENCE';
        var key = bundle.toLowerCase() + '|' + status + '|' + (dt || '');
        if (!apps.has(key)) {
          apps.set(key, {
            name: APP_NAMES[bundle] || bundle.split('.').pop(),
            bundle_id: bundle,
            status: status,
            time: dt || 'Not available',
            source: source,
            reason: this._reason(status, ctx),
            evidence: ctx.slice(0, 650),
            confidence: status === 'EVIDENCE' ? 'LOW' : 'MEDIUM'
          });
        }
        if (action) {
          timeline.push({ time: dt || 'Not available', source: source, kind: 'APP ' + action, context: ctx.slice(0, 400) });
        }
      }

      var lines = text.split('\n');
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        var l = line.toLowerCase().trim();
        if (!l) continue;
        var ldt = closestDate(line);
        if (/\bdns[a-z]*\b|resolver|qname/i.test(l)) {
          dns.push({ source: source, time: ldt || 'Not available', line: line.slice(0, 350) });
        }
        if (containsAny(l, ['vpn', 'networkextension', 'proxy.pac', 'http_proxy', 'socks_proxy', 'proxy server'])) {
          vpn.push({ source: source, time: ldt || 'Not available', line: line.slice(0, 350) });
        }
        if (containsAny(l, ['mobileconfig', 'payloadidentifier', 'payloadtype', 'configuration profile', 'mdm'])) {
          profiles.push({ source: source, time: ldt || 'Not available', line: line.slice(0, 350) });
        }
        if (containsAny(l, ['certificate', 'trust settings', 'provisioningprofile', 'embedded.mobileprovision'])) {
          certs.push({ source: source, time: ldt || 'Not available', line: line.slice(0, 350) });
        }
        if (containsAny(l, ['brctl', 'cloudd', 'bird:', 'fileprovider', 'ubiquity', 'icloud'])) {
          icloud.push({ source: source, time: ldt || 'Not available', line: line.slice(0, 350) });
        }
        if (ldt && containsAny(l, ['install', 'uninstall', 'remove', 'revok', 'profile', 'vpn', 'proxy', 'dns', 'brctl', 'mobileinstallation'])) {
          timeline.push({ time: ldt, source: source, kind: 'SYSTEM EVENT', context: line.slice(0, 400) });
        }
      }

      findings = findings.concat(this._artifactFindings(source, text));
    }

    var totalApps = apps.size;
    var appList = Array.from(apps.values()).slice(0, max);
    var seenEvents = new Set();
    var uniqueTimeline = [];
    for (var t = 0; t < timeline.length; t++) {
      var ev = timeline[t];
      var ek = ev.time + '\u0000' + ev.source + '\u0000' + ev.kind + '\u0000' + ev.context;
      if (!seenEvents.has(ek)) { seenEvents.add(ek); uniqueTimeline.push(ev); }
    }
    timeline = uniqueTimeline;
    timeline.sort(function (a, b) { return sortKey(a.time) < sortKey(b.time) ? -1 : sortKey(a.time) > sortKey(b.time) ? 1 : 0; });

    return {
      apps: appList,
      findings: dedupe(findings).slice(0, max),
      timeline: timeline.slice(0, max),
      dns: dns.slice(0, max),
      vpn: vpn.slice(0, max),
      profiles: profiles.slice(0, max),
      certificates: certs.slice(0, max),
      icloud: icloud.slice(0, max),
      totalApps: totalApps,
      logs: this.records.map(function (rec, i) {
        return {
          index: i,
          source: rec.name,
          text: rec.text,
          characters: rec.text.length,
          lines: countLines(rec.text)
        };
      }),
      files: this.files.slice(0, 20000),
      warnings: this.warnings,
      stats: {
        files: this.fileCount,
        bytes: this.totalBytes,
        records: this.records.length
      }
    };
  };

  function containsAny(hay, needles) {
    for (var i = 0; i < needles.length; i++) {
      if (hay.indexOf(needles[i]) !== -1) return true;
    }
    return false;
  }

  function sortKey(t) {
    return (!t || t === 'Not available') ? '9999' : t;
  }

  function countLines(s) {
    var n = 1;
    for (var i = 0; i < s.length; i++) { if (s.charCodeAt(i) === 10) n++; }
    return n;
  }

  function dedupe(items) {
    var seen = new Set();
    var out = [];
    for (var i = 0; i < items.length; i++) {
      var x = items[i];
      var k = x.name + '\u0000' + x.source + '\u0000' + String(x.matched).toLowerCase();
      if (!seen.has(k)) { seen.add(k); out.push(x); }
    }
    return out;
  }

  Analyzer.prototype._context = function (text, start, end) {
    var a = Math.max(0, start - 450);
    var b = Math.min(text.length, end + 450);
    return text.slice(a, b).replace(/\x00/g, ' ').replace(/[ \t]+/g, ' ');
  };

  function lineOf(text, index) {
    var a = text.lastIndexOf('\n', index);
    var b = text.indexOf('\n', index);
    return text.slice(a + 1, b === -1 ? text.length : b);
  }

  function lineHasOtherBundle(line, bundle) {
    var re = new RegExp(BUNDLE_SRC, 'gi');
    var target = String(bundle).toLowerCase();
    var m;
    while ((m = re.exec(line)) !== null) {
      if (m[0].replace(/[.,;:]+$/, '').toLowerCase() !== target) return true;
    }
    return false;
  }

  Analyzer.prototype._classify = function (ctx, source, bundle) {
    var hay = ctx + '\n' + source;

    function hasKeyword(re) {
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(hay)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (!lineHasOtherBundle(lineOf(hay, m.index), bundle)) return true;
      }
      return false;
    }

    if (hasKeyword(/\b(?:app\s+not\s+installed|not\s+installed)\b/gi)) return 'NOT INSTALLED';
    if (hasKeyword(/\b(?:installation\s+failed|install\s+failed|sync\s+disabled)\b/gi)) return null;
    if (hasKeyword(/\b(?:revoked|revoke|revocation)\b/gi)) return 'REVOKED';
    if (hasKeyword(/\b(?:uninstalled|uninstall|removed|remove|deleted|delete)\b/gi)) return 'REMOVED';
    if (hasKeyword(/\b(?:installed|installation\s+(?:succeeded|complete|completed)|install\s+(?:succeeded|complete|completed))\b/gi)) return 'INSTALLED';
    return null;
  };

  Analyzer.prototype._reason = function (status, ctx) {
    if (status === 'INSTALLED') return 'Explicit installation-related wording is present in the same local evidence context; verify the original record.';
    if (status === 'REMOVED') return 'Removal-related wording is present in the same local evidence context.';
    if (status === 'REVOKED') return 'Revocation-related wording is present in the same local evidence context.';
    if (status === 'NOT INSTALLED') return 'The supplied record explicitly indicates that the app was not installed.';
    return 'Bundle identifier found in supplied evidence; installation is not confirmed.';
  };

  Analyzer.prototype._artifactFindings = function (source, text) {
    var hay = source + '\n' + text;
    var out = [];

    for (var r = 0; r < RULES.length; r++) {
      var rule = RULES[r];
      var re = RULE_RES[r];
      re.lastIndex = 0;
      var count = 0;
      var m;
      while ((m = re.exec(hay)) !== null && count < 1) {
        var ctx = this._context(hay, m.index, m.index + m[0].length);
        out.push({
          name: rule[1],
          category: rule[0],
          confidence: (rule[0] === 'APPLICATION DATA' || rule[0] === 'ICLOUD / FILE PROVIDER') ? 'MEDIUM' : 'LOW',
          source: source,
          matched: m[0],
          context: ctx.slice(0, 450),
          note: rule[3]
        });
        count++;
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    return out;
  };

  /* ------------------------------------------------------------
     Report
     ------------------------------------------------------------ */

  function buildTextReport(result, analyzer) {
    var lines = [];
    lines.push('METHOD CHECK iOS — APOS ACADEMY');
    lines.push('FORENSIC EVIDENCE REPORT');
    lines.push('Generated UTC: ' + new Date().toISOString());
    lines.push('');
    lines.push('QUICK SUMMARY');
    lines.push('Files processed: ' + analyzer.fileCount);
    lines.push('Applications found: ' + result.apps.length);
    lines.push('Installed: ' + result.apps.filter(function (a) { return a.status === 'INSTALLED'; }).length +
      ' | Removed: ' + result.apps.filter(function (a) { return a.status === 'REMOVED'; }).length +
      ' | Revoked: ' + result.apps.filter(function (a) { return a.status === 'REVOKED'; }).length +
      ' | Reference only: ' + result.apps.filter(function (a) { return a.status === 'EVIDENCE'; }).length);
    lines.push('Logs / text records: ' + result.logs.length);
    lines.push('Warnings: ' + result.warnings.length);
    lines.push('');
    lines.push('IMPORTANT: Findings describe only the supplied evidence. A Bundle ID or app-name match alone does not prove installation.');
    lines.push('Files processed: ' + analyzer.fileCount);
    lines.push('Expanded bytes processed: ' + analyzer.totalBytes);
    lines.push('Unique source records: ' + analyzer.records.length);
    lines.push('');

    var sections = [
      ['APPLICATIONS', result.apps],
      ['FORENSIC ARTIFACTS', result.findings],
      ['TIMELINE', result.timeline],
      ['DNS', result.dns],
      ['VPN / PROXY', result.vpn],
      ['PROFILES / MDM', result.profiles],
      ['CERTIFICATES', result.certificates],
      ['BRCTL / ICLOUD', result.icloud]
    ];

    for (var s = 0; s < sections.length; s++) {
      var title = sections[s][0];
      var items = sections[s][1];
      lines.push('');
      lines.push('=== ' + title + ' (' + items.length + ') ===');
      for (var i = 0; i < items.length; i++) {
        lines.push(JSON.stringify(items[i]));
      }
    }

    lines.push('');
    lines.push('=== LOG SOURCES (full text is in the .json export and the Logs tab) ===');
    for (var lg = 0; lg < result.logs.length; lg++) {
      var L = result.logs[lg];
      lines.push(L.source + ' | ' + L.characters + ' chars | ' + L.lines + ' lines');
    }

    lines.push('');
    lines.push('=== SHA-256 ===');
    for (var f = 0; f < result.files.length; f++) {
      lines.push(result.files[f].sha256 + '  ' + result.files[f].path);
    }

    lines.push('');
    lines.push('=== WARNINGS ===');
    if (result.warnings.length) {
      for (var w = 0; w < result.warnings.length; w++) lines.push('- ' + result.warnings[w]);
    } else {
      lines.push('None');
    }

    return lines.join('\n');
  }

  window.MCAnalyzer = {
    Analyzer: Analyzer,
    DEFAULTS: DEFAULTS,
    buildTextReport: buildTextReport,
    version: '1.0.0'
  };
})();
