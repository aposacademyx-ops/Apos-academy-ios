/* METHOD CHECK iOS — simple UI controller */
(function () {
  'use strict';

  var A = window.MCAnalyzer;
  var $ = function (s) { return document.querySelector(s); };

  /* password gate */
  (function () {
    var gate = $('#gate');
    if (!gate) return;
    var pass = $('#gatePass');
    var btn = $('#gateBtn');
    var err = $('#gateErr');
    function unlock() {
      if (pass.value === 'hext') {
        gate.style.display = 'none';
        document.body.style.overflow = '';
        try { sessionStorage.setItem('mc_unlocked', '1'); } catch (e) {}
      } else {
        err.hidden = false;
        pass.value = '';
        pass.focus();
      }
    }
    btn.addEventListener('click', unlock);
    pass.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); unlock(); } });
    try {
      if (sessionStorage.getItem('mc_unlocked') === '1') {
        gate.style.display = 'none';
      } else {
        document.body.style.overflow = 'hidden';
        setTimeout(function () { pass.focus(); }, 50);
      }
    } catch (e) {
      document.body.style.overflow = 'hidden';
      setTimeout(function () { pass.focus(); }, 50);
    }
  })();

  var state = { running: false, result: null, report: '', tab: 'overview', query: '' };

  var LABELS = {
    INSTALLED: 'Installed',
    REMOVED: 'Removed',
    REVOKED: 'Revoked',
    NOT_INSTALLED: 'Not installed',
    EVIDENCE: 'Reference only'
  };

  function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtBytes(n) {
    if (!n) return '0 B';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function date(v) { return (!v || v === 'Not available') ? '—' : v; }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  var el = {
    dropzone: $('#dropzone'), fileInput: $('#fileInput'), browseBtn: $('#browseBtn'),
    progressBox: $('#progressBox'), statusText: $('#statusText'), progressText: $('#progressText'),
    barFill: $('#barFill'), progressDetail: $('#progressDetail'),
    results: $('#results'), summary: $('#summary'), panel: $('#panel'), tabs: $('#tabs'),
    search: $('#search'), exportTxt: $('#exportTxt'), exportJson: $('#exportJson'),
    resetBtn: $('#resetBtn'), errorBox: $('#errorBox')
  };

  if (!A) {
    el.errorBox.hidden = false;
    el.errorBox.textContent = 'Analysis engine could not be loaded (analyzer.js). Keep it next to index.html.';
    return;
  }

  var D = A.DEFAULTS;

  /* ---------- input ---------- */

  el.browseBtn.addEventListener('click', function (e) { e.stopPropagation(); el.fileInput.click(); });
  el.dropzone.addEventListener('click', function (e) {
    if (!e.target.closest('button')) el.fileInput.click();
  });

  el.fileInput.addEventListener('change', function () {
    var files = Array.prototype.slice.call(el.fileInput.files || []);
    el.fileInput.value = '';
    start(files);
  });

  ['dragenter', 'dragover'].forEach(function (ev) {
    el.dropzone.addEventListener(ev, function (e) {
      e.preventDefault(); e.stopPropagation(); el.dropzone.classList.add('over');
    });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    el.dropzone.addEventListener(ev, function (e) {
      e.preventDefault(); el.dropzone.classList.remove('over');
    });
  });
  el.dropzone.addEventListener('drop', function (e) {
    e.preventDefault(); e.stopPropagation(); el.dropzone.classList.remove('over');
    start(e.dataTransfer ? Array.prototype.slice.call(e.dataTransfer.files) : []);
  });

  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });
  window.addEventListener('beforeunload', function (e) {
    if (state.running) { e.preventDefault(); e.returnValue = ''; }
  });

  /* ---------- analysis ---------- */

  async function start(files) {
    if (!files.length || state.running) return;
    state.running = true;
    state.result = null;
    state.report = '';

    el.errorBox.hidden = true;
    el.results.hidden = true;
    el.progressBox.hidden = false;
    el.barFill.style.width = '0%';
    el.progressDetail.textContent = 'Reading and unpacking files…';

    var analyzer = new A.Analyzer();
    analyzer.onProgress = function (p) {
      el.progressText.textContent = p.files + ' files Â· ' + fmtBytes(p.bytes);
    };

    try {
      for (var i = 0; i < files.length; i++) {
        var f = files[i];
        el.statusText.textContent = 'Working on: ' + f.name;
        el.progressDetail.textContent = 'File ' + (i + 1) + ' of ' + files.length + ' — ' + fmtBytes(f.size);

        if (f.size > analyzer.maxUpload) {
          analyzer.warnings.push(f.name + ': file is larger than ' + D.maxUploadMB + ' MB and was skipped.');
          continue;
        }
        try {
          var bytes = new Uint8Array(await f.arrayBuffer());
          await analyzer.ingest(f.name, bytes, 0);
        } catch (err) {
          analyzer.warnings.push(f.name + ': could not be read (' + (err && err.message ? err.message : err) + ').');
        }
        el.barFill.style.width = Math.round(((i + 1) / files.length) * 100) + '%';
        await sleep(0);
      }

      el.statusText.textContent = 'Building report…';
      await sleep(0);

      var result = analyzer.analyze();
      state.result = result;
      state.report = A.buildTextReport(result, analyzer);
      state.tab = 'overview';
      state.query = '';
      el.search.value = '';

      render(result);
      el.progressBox.hidden = true;
      el.dropzone.hidden = true;
      el.results.hidden = false;
      el.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      el.errorBox.hidden = false;
      el.errorBox.textContent = 'Analysis failed:\n' + (err && err.stack ? err.stack : String(err));
      el.progressBox.hidden = true;
    } finally {
      state.running = false;
    }
  }

  /* ---------- rendering ---------- */

  function render(r) {
    renderSummary(r);
    $('#c-apps').textContent = r.apps.length;
    $('#c-logs').textContent = r.logs.length;
    $('#c-files').textContent = r.files.length;
    $('#c-warnings').textContent = r.warnings.length;
    renderPanel();
  }

  function renderSummary(r) {
    var installed = r.apps.filter(function (a) { return a.status === 'INSTALLED'; }).length;
    var removed = r.apps.filter(function (a) { return a.status === 'REMOVED'; }).length;
    var cards = [
      { k: 'Files analyzed', v: r.stats.files, cls: '' },
      { k: 'Apps found', v: r.apps.length, cls: 'info' },
      { k: 'Installed', v: installed, cls: 'ok' },
      { k: 'Removed', v: removed, cls: 'bad' },
      { k: 'Logs extracted', v: r.logs.length, cls: '' },
      { k: 'DNS entries', v: r.dns.length, cls: '' },
      { k: 'VPN / proxy', v: r.vpn.length, cls: '' },
      { k: 'Warnings', v: r.warnings.length, cls: r.warnings.length ? 'warn' : '' }
    ];
    el.summary.innerHTML = cards.map(function (c) {
      return '<div class="card ' + c.cls + '"><div class="k">' + esc(c.k) + '</div><div class="v">' + c.v + '</div></div>';
    }).join('');
  }

  function q() { return state.query.trim().toLowerCase(); }
  function matches(o) {
    if (!q()) return true;
    try { return JSON.stringify(o).toLowerCase().indexOf(q()) !== -1; }
    catch (e) { return true; }
  }
  function none(msg) { return '<div class="empty-note">' + esc(msg) + '</div>'; }
  function chip(status) {
    var label = LABELS[status] || status;
    return '<span class="chip ' + String(status).replace(/\s+/g, '_') + '">' + esc(label) + '</span>';
  }

  function block(title, hint, body) {
    return '<section class="block"><h2>' + esc(title) + '</h2>' +
      (hint ? '<p class="hint">' + esc(hint) + '</p>' : '') + body + '</section>';
  }

  function table(head, rows) {
    if (!rows.length) return none('Nothing found here.');
    var body = rows.map(function (cells) {
      return '<tr>' + head.map(function (h, i) {
        return '<td data-label="' + esc(h) + '">' + (cells[i] === undefined ? '' : cells[i]) + '</td>';
      }).join('') + '</tr>';
    }).join('');
    return '<div class="table-wrap"><table><thead><tr>' +
      head.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') +
      '</tr></thead><tbody>' + body + '</tbody></table></div>';
  }

  function section(title, count, body) {
    return '<section class="cat"><h2>' + esc(title) + ' <span class="count">' + count + '</span></h2>' +
      (body || none('Nothing found here.')) + '</section>';
  }

  function lineTable(items) {
    return table(['Entry', 'Date', 'Source'], items.map(function (x) {
      var line = String(x.line);
      if (line.length > 90) line = line.slice(0, 90) + '…';
      var src = String(x.source);
      if (src.length > 55) src = '…' + src.slice(-54);
      return [esc(line), esc(date(x.time)), esc(src)];
    }));
  }

  function eventName(kind) {
    return String(kind).replace(/^APP /, 'App ').toLowerCase().replace(/^./, function (c) { return c.toUpperCase(); });
  }

  var TOOL_KEYS = ['filza', 'gbox', 'esign', 'trollstore', 'trollfools', 'dopamine',
    'freefire', 'sileo', 'ellekit', 'procursus', 'cydia', 'sideload'];

  function renderOverview(r) {
    var out = '';
    if (r.dns.length || r.vpn.length) {
      out += '<div class="alert">DNS or VPN / proxy entries found in your files.</div>';
    }

    // 1 — tools that can edit game/app files
    var tools = [];
    r.apps.forEach(function (a) {
      var hay = (a.name + ' ' + a.bundle_id).toLowerCase();
      if (TOOL_KEYS.some(function (k) { return hay.indexOf(k) !== -1; })) {
        tools.push({ name: a.name, id: a.bundle_id, why: a.status, extra: a.reason, evidence: a.evidence });
      }
    });
    r.findings.forEach(function (f) {
      if (/filza|gbox|esign|trollstore|trollfools|dopamine|jailbreak/i.test(f.name + ' ' + f.category)) {
        tools.push({ name: f.name, id: f.matched, why: f.confidence, extra: f.note, evidence: f.context });
      }
    });
    var seen = {};
    tools = tools.filter(function (t) {
      var k = (t.name + t.id).toLowerCase();
      if (seen[k]) return false;
      seen[k] = 1; return true;
    });
    out += section('Cheat & file-edit tools', tools.length, table(['Tool / app', 'ID / match', 'Status'],
      tools.map(function (t) {
        return ['<b>' + esc(t.name) + '</b>', esc(t.id), esc(t.why)];
      })));

    // 2 — all app references
    var apps = r.apps.filter(matches);
    out += section('Applications', apps.length, table(['App', 'Bundle ID', 'Status', 'Date'],
      apps.map(function (a) {
        return ['<b>' + esc(a.name) + '</b>', esc(a.bundle_id), chip(a.status), esc(date(a.time))];
      })));

    // 3 — timeline
    var events = r.timeline.filter(matches);
    out += section('Timeline', events.length, table(['Date / time', 'Event', 'Source'],
      events.map(function (t) {
        var src = String(t.source);
        if (src.length > 55) src = '…' + src.slice(-54);
        return [esc(date(t.time)), esc(eventName(t.kind)), esc(src)];
      })));

    // 4 — network and device, one category each
    var dns = r.dns.filter(matches);
    var vpn = r.vpn.filter(matches);
    var profiles = r.profiles.filter(matches);
    var certs = r.certificates.filter(matches);
    var icloud = r.icloud.filter(matches);
    out += section('DNS', dns.length, lineTable(dns));
    out += section('VPN / Proxy', vpn.length, lineTable(vpn));
    out += section('Configuration profiles', profiles.length, lineTable(profiles));
    out += section('Certificates', certs.length, lineTable(certs));
    out += section('iCloud / brctl', icloud.length, lineTable(icloud));

    // 5 — each artifact type in its own category
    var groups = {};
    r.findings.filter(matches).forEach(function (f) { (groups[f.name] = groups[f.name] || []).push(f); });
    Object.keys(groups).forEach(function (name) {
      var items = groups[name];
      out += section(name, items.length, table(['Match', 'Source', 'Note'], items.map(function (f) {
        return ['<b>' + esc(f.matched) + '</b>', esc(f.source), '<span class="small">' + esc(String(f.note).slice(0, 80)) + '</span>'];
      })));
    });

    return out;
  }

  function renderLogs(r) {
    var logs = r.logs.filter(function (l) {
      return !q() || l.source.toLowerCase().indexOf(q()) !== -1 || l.text.toLowerCase().indexOf(q()) !== -1;
    });
    var out = block('Logs & extracted text', logs.length + ' record(s). All text is available here and in the .json export.');
    out += '<div class="log-actions" style="margin-bottom:12px">' +
      '<button type="button" class="btn primary" data-download="all">Download all logs (.txt)</button></div>';

    if (!logs.length) return out + none('No logs or readable text found.');

    out += logs.map(function (l) {
      return '<details class="log-item" data-log="' + l.index + '">' +
        '<summary>' + esc(l.source) + ' <span class="muted small">Â· ' + l.lines + ' lines Â· ' + fmtBytes(l.characters) + '</span></summary>' +
        '</details>';
    }).join('');
    return out;
  }

  function renderFiles(r) {
    var rows = r.files.filter(matches).map(function (f) {
      return [esc(f.path), esc(f.kind), fmtBytes(f.size), esc(f.sha256)];
    });
    return block('Processed files', 'Files opened and their SHA-256.',
      table(['File', 'Type', 'Size', 'SHA-256'], rows));
  }

  function renderWarnings(r) {
    var items = r.warnings.filter(matches);
    return block('Warnings', 'Limits or files that could not be fully processed.',
      items.length ? items.map(function (w) {
        return '<div class="simple-item">' + esc(w) + '</div>';
      }).join('') : none('No warnings. Everything was processed.'));
  }

  function renderPanel() {
    if (!state.result) return;
    var r = state.result;
    var html = state.tab === 'overview' ? renderOverview(r) :
      state.tab === 'logs' ? renderLogs(r) :
      state.tab === 'files' ? renderFiles(r) : renderWarnings(r);
    el.panel.innerHTML = html;

    var btns = el.tabs.querySelectorAll('button');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].getAttribute('data-tab') === state.tab);
    }
  }

  /* ---------- events ---------- */

  el.tabs.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-tab]');
    if (!b) return;
    state.tab = b.getAttribute('data-tab');
    renderPanel();
  });

  var timer = null;
  el.search.addEventListener('input', function () {
    clearTimeout(timer);
    timer = setTimeout(function () { state.query = el.search.value; renderPanel(); }, 120);
  });

  el.panel.addEventListener('toggle', function (e) {
    var d = e.target;
    if (!d.classList || !d.classList.contains('log-item') || !d.open || d.querySelector('.log-body')) return;
    var log = state.result.logs[Number(d.getAttribute('data-log'))];
    if (!log) return;
    var body = document.createElement('div');
    body.className = 'log-body';
    var pre = document.createElement('pre');
    pre.className = 'log-text';
    pre.textContent = log.text;
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn';
    btn.setAttribute('data-download-log', log.index);
    btn.textContent = 'Download this log (.txt)';
    body.appendChild(pre);
    body.appendChild(btn);
    d.appendChild(body);
  }, true);

  el.panel.addEventListener('click', function (e) {
    var one = e.target.closest('[data-download-log]');
    if (one && state.result) {
      var l = state.result.logs[Number(one.getAttribute('data-download-log'))];
      download(safeFileName(l.source) + '.txt', l.text, 'text/plain;charset=utf-8');
      return;
    }
    if (e.target.closest('[data-download="all"]') && state.result) {
      var all = state.result.logs.map(function (l) {
        return '===== ' + l.source + ' =====\n' + l.text + '\n';
      }).join('\n');
      download('all_logs.txt', all, 'text/plain;charset=utf-8');
    }
  });

  function safeFileName(s) { return String(s).replace(/[^\w.\-]+/g, '_').slice(0, 120); }

  el.exportTxt.addEventListener('click', function () {
    if (state.result) download('method_check_report.txt', state.report, 'text/plain;charset=utf-8');
  });
  el.exportJson.addEventListener('click', function () {
    if (state.result) download('method_check_result.json', JSON.stringify(state.result, null, 2), 'application/json;charset=utf-8');
  });
  el.resetBtn.addEventListener('click', function () {
    state.result = null; state.report = ''; state.query = ''; state.tab = 'overview';
    el.results.hidden = true; el.progressBox.hidden = true; el.errorBox.hidden = true;
    el.dropzone.hidden = false;
    el.search.value = ''; el.panel.innerHTML = ''; el.summary.innerHTML = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  function download(name, text, type) {
    var blob = new Blob([text], { type: type || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }
})();
