/* unraid-trivy-scan report page.
 * Data: include/report.php (report JSON) and include/status.php (run state). Every value from them is put into the
 * page with textContent or a property assignment (never innerHTML), so the DOM escapes it exactly once.
 * Links: only https URLs from the report; CVE ids that look like CVE-YYYY-N link to NVD. */
(function () {
  'use strict';
  /* Answer of include/action.php as {ok, message|error}. When Unraid's request prologue (local_prepend.php) rejects the
   * csrf_token it logs and exit()s: HTTP 200 with an empty body. That must not show up as "HTTP 200". */
  function parseActionResponse(r) {
    return r.text().then(function (t) {
      if (t === '') return { ok: false, error: r.ok ? 'Session expired or the security token was rejected. Reload the page and try again.' : 'HTTP ' + r.status };
      try { var j = JSON.parse(t); if (j && typeof j === 'object') return j; } catch (e) { /* not JSON */ }
      return { ok: false, error: 'Unexpected answer (HTTP ' + r.status + ')' };
    });
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { parseActionResponse: parseActionResponse };   // tests/action-ui.js
  var root = document.getElementById('uts-report');
  if (!root) return;
  var BASE = root.getAttribute('data-base');
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  var SEV_RANK = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  var FIX_LABEL = { package: 'Package update', update: 'Newer image', both: 'Package update, newer image', none: 'No fix yet' };
  var FIX_FILTERS = [['fixable', 'With a fix (default)'], ['package', 'Package update available'],
                     ['update', 'Fixed in a newer image'], ['none', 'No fix yet'], ['all', 'All']];
  var UPDATE_LABEL = { off: 'Not checked (setting off)', skipped: 'Not checked', failed: 'Registry check failed',
                       current: 'Image is current', newer: 'Newer image in registry', checked: 'Checked', na: 'Not applicable' };
  var IN_UPDATE = { gone: 'Fixed in newer image', present: 'Still in newer image', same: 'No newer image', '': '-' };

  /* Target filter: 'all', 'os' (the Unraid OS), 'images' (container images), or 't<n>' (one target, by its index in
   * report.images; not remembered, since the index belongs to one report). */
  var TARGET_KINDS = ['all', 'os', 'images'];

  var state = { report: null, status: null, error: '', open: {},
                f: { sev: SEVS.slice(), fix: 'fixable', target: 'all', q: '', sort: 'severity', dir: -1, page: 1, size: 50 } };
  try {
    var saved = JSON.parse(localStorage.getItem('uts-filters') || 'null');
    if (saved && typeof saved === 'object') {
      if (Array.isArray(saved.sev)) state.f.sev = saved.sev.filter(function (s) { return SEVS.indexOf(s) >= 0; });
      if (FIX_FILTERS.some(function (x) { return x[0] === saved.fix; })) state.f.fix = saved.fix;
      if (TARGET_KINDS.indexOf(saved.target) >= 0) state.f.target = saved.target;
      if ([25, 50, 100].indexOf(saved.size) >= 0) state.f.size = saved.size;
    }
  } catch (e) { /* storage unavailable: defaults */ }
  function persist() {
    var t = TARGET_KINDS.indexOf(state.f.target) >= 0 ? state.f.target : 'all';
    try { localStorage.setItem('uts-filters', JSON.stringify({ sev: state.f.sev, fix: state.f.fix, target: t, size: state.f.size })); } catch (e) { /* ignore */ }
  }

  /* el('tag', {attr: value, className, onclick...}, child...) ; string children become text nodes */
  function el(tag, attrs) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'className') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.slice(0, 2) === 'on') n.addEventListener(k.slice(2), v);
      else if (k === 'href') n.href = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) add(n, arguments[i]);
    return n;
  }
  function add(n, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(n, x); }); return; }
    n.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
  function str(v) { return typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : ''); }
  function num(v) { return typeof v === 'number' && isFinite(v) ? v : 0; }
  function httpsUrl(u) { return typeof u === 'string' && /^https:\/\/[A-Za-z0-9.-]+(\/[^\s"'<>\\`]*)?$/.test(u) ? u : ''; }
  function cveUrl(c) {
    var u = httpsUrl(c.url);
    if (u) return u;
    return /^CVE-\d{4}-\d{4,}$/.test(str(c.id)) ? 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c.id) : '';
  }
  function fmtTime(t) {
    if (!t) return '-';
    var d = new Date(t * 1000);
    function p(x) { return x < 10 ? '0' + x : '' + x; }
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function sevBadge(s) {
    s = SEV_RANK[s] !== undefined ? s : 'UNKNOWN';
    return el('span', { className: 'uts-badge uts-sev-' + s.toLowerCase() }, s.charAt(0) + s.slice(1).toLowerCase());
  }

  /* ---------------- network ---------------- */
  function getJSON(path) {
    return fetch(BASE + path, { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function csrf() {
    /* Unraid pages define a global csrf_token; the page also carries it in data-csrf */
    return (typeof window.csrf_token === 'string' && window.csrf_token) || root.getAttribute('data-csrf') || '';
  }
  function action(a) {
    var body = new URLSearchParams();
    body.set('action', a); body.set('csrf_token', csrf());
    return fetch(BASE + '/include/action.php', { method: 'POST', credentials: 'same-origin', body: body,
                                                  headers: { 'X-CSRF-Token': csrf() } })
      .then(parseActionResponse);
  }

  /* ---------------- status bar ---------------- */
  var $status = document.getElementById('uts-status');
  var $prog = document.getElementById('uts-progress');
  var $scan = document.getElementById('uts-scan');
  var $stop = document.getElementById('uts-stop');
  var PHASE = { pull: 'Downloading the Trivy image', db: 'Updating databases', scan: 'Scanning', os: 'Scanning the Unraid OS',
                registry: 'Registry check', report: 'Writing the report' };
  var pollTimer = null, lastGenerated = null;

  function renderStatus() {
    var st = state.status;
    if (!st) { $status.textContent = state.error ? 'Status unavailable: ' + state.error : 'Loading...'; return; }
    if (st.running) {
      var t = (PHASE[str(st.phase)] || 'Scan running');
      if (num(st.total) > 0) t += ': ' + num(st.done) + ' of ' + num(st.total);
      if (str(st.current)) t += ' (' + str(st.current) + ')';
      $status.textContent = t;
      $prog.hidden = false;
      if (num(st.total) > 0) { $prog.max = num(st.total); $prog.value = num(st.done); } else { $prog.removeAttribute('value'); }
    } else {
      var l = st.last || {};
      var t2 = 'Idle.';
      if (str(l.result) === 'ok') t2 = 'Last scan finished ' + fmtTime(num(l.ended)) + ': ' + str(l.message) + '.';
      else if (str(l.result) === 'failed') t2 = 'Last scan failed ' + fmtTime(num(l.ended)) + ': ' + str(l.message);
      else if (str(l.result) === 'stopped') t2 = 'Last scan stopped ' + fmtTime(num(l.ended)) + ': ' + str(l.message);
      $status.textContent = t2;
      $prog.hidden = true;
    }
    $scan.disabled = !!st.running;
    $stop.hidden = !st.running;
  }
  function poll() {
    getJSON('/include/status.php').then(function (st) {
      state.status = st; state.error = '';
      renderStatus();
      var gen = st && st.report ? num(st.report.generated) : 0;
      if (lastGenerated !== null && gen !== lastGenerated) loadReport();
      lastGenerated = gen;
      schedule(st && st.running ? 3000 : 30000);
    }).catch(function (e) { state.error = e.message; renderStatus(); schedule(30000); });
  }
  function schedule(ms) { clearTimeout(pollTimer); pollTimer = setTimeout(poll, ms); }
  $scan.addEventListener('click', function () {
    $scan.disabled = true;
    action('start').then(function (r) {
      if (!r.ok) $status.textContent = 'Could not start: ' + str(r.error || r.message);
      setTimeout(poll, 1000);
    });
  });
  $stop.addEventListener('click', function () {
    $stop.disabled = true;
    action('stop').then(function () { $stop.disabled = false; poll(); });
  });

  /* ---------------- report ---------------- */
  var $body = document.getElementById('uts-body');
  function loadReport() {
    getJSON('/include/report.php').then(function (r) {
      state.report = (r && typeof r === 'object' && Array.isArray(r.cves)) ? r : null;
      state.error = '';
      renderReport();
    }).catch(function (e) {
      $body.replaceChildren(el('p', { className: 'uts-notice uts-notice-error', role: 'alert' }, 'The report could not be loaded: ' + e.message));
    });
  }

  function summaryCards(r) {
    var bs = (r.summary && r.summary.by_severity) || {};
    var cards = SEVS.filter(function (s) { return s !== 'UNKNOWN' || num((bs.UNKNOWN || {}).total) > 0; }).map(function (s) {
      var x = bs[s] || {};
      return el('div', { className: 'uts-card uts-card-' + s.toLowerCase() },
        el('span', { className: 'uts-card-label' }, sevBadge(s)),
        el('span', { className: 'uts-card-num' }, String(num(x.fixable))),
        el('span', { className: 'uts-card-sub' }, 'fixable of ' + num(x.total)));
    });
    var sm = r.summary || {};
    var osOn = str(sm.os) === 'ok' || str(sm.os) === 'failed';
    cards.push(el('div', { className: 'uts-card' }, el('span', { className: 'uts-card-label' }, 'Images scanned'),
      el('span', { className: 'uts-card-num' }, String(num(sm.images))),
      el('span', { className: 'uts-card-sub' }, (r.scope === 'all' ? 'running and stopped' : 'running containers') + (str(sm.os) === 'ok' ? ', plus the Unraid OS' : ''))));
    cards.push(el('div', { className: 'uts-card' + (num(sm.failed) ? ' uts-card-fail' : '') }, el('span', { className: 'uts-card-label' }, 'Could not scan'),
      el('span', { className: 'uts-card-num' }, String(num(sm.failed))), el('span', { className: 'uts-card-sub' }, osOn ? 'image(s) or the OS' : 'image(s)')));
    return el('div', { className: 'uts-cards' }, cards);
  }

  function metaLine(r) {
    var parts = ['Report from ' + fmtTime(num(r.generated))];
    if (str(r.trivy)) parts.push('Trivy ' + str(r.trivy).split('@')[0]);
    if (r.db && str(r.db.updated)) parts.push('vulnerability DB from ' + str(r.db.updated).slice(0, 16).replace('T', ' ') + ' UTC');
    parts.push('registry check ' + (r.registry ? 'on' : 'off'));
    var sm = r.summary || {};
    parts.push('Unraid OS scan ' + (str(sm.os) === 'ok' || str(sm.os) === 'failed' ? 'on' : 'off'));
    return el('p', { className: 'uts-meta' }, parts.join(' · '));
  }

  function notices(r) {
    var out = [];
    var w = Array.isArray(r.warnings) ? r.warnings : [];
    if (w.length) out.push(el('div', { className: 'uts-notice uts-notice-warn', role: 'note' },
      el('strong', null, 'Warnings from this scan'), el('ul', null, w.map(function (x) { return el('li', null, str(x)); }))));
    var images = Array.isArray(r.images) ? r.images : [];
    var failed = images.filter(function (im) { return im && im.scan !== 'ok'; });
    if (failed.length) out.push(el('details', { className: 'uts-notice uts-notice-error', open: true },
      el('summary', null, failed.length + (failed.some(isOs) ? ' target(s)' : ' image(s)') + ' could not be scanned'),
      el('ul', null, failed.map(function (im) {
        return el('li', null, el('strong', null, str(im.name)), containersText(im), ': ', str(im.error) || 'unknown error');
      }))));
    return out;
  }
  function isOs(im) { return !!im && im.kind === 'os'; }
  function targetName(im) {
    return [isOs(im) ? el('span', { className: 'uts-badge uts-os-badge' }, 'OS') : null, isOs(im) ? ' ' : null,
            el('span', { className: 'uts-mono' }, str(im.name) || '?')];
  }
  function containersText(im) {
    var c = Array.isArray(im.containers) ? im.containers.map(str).filter(Boolean) : [];
    return c.length ? ' (' + c.join(', ') + ')' : '';
  }

  function imagesTable(r) {
    var images = Array.isArray(r.images) ? r.images : [];
    if (!images.length) return null;
    var rows = images.map(function (im) {
      var upd = UPDATE_LABEL[str(im.update)] || '-';
      var note = str(im.update_note);
      return el('tr', null,
        el('td', null, targetName(im), im.stale ? el('div', { className: 'uts-hint' }, 'The tag now points to a newer local image: recreate the container to use it.') : null),
        el('td', null, (Array.isArray(im.containers) ? im.containers.map(str) : []).join(', ')),
        el('td', null, str(im.os) || '-'),
        el('td', { className: 'uts-num' }, im.scan === 'ok' ? String(num(im.vulns)) : '-'),
        el('td', null, im.scan === 'ok' ? 'Scanned' : 'Failed'),
        el('td', null, upd, note ? el('div', { className: 'uts-hint' }, note) : null));
    });
    return el('details', { className: 'uts-images' },
      el('summary', null, (images.some(isOs) ? 'Scanned targets (' : 'Scanned images (') + images.length + ')'),
      el('div', { className: 'uts-scroll' }, el('table', { className: 'uts-table uts-table-plain' },
        el('thead', null, el('tr', null, ['Image', 'Containers', 'OS', 'Findings', 'Scan', 'Registry'].map(function (h) { return el('th', { scope: 'col' }, h); }))),
        el('tbody', null, rows))));
  }

  /* The Unraid OS package list: Trivy has no Slackware advisory feed, so it is shown, not matched. */
  function hostPackages(r) {
    var h = r.host;
    if (!h || typeof h !== 'object') return null;
    var pk = Array.isArray(h.packages) ? h.packages.filter(Array.isArray) : [];
    var ver = str(h.version);
    var notes = /^[0-9]+\.[0-9]+\.[0-9]+$/.test(ver) ? 'https://docs.unraid.net/unraid-os/release-notes/' + ver + '/' : '';
    var open = /(?:^|[#&])packages(?:&|$)/.test(location.hash);
    return el('details', { className: 'uts-images uts-host', open: open },
      el('summary', null, str(h.name) + ': OS packages, not CVE-matched (' + num(h.package_count) + ')'),
      el('p', { className: 'uts-hint uts-host-note' },
        'Unraid OS is based on Slackware, and Trivy has no Slackware advisory feed, so these packages and the kernel are ',
        el('strong', null, 'not'), ' checked for CVEs. Check them against the Unraid release notes',
        notes ? [' (', el('a', { href: notes, target: '_blank', rel: 'noopener noreferrer' }, 'Unraid ' + ver), ')'] : null,
        '. The OS scan above covers what Trivy can match inside the OS: Go binaries, Node.js packages (including the Unraid API) and other language packages.'),
      el('p', { className: 'uts-meta' }, 'Kernel ', el('span', { className: 'uts-mono' }, str(h.kernel) || '-'), ' · ' + pk.length + ' Slackware packages'),
      el('ul', { className: 'uts-pkglist' }, pk.map(function (p) {
        return el('li', null, el('span', { className: 'uts-mono' }, str(p[0])), ' ', el('span', { className: 'uts-mono uts-hint' }, str(p[1]) + (str(p[2]) ? '-' + str(p[2]) : '')));
      })));
  }

  /* ---- filtering / sorting ---- */
  /* null for 'all', else a test on a target index (report.images) */
  function targetTest(t, images) {
    if (t === 'os') return function (n) { return isOs(images[n]); };
    if (t === 'images') return function (n) { return !!images[n] && !isOs(images[n]); };
    var m = /^t([0-9]+)$/.exec(t);
    if (m) { var want = +m[1]; return function (n) { return n === want; }; }
    return null;
  }
  function filtered(r) {
    var f = state.f, q = f.q.trim().toLowerCase();
    var images = Array.isArray(r.images) ? r.images : [];
    var hiddenNoFix = 0;
    var inTarget = targetTest(f.target, images);
    var list = r.cves.filter(function (c) {
      if (!c || typeof c !== 'object') return false;
      if (f.sev.indexOf(c.severity) < 0) return false;
      if (inTarget && !(Array.isArray(c.affected) ? c.affected : []).some(function (a) { return a && inTarget(num(a.img)); })) return false;
      var fix = str(c.fix) || 'none';
      if (f.fix === 'fixable' && fix === 'none') { hiddenNoFix++; return false; }
      if (f.fix === 'package' && fix !== 'package' && fix !== 'both') return false;
      if (f.fix === 'update' && fix !== 'update' && fix !== 'both') return false;
      if (f.fix === 'none' && fix !== 'none') return false;
      if (q) {
        var hay = [str(c.id), str(c.title)];
        (Array.isArray(c.affected) ? c.affected : []).forEach(function (a) {
          hay.push(str(a.pkg)); hay.push(str(a.path)); hay.push(str(a.target));
          var im = images[a.img]; if (im) { hay.push(str(im.name)); hay.push((Array.isArray(im.containers) ? im.containers.map(str) : []).join(' ')); }
        });
        if (hay.join('\n').toLowerCase().indexOf(q) < 0) return false;
      }
      return true;
    });
    var key = f.sort, dir = f.dir;
    function firstPkg(c) { return (c.affected && c.affected[0] && str(c.affected[0].pkg)) || ''; }
    var fixRank = { both: 3, package: 2, update: 1, none: 0 };
    list.sort(function (a, b) {
      var x, y;
      switch (key) {
        case 'id': x = str(a.id); y = str(b.id); break;
        case 'pkg': x = firstPkg(a); y = firstPkg(b); break;
        case 'images': x = num(a.image_count); y = num(b.image_count); break;
        case 'fix': x = fixRank[a.fix] || 0; y = fixRank[b.fix] || 0; break;
        default: x = SEV_RANK[a.severity] || 0; y = SEV_RANK[b.severity] || 0;
      }
      if (x < y) return -dir;
      if (x > y) return dir;
      return (num(b.image_count) - num(a.image_count)) || (str(a.id) < str(b.id) ? -1 : 1);
    });
    return { list: list, hiddenNoFix: hiddenNoFix };
  }

  function filters() {
    var f = state.f;
    var sevBoxes = SEVS.map(function (s) {
      return el('label', { className: 'uts-check' },
        el('input', { type: 'checkbox', value: s, checked: f.sev.indexOf(s) >= 0, onchange: function (e) {
          var on = e.target.checked;
          f.sev = SEVS.filter(function (x) { return x === s ? on : f.sev.indexOf(x) >= 0; });
          f.page = 1; persist(); renderTable();
        } }), ' ', sevBadge(s));
    });
    var fixSel = el('select', { id: 'uts-fix', onchange: function (e) { f.fix = e.target.value; f.page = 1; persist(); renderTable(); } },
      FIX_FILTERS.map(function (o) { return el('option', { value: o[0], selected: f.fix === o[0] }, o[1]); }));
    // Target: all / the Unraid OS / container images / one target. Targets that could not be scanned have no findings.
    var images = state.report && Array.isArray(state.report.images) ? state.report.images : [];
    var hasOs = images.some(isOs);
    if (f.target === 'os' && !hasOs) f.target = 'all';
    var one = /^t([0-9]+)$/.exec(f.target);
    if (one && !(images[+one[1]] && images[+one[1]].scan === 'ok')) f.target = 'all';
    var kinds = [['all', 'All targets']].concat(hasOs ? [['os', 'Unraid OS'], ['images', 'Container images']] : []);
    var singles = [];
    images.forEach(function (im, n) {
      if (im && im.scan === 'ok') singles.push(el('option', { value: 't' + n, selected: f.target === 't' + n },
        (isOs(im) ? 'OS: ' : '') + (str(im.name) || '?') + containersText(im)));
    });
    var targetSel = el('select', { id: 'uts-target', onchange: function (e) { f.target = e.target.value; f.page = 1; persist(); renderTable(); } },
      kinds.map(function (o) { return el('option', { value: o[0], selected: f.target === o[0] }, o[1]); }),
      singles.length > 1 ? el('optgroup', { label: 'One target' }, singles) : null);
    var search = el('input', { type: 'search', id: 'uts-q', placeholder: 'CVE, package, image, path', value: f.q,
      oninput: function (e) { f.q = e.target.value; f.page = 1; renderTable(); } });
    var size = el('select', { id: 'uts-size', onchange: function (e) { f.size = +e.target.value; f.page = 1; persist(); renderTable(); } },
      [25, 50, 100].map(function (n) { return el('option', { value: n, selected: f.size === n }, n + ' per page'); }));
    return el('div', { className: 'uts-filters', role: 'group', 'aria-label': 'Filters' },
      el('fieldset', { className: 'uts-sevs' }, el('legend', null, 'Severity'), sevBoxes),
      el('label', { className: 'uts-field', 'for': 'uts-target' }, el('span', null, 'Target'), targetSel),
      el('label', { className: 'uts-field', 'for': 'uts-fix' }, el('span', null, 'Fix status'), fixSel),
      el('label', { className: 'uts-field', 'for': 'uts-q' }, el('span', null, 'Search'), search),
      el('label', { className: 'uts-field', 'for': 'uts-size' }, el('span', null, 'Rows'), size));
  }

  var COLS = [['', null], ['CVE', 'id'], ['Severity', 'severity'], ['Package', 'pkg'], ['Images', 'images'], ['Fix', 'fix'], ['Title', null]];
  function colLabel(c) { return c[1] === 'images' && state.report && state.report.host ? 'Targets' : c[0]; }
  function head() {
    return el('thead', null, el('tr', null, COLS.map(function (c) {
      if (!c[1]) return el('th', { scope: 'col' }, c[0] ? c[0] : el('span', { className: 'uts-sr' }, 'Details'));
      var active = state.f.sort === c[1];
      return el('th', { scope: 'col', 'aria-sort': active ? (state.f.dir > 0 ? 'ascending' : 'descending') : 'none' },
        el('button', { type: 'button', className: 'uts-sort', onclick: function () {
          if (state.f.sort === c[1]) state.f.dir = -state.f.dir; else { state.f.sort = c[1]; state.f.dir = (c[1] === 'id' || c[1] === 'pkg') ? 1 : -1; }
          renderTable();
        } }, colLabel(c), el('span', { className: 'uts-sort-ind', 'aria-hidden': 'true' }, active ? (state.f.dir > 0 ? ' ▲' : ' ▼') : '')));
    })));
  }

  function cveRows(c, images) {
    var id = str(c.id), open = !!state.open[id];
    var detailId = 'uts-d-' + id.replace(/[^A-Za-z0-9_-]/g, '_');
    var aff = Array.isArray(c.affected) ? c.affected : [];
    var pkgs = [];
    aff.forEach(function (a) { var p = str(a.pkg); if (p && pkgs.indexOf(p) < 0) pkgs.push(p); });
    var url = cveUrl(c);
    var toggle = el('button', { type: 'button', className: 'uts-toggle', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': detailId,
      title: 'Show affected images, packages and paths', onclick: function () { state.open[id] = !state.open[id]; renderTable(); } },
      el('span', { 'aria-hidden': 'true' }, open ? '▾' : '▸'), el('span', { className: 'uts-sr' }, 'Details for ' + id));
    var row = el('tr', { className: 'uts-row' + (open ? ' uts-open' : '') },
      el('td', { className: 'uts-tcell' }, toggle),
      el('td', { className: 'uts-mono uts-id' }, url ? el('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, id) : id),
      el('td', null, sevBadge(c.severity)),
      el('td', { className: 'uts-mono uts-pkg' }, pkgs[0] || '-', pkgs.length > 1 ? el('span', { className: 'uts-more' }, ' +' + (pkgs.length - 1)) : null),
      el('td', { className: 'uts-num' }, String(num(c.image_count))),
      el('td', null, el('span', { className: 'uts-fix uts-fix-' + (FIX_LABEL[c.fix] ? c.fix : 'none') }, FIX_LABEL[c.fix] || FIX_LABEL.none)),
      el('td', { className: 'uts-title' }, str(c.title)));
    if (!open) return [row];
    var detail = el('tr', { className: 'uts-detail', id: detailId },
      el('td', { colspan: COLS.length },
        el('table', { className: 'uts-table uts-table-plain uts-inner' },
          el('thead', null, el('tr', null, ['Image or OS', 'Containers', 'Package', 'Installed', 'Fixed in', 'Status', 'Newer image', 'Target or file'].map(function (h) { return el('th', { scope: 'col' }, h); }))),
          el('tbody', null, aff.map(function (a) {
            var im = images[a.img] || {};
            var where = str(a.path) || str(a.target);
            if (isOs(im) && where && where.charAt(0) !== '/') where = '/' + where;   // rootfs paths are relative to /
            return el('tr', null,
              el('td', null, targetName(im)),
              el('td', null, (Array.isArray(im.containers) ? im.containers.map(str) : []).join(', ')),
              el('td', { className: 'uts-mono' }, str(a.pkg)),
              el('td', { className: 'uts-mono' }, str(a.installed)),
              el('td', { className: 'uts-mono' }, str(a.fixed) || '-'),
              el('td', null, str(a.status).replace(/_/g, ' ')),
              el('td', null, IN_UPDATE[str(a.update)] || '-'),
              el('td', { className: 'uts-mono uts-hint' }, where));
          })))));
    return [row, detail];
  }

  var $table = null;
  function renderTable() {
    var r = state.report;
    if (!r || !$table) return;
    var res = filtered(r), f = state.f;
    var pages = Math.max(1, Math.ceil(res.list.length / f.size));
    if (f.page > pages) f.page = pages;
    var start = (f.page - 1) * f.size, slice = res.list.slice(start, start + f.size);
    var images = Array.isArray(r.images) ? r.images : [];
    var body;
    if (!r.cves.length) {
      body = el('tbody', null, el('tr', null, el('td', { colspan: COLS.length, className: 'uts-empty' }, 'No vulnerabilities found in the scanned ' + (r.host ? 'targets.' : 'images.'))));
    } else if (!slice.length) {
      body = el('tbody', null, el('tr', null, el('td', { colspan: COLS.length, className: 'uts-empty' },
        'No CVEs match the filters.' + (res.hiddenNoFix ? ' ' + res.hiddenNoFix + ' CVE(s) without a fix are hidden; choose "All" under Fix status to see them.' : ''))));
    } else {
      body = el('tbody', null, slice.map(function (c) { return cveRows(c, images); }));
    }
    $table.replaceChildren(head(), body);
    var info = res.list.length ? (start + 1) + '–' + (start + slice.length) + ' of ' + res.list.length + ' CVEs' : '0 CVEs';
    if (res.hiddenNoFix && slice.length) info += ' (' + res.hiddenNoFix + ' without a fix hidden)';
    $pager.replaceChildren(
      el('span', { className: 'uts-pager-info' }, info),
      el('button', { type: 'button', disabled: f.page <= 1, onclick: function () { f.page--; renderTable(); } }, 'Previous'),
      el('span', { className: 'uts-pager-page' }, 'Page ' + f.page + ' of ' + pages),
      el('button', { type: 'button', disabled: f.page >= pages, onclick: function () { f.page++; renderTable(); } }, 'Next'));
  }
  var $pager = null;

  function renderReport() {
    var r = state.report;
    if (!r) {
      $body.replaceChildren(el('div', { className: 'uts-empty-state' },
        el('h3', null, 'No report yet'),
        el('p', null, 'Press "Scan now", or set a schedule on the Settings tab.'),
        el('p', null, 'The first scan downloads the pinned Trivy image (about 60 MB), the vulnerability database (about 1.6 GB on disk) and, if enabled, the Java database (about 1.5 GB).'),
        el('p', null, 'On the Settings tab, under "Databases", you choose for each database whether it is kept on disk between scans (then it is only refreshed when a newer one is published, about once a day) or downloaded for every scan and deleted afterwards (no disk space used between scans, but the full download each time).')));
      return;
    }
    $table = el('table', { className: 'uts-table uts-cves' });
    $pager = el('div', { className: 'uts-pager', role: 'navigation', 'aria-label': 'Pages' });
    var parts = [summaryCards(r), metaLine(r)].concat(notices(r), [imagesTable(r), hostPackages(r), filters(), el('div', { className: 'uts-scroll' }, $table), $pager]);
    $body.replaceChildren.apply($body, parts.filter(Boolean));
    var m = /(?:^|[#&])open=([A-Za-z0-9._:-]+)/.exec(location.hash);
    if (m && !state.openedFromHash) { state.open[m[1]] = true; state.f.q = m[1]; state.f.fix = 'all'; state.openedFromHash = true;
      var qi = document.getElementById('uts-q'); if (qi) qi.value = m[1];
      var fs = document.getElementById('uts-fix'); if (fs) fs.value = 'all'; }
    renderTable();
  }

  poll();
  loadReport();
})();
