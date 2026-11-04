// export-test.js - the CSV export of assets/report.js (csvCell, toCsv): RFC 4180 quoting, formula-injection guard.
global.document = { getElementById: () => null };
const path = require('path');
const { toCsv, csvCell } = require(path.join(__dirname, '..', 'src/usr/local/emhttp/plugins/unraid-cve-lens/assets/report.js'));
let fail = 0;
const check = (name, cond, got) => { console.log((cond ? 'ok   ' : 'FAIL ') + 'export: ' + name + (cond ? '' : ': ' + JSON.stringify(got))); if (!cond) fail = 1; };
for (const c of ['=1+1', '+SUM(A1)', '-2+3', '@cmd', '\tx', '\rx']) {
  const o = csvCell(c);
  check('formula start ' + JSON.stringify(c) + ' is neutralised', o.replace(/^"/, '').startsWith("'" + c[0]), o);
}
check('plain text unchanged', csvCell('openssl') === 'openssl', csvCell('openssl'));
check('comma -> quoted', csvCell('a,b') === '"a,b"', csvCell('a,b'));
check('quote doubled', csvCell('say "hi"') === '"say ""hi"""', csvCell('say "hi"'));
check('newline kept inside quotes', csvCell('a\nb') === '"a\nb"' && csvCell('a\r\nb') === '"a\r\nb"', csvCell('a\nb'));
check('formula with a comma: apostrophe and quotes', csvCell('=HYPERLINK("x","y")') === '"\'=HYPERLINK(""x"",""y"")"', csvCell('=HYPERLINK("x","y")'));
check('non-strings become empty', csvCell(undefined) === '' && csvCell(null) === '' && csvCell({}) === '', 0);
check('number kept', csvCell(5) === '5', csvCell(5));
const images = [{ name: 'example/web:1', containers: ['web', '=evil'] }, { kind: 'os', name: 'Unraid OS 7.3.4', containers: [] }];
const cves = [{ id: 'CVE-2024-0001', severity: 'HIGH', fix: 'package', title: '=cmd|"x",\nsecond line', url: 'javascript:alert(1)',
  affected: [{ img: 0, pkg: 'libssl', installed: '1.0', fixed: '1.1', source: 'trivy' }, { img: 1, pkg: '@scope/p', installed: '-1', fixed: '', source: 'cpe' }] },
  { id: 'GHSA-x', severity: 'LOW', fix: 'none', title: 't', url: 'https://github.com/advisories/GHSA-x', affected: [{ img: 0, pkg: 'p', installed: '1', fixed: '' }] }, null, { id: 'bad', affected: 'x' }];
const out = toCsv(cves, images);
const lines = out.split('\r\n');
check('header', lines[0] === 'cve,severity,package,installed,fixed,target,containers,fix_status,source,title,url', lines[0]);
check('one row per CVE x affected target (3 rows, CRLF, trailing newline)', out.endsWith('\r\n') && out.split('\r\n').length === 5, out.split('\r\n').length);
check('title with formula, quote and newline escaped', out.includes('"\'=cmd|""x"",\nsecond line"'), out);
check('container starting with = is only joined text inside one cell, not a cell start', out.includes(',web; =evil,'), out);
check('javascript: url replaced by the NVD link', !out.includes('javascript:') && out.includes('https://nvd.nist.gov/vuln/detail/CVE-2024-0001'), out);
check('negative installed version and @package get the apostrophe', out.includes(",'@scope/p,'-1,") , out);
check('missing source defaults to trivy; https url kept', out.includes(',none,trivy,t,https://github.com/advisories/GHSA-x'), out);
check('malformed entries skipped', !out.includes('bad'), out);
// exploit columns (CISA KEV, FIRST EPSS)
const xc = [{ id: 'CVE-2024-0001', severity: 'CRITICAL', fix: 'package', title: 't', kev: { added: '2030-01-02', ransomware: true }, epss: 0.82641, epss_pct: 0.99667,
  affected: [{ img: 0, pkg: 'p', installed: '1', fixed: '2' }] },
  { id: 'CVE-2024-0003', severity: 'LOW', fix: 'none', title: 't', kev: null, epss: null, epss_pct: null, affected: [{ img: 0, pkg: 'q', installed: '1', fixed: '' }] }];
const xo = toCsv(xc, images).split('\r\n');
check('KEV/EPSS data present: kev, kev_added, kev_ransomware, epss, epss_percentile columns appended', xo[0] === 'cve,severity,package,installed,fixed,target,containers,fix_status,source,title,url,kev,kev_added,kev_ransomware,epss,epss_percentile', xo[0]);
check('KEV row: yes, date, ransomware yes, EPSS and percentile as numbers', xo[1].endsWith(',yes,2030-01-02,yes,0.82641,0.99667'), xo[1]);
check('row without KEV/EPSS: no, empty cells', xo[2].endsWith(',no,,,,'), xo[2]);
check('explicit withExploit=true keeps the columns for a view without KEV CVEs', toCsv([xc[1]], images, true).split('\r\n')[0].endsWith(',epss,epss_percentile'), 0);
check('withExploit=false (report without exploit data): no extra columns', toCsv(xc, images, false).split('\r\n')[0].endsWith(',title,url'), 0);
check('all null (exploit data off): no extra columns by default', toCsv([xc[1]], images).split('\r\n')[0].endsWith(',title,url'), 0);
// source column: the same two values as the page's "Found by" filter (trivy, cpe); anything else counts as trivy
const rep = require(path.join(__dirname, '..', 'src/usr/local/emhttp/plugins/unraid-cve-lens/assets/report.js'));
const sc = [{ id: 'CVE-2024-0009', severity: 'LOW', fix: 'none', title: 't', affected: [{ img: 0, pkg: 'a', installed: '1', fixed: '', source: '=evil' }, { img: 1, pkg: 'b', installed: '1', fixed: '', source: 'cpe' }] }];
const so = toCsv(sc, images, false).split('\r\n');
check('source: unknown value exported as trivy, cpe kept', so[1].includes(',none,trivy,t,') && so[2].includes(',none,cpe,t,'), so);
check('cveSources: both scanners of a CVE, in a fixed order', typeof rep.cveSources === 'function' && JSON.stringify(rep.cveSources(sc[0])) === '["trivy","cpe"]'
  && JSON.stringify(rep.cveSources({ affected: [{ source: 'cpe' }, null, 'x'] })) === '["cpe"]' && JSON.stringify(rep.cveSources(null)) === '[]', 0);
process.exit(fail);
