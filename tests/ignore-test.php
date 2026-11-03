<?php
/* tests/ignore-test.php <repo>: the ignore list (include/ignore.php): line parser, scope matching, edits, and its effect
 * in include/aggregate.php on the fixtures. Prints "ok"/"FAIL" lines; exit 1 on any failure. Work files: tests/.work/ign. */
$repo = $argv[1];
$P = "$repo/src/usr/local/emhttp/plugins/unraid-cve-lens";
require "$P/include/ignore.php";
$agg = "$P/include/aggregate.php";
$w = "$repo/tests/.work/ign"; exec('rm -rf ' . escapeshellarg($w)); @mkdir($w, 0755, true);
$fail = 0;
function t(bool $c, string $m) { global $fail; echo ($c ? "ok   " : "FAIL ") . "ignore: $m\n"; if (!$c) $fail = 1; }

// ---- the line parser
$cases = [   // line => [kind, id, scope, until, reason] or [invalid, why-substring]
  ['CVE-2024-0001',                                    ['entry', 'CVE-2024-0001', '*', '', '']],
  ['  CVE-2024-0001   nginx:1.19-alpine  until=2026-12-31  # not reachable  ', ['entry', 'CVE-2024-0001', 'nginx:1.19-alpine', '2026-12-31', 'not reachable']],
  ['CVE-2024-0001 lscr.io/linuxserver/plex # a # b',   ['entry', 'CVE-2024-0001', 'lscr.io/linuxserver/plex', '', 'a # b']],
  ['CVE-2024-0001 os',                                 ['entry', 'CVE-2024-0001', 'os', '', '']],
  ['CVE-2024-0001 *',                                  ['entry', 'CVE-2024-0001', '*', '', '']],
  ['until=2026-12-31 CVE-2024-0001',                   ['invalid', 'does not start with']],
  ['GHSA-abcd-efgh-ijkl # advisory',                   ['entry', 'GHSA-abcd-efgh-ijkl', '*', '', 'advisory']],
  ['# only a comment',                                 ['blank']],
  ['',                                                 ['blank']],
  ['not a cve',                                        ['invalid', 'does not start with']],
  ['CVE-2024-0001 a b',                                ['invalid', 'more than one scope']],
  ['CVE-2024-0001 until=2026-02-30',                   ['invalid', 'not a date']],
  ['CVE-2024-0001 until=2026-1-1',                     ['invalid', 'not a date']],
  ['CVE-2024-0001 until=',                             ['invalid', 'not a date']],
  ['CVE-2024-0001 until=2026-12-01 until=2026-12-02',  ['invalid', 'twice']],
  ['CVE-2024-0001 foo=bar',                            ['invalid', 'unknown option']],
  ['CVE-2024-0001 $(reboot)',                          ['invalid', 'scope is not']],
  ['CVE-2024-0001 ../../etc',                          ['invalid', 'scope is not']],
  ["CVE-2024-0001 x\x01y",                             ['invalid', 'control characters']],
  ['CVE-2024-0001 x # ' . str_repeat('r', 700),        ['invalid', 'longer than']],
  ["CVE-2024-0001 \xff\xfe",                           ['invalid', 'not valid UTF-8']],
];
foreach ($cases as [$line, $want]) {
  $p = uts_ign_parse_line($line);
  $ok = $p['kind'] === $want[0] && ($want[0] === 'blank' || ($want[0] === 'invalid' ? strpos($p['why'], $want[1]) !== false
        : [$p['id'], $p['scope'], $p['until'], $p['reason']] === array_slice($want, 1)));
  t($ok, 'parse ' . json_encode(substr($line, 0, 50)) . ' -> ' . $want[0] . ($want[0] === 'invalid' ? " ($want[1])" : '') . ($ok ? '' : ' got ' . json_encode($p)));
}
$r = uts_ign_parse(["CVE-2024-0001 until=2026-11-02", "CVE-2024-0002 until=2026-11-03", "CVE-2024-0003", "junk", "# c"], '2026-11-03');
t(count($r['expired']) === 1 && $r['expired'][0]['id'] === 'CVE-2024-0001', 'until before today is expired');
t(count($r['active']) === 2 && $r['active'][0]['id'] === 'CVE-2024-0002' && $r['active'][1]['line'] === 3, 'until today still hides; entries carry their line number');
t($r['invalid'] === [[4, 'does not start with a CVE or advisory id']], 'invalid line reported with its number');
$many = array_fill(0, UTS_IGN_MAX_LINES + 3, 'CVE-2024-0001');
$r = uts_ign_parse($many, '2026-11-03');
t(count($r['active']) === UTS_IGN_MAX_LINES && count($r['invalid']) === 1 && strpos($r['invalid'][0][1], 'more than') !== false, 'lines past the cap are reported, not silently dropped');

// ---- scope matching
$m = fn($scope, $kind, $names) => uts_ign_scope_matches($scope, $kind, $names);
t($m('*', 'image', ['x']) && $m('*', 'os', ['Unraid OS 7']), '* matches images and the OS');
t($m('os', 'os', ['Unraid OS 7']) && !$m('os', 'image', ['os:1', 'os:1']), 'os matches only the OS target');
t(!$m('nginx', 'os', ['nginx']), 'an image scope never matches the OS');
t($m('nginx', 'image', ['nginx:1.19-alpine', 'nginx:1.19-alpine']) && $m('nginx', 'image', ['x', 'docker.io/library/nginx:latest']), 'name without tag matches any tag, Docker Hub prefix optional');
t($m('nginx:1.19-alpine', 'image', ['nginx:1.19-alpine', '']) && !$m('nginx:1.19-alpine', 'image', ['nginx:1.20', 'nginx:1.20']), 'name with tag matches that tag only');
t($m('lscr.io/linuxserver/plex', 'image', ['lscr.io/linuxserver/plex:latest', 'lscr.io/linuxserver/plex:latest']) && !$m('linuxserver/plex', 'image', ['lscr.io/linuxserver/plex:latest', '']), 'registry names match exactly (no suffix guessing)');
t($m('Example/DB', 'image', ['example/db:2 (running older image bbbbbbbbbbbb)', '']), 'case-insensitive; the "running older image" note is ignored');
t($m('localhost:5000/app', 'image', ['localhost:5000/app:2', '']) && !$m('localhost:5000/app', 'image', ['localhost:5000/other:2', '']), 'a registry port is not a tag');
t(!$m('nginx', 'image', ['nginx-proxy:1', 'nginx-proxy:1']) && !$m('web', 'image', ['example/web:1', '']), 'no prefix or suffix matching');

// ---- edits
$f = "$w/edit/ignore.txt"; $lock = "$w/run/ignore.lock";
t(uts_ign_add($f, $lock, 'CVE-2024-0001', '*', '', 'first', '2026-11-03') === null && file_get_contents($f) === "CVE-2024-0001 * # first\n", 'add creates the file (and its directory)');
file_put_contents($f, "# mine\njunk line\n" . file_get_contents($f));
t(uts_ign_add($f, $lock, 'CVE-2024-0002', 'example/web:1.2', '2026-12-31', "multi\nline # reason", '2026-11-03') === null
  && trim(file_get_contents($f)) === "# mine\njunk line\nCVE-2024-0001 * # first\nCVE-2024-0002 example/web:1.2 until=2026-12-31 # multi line # reason", 'add appends; comments and invalid lines are kept; newline in the reason becomes a space');
t(uts_ign_add($f, $lock, 'CVE-2024-0001', '*', '', 'second', '2026-11-03') === null && substr_count(file_get_contents($f), 'CVE-2024-0001 ') === 1
  && strpos(file_get_contents($f), 'second') !== false, 'adding the same id and scope replaces that entry');
$before = file_get_contents($f);
foreach ([['not an id', '*', '', ''], ['CVE-2024-0003', 'a b', '', ''], ['CVE-2024-0003', '$(id)', '', ''], ['CVE-2024-0003', '*', '2026-02-30', ''],
          ['CVE-2024-0003', '*', '2026-11-02', ''], ['CVE-2024-0003', '*', 'tomorrow', ''], ["CVE-2024-0003\nCVE-2024-0009", '*', '', ''], ['CVE-2024-0003', "x\ny", '', '']] as [$id, $sc, $un, $re]) {
  $e = uts_ign_add($f, $lock, $id, $sc, $un, $re, '2026-11-03');
  t($e !== null && file_get_contents($f) === $before, 'add refused, file unchanged: ' . json_encode([$id, $sc, $un]) . " -> $e");
}
$e = uts_ign_remove($f, $lock, 'CVE-2024-0002', 'example/web:1.2');
t($e === null && strpos(file_get_contents($f), 'CVE-2024-0002') === false && strpos(file_get_contents($f), 'junk line') !== false, 'remove drops the entry only');
t(uts_ign_remove($f, $lock, 'CVE-2024-0002', 'example/web:1.2') === 'no such entry in ignore.txt', 'removing a missing entry is an error');
t(!glob("$w/edit/*.tmp.*") && (fileperms($f) & 0777) === 0644, 'no temp file left, mode 0644');
file_put_contents($f, str_repeat("CVE-2024-0001 * # x\n", UTS_IGN_MAX_LINES));
t(uts_ign_add($f, $lock, 'CVE-2024-0007', '*', '', '', '2026-11-03') !== null, 'line cap: a full file refuses another entry');
file_put_contents($f, str_repeat('#' . str_repeat('x', 500) . "\n", 600));
t(uts_ign_add($f, $lock, 'CVE-2024-0007', '*', '', '', '2026-11-03') === 'ignore.txt is larger than 256 KiB, not changed', 'size cap: an oversized file is refused, not truncated');
@mkdir("$w/lnk"); file_put_contents("$w/lnk/real", "x\n"); symlink("$w/lnk/real", "$w/lnk/ignore.txt");
t(uts_ign_add("$w/lnk/ignore.txt", $lock, 'CVE-2024-0007', '*', '', '', '2026-11-03') === 'ignore.txt is a symbolic link, not changed' && file_get_contents("$w/lnk/real") === "x\n", 'a symlinked ignore.txt is not written through');

// ---- aggregate: images (tests/fixtures/basic), today=2026-11-03
function agg(string $agg, string $work, string $out, string $today = '2026-11-03'): string {
  @unlink($out);
  return (string)shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($work) . ' ' . escapeshellarg($out) . ' scope=all registry=yes trivy=x today=' . $today . ' 2>&1');
}
function work(string $repo, string $w, string $name, string $fixture, ?string $ignore): string {
  $d = "$w/$name"; exec('cp -r ' . escapeshellarg("$repo/tests/fixtures/$fixture") . ' ' . escapeshellarg($d));
  if ($ignore !== null) file_put_contents("$d/ignore.txt", $ignore);
  return $d;
}
$base = json_decode((string)(agg($agg, "$repo/tests/fixtures/basic", "$w/base.json") ? file_get_contents("$w/base.json") : ''), true);
t(array_key_exists('ignored', $base) && $base['ignored'] === null, 'no ignore.txt -> report.ignored is null, everything counted (' . $base['summary']['total'] . ' CVEs)');
$d = work($repo, $w, 'a', 'basic', "# test\nCVE-2024-0001 example/db # db only\nCVE-2024-0002 example/web:1.2 until=2026-12-31 # tag exact\nCVE-2024-0003 example/web:1.3 # other tag\n"
  . "CVE-2024-0004 until=2026-01-01 # expired\nGHSA-abcd-efgh-ijkl *\nCVE-2024-9999 nosuchimage\ngarbage line\nCVE-2024-0002 a b\nCVE-2024-0002 until=2026-13-40\nCVE-2024-0002 foo=bar\n");
$o = agg($agg, $d, "$w/a.json"); $r = json_decode((string)file_get_contents("$w/a.json"), true);
$c = []; foreach ($r['cves'] as $x) $c[$x['id']] = $x;
t(array_keys($c) === ['CVE-2024-0001', 'CVE-2024-0003', 'CVE-2024-0004'] && $r['summary']['total'] === 3, 'ignored CVEs leave the counts: ' . implode(',', array_keys($c)));
t(($c['CVE-2024-0001']['image_count'] ?? 0) === 1 && count($c['CVE-2024-0001']['affected']) === 1 && $c['CVE-2024-0001']['affected'][0]['img'] === 0, 'a scoped ignore hides the CVE on that image only');
t(($r['images'][1]['vulns'] ?? -1) === 0 && ($r['images'][0]['vulns'] ?? 0) === 3, 'per-image finding counts exclude the ignored ones');
t(($r['summary']['by_severity']['CRITICAL']['total'] ?? 0) === 1, 'severity counts follow (CRITICAL stays 1 through the web image)');
$g = $r['ignored']; $e = []; foreach ($g['entries'] as $x) $e[$x['id']] = $x;
t($g['count'] === 3 && isset($e['CVE-2024-0001'], $e['CVE-2024-0002'], $e['GHSA-abcd-efgh-ijkl']), 'Ignored list has the 3 hidden entries');
t(($e['CVE-2024-0001']['scope'] ?? '') === 'example/db' && strpos($e['CVE-2024-0001']['image'] ?? '', 'example/db:2') === 0 && ($e['CVE-2024-0001']['reason'] ?? '') === 'db only'
  && ($e['CVE-2024-0002']['until'] ?? '') === '2026-12-31' && ($e['GHSA-abcd-efgh-ijkl']['scope'] ?? '') === '*', 'entries carry scope, image, reason, until');
t(count($g['expired']) === 1 && $g['expired'][0]['id'] === 'CVE-2024-0004' && $g['expired'][0]['until'] === '2026-01-01' && $g['expired'][0]['matches'] === 1,
  'the expired entry is listed, with the number of findings it would have hidden; it hides nothing');
t($g['invalid_count'] === 4 && array_column($g['invalid'], 0) === [8, 9, 10, 11], 'invalid lines counted and listed by line number (' . json_encode(array_column($g['invalid'], 0)) . ')');
t(isset($c['CVE-2024-0003']), 'a different tag in the scope does not hide the CVE');
// notification: the only fixable critical is CVE-2024-0001
$d1 = work($repo, $w, 'n1', 'basic', "CVE-2024-0001 # accepted\n");
t(strpos(agg($agg, $d1, "$w/n1.json"), 'new_fixable_critical=0') !== false, 'an ignored CVE never notifies');
t(strpos(agg($agg, "$repo/tests/fixtures/basic", "$w/n0.json"), 'new_fixable_critical=1') !== false, '(control) without the ignore it does');
$d2 = work($repo, $w, 'n2', 'basic', "CVE-2024-0001 until=2026-11-02 # accepted for a while\n");
$o = agg($agg, $d2, "$w/n2.json");
$r2 = json_decode((string)file_get_contents("$w/n2.json"), true);
t(strpos($o, 'new_fixable_critical=1') !== false && $r2['summary']['total'] === 5 && $r2['ignored']['expired'][0]['matches'] === 2, 'an expired ignore hides nothing and notifies again');
t(strpos(agg($agg, $d2, "$w/n3.json", '2026-11-02'), 'new_fixable_critical=0') !== false, 'the day of until still hides');
// with exploit data (feat KEV): ignored findings are out of the KEV count and never notify as new KEV
function aggx(string $agg, string $work, string $out, string $exploit): string {
  return (string)shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($work) . ' ' . escapeshellarg($out) . ' scope=all registry=yes trivy=x today=2026-11-03 exploit=' . escapeshellarg($exploit) . ' 2>&1');
}
$xf = "$repo/tests/fixtures/exploit";
@unlink("$w/kp.json"); aggx($agg, "$repo/tests/fixtures/basic", "$w/kp.json", $xf);
$kp = json_decode((string)file_get_contents("$w/kp.json"), true);
foreach ($kp['cves'] as &$pc) if ($pc['id'] === 'CVE-2024-0001') $pc['kev'] = null;   // previous report: CVE-2024-0001 not yet KEV
unset($pc);
$kpj = json_encode($kp);
file_put_contents("$w/k0.json", $kpj);
t(strpos(aggx($agg, "$repo/tests/fixtures/basic", "$w/k0.json", $xf), 'new_kev=1') !== false, '(control) a CVE newly on the KEV list notifies');
$dk = work($repo, $w, 'k1', 'basic', "CVE-2024-0001 # accepted\n");
file_put_contents("$w/k1.json", $kpj);
$ok = aggx($agg, $dk, "$w/k1.json", $xf); $rk = json_decode((string)file_get_contents("$w/k1.json"), true);
t(strpos($ok, 'new_kev=0') !== false && ($rk['summary']['kev'] ?? -1) === 1 && !in_array('CVE-2024-0001', array_column($rk['cves'], 'id'), true),
  'an ignored KEV CVE is not counted (summary.kev ' . ($rk['summary']['kev'] ?? '?') . ') and never notifies as new KEV');
// with history/changes (feat export): a CVE hidden by a new ignore entry is not "fixed", and not in the history totals
@mkdir("$w/ch", 0755, true); @unlink("$w/ch/history.jsonl");
agg($agg, "$repo/tests/fixtures/basic", "$w/ch/report.json");
$dc = work($repo, $w, 'ch-work', 'basic', "CVE-2024-0002 # accepted\n");
shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($dc) . ' ' . escapeshellarg("$w/ch/report.json") . ' scope=all registry=yes trivy=x today=2026-11-03 2>&1');
$rc = json_decode((string)file_get_contents("$w/ch/report.json"), true);
$hl = file("$w/ch/history.jsonl"); $hlast = json_decode(end($hl), true);
t(($rc['changes']['fixed'] ?? null) === [] && ($rc['changes']['new'] ?? null) === [] && ($rc['ignored']['count'] ?? 0) === 1,
  'a newly ignored CVE is neither "gone" nor "new" in changes (' . json_encode($rc['changes'] ?? null) . ')');
t(count($hl) === 2 && ($hlast['total'] ?? 0) === 4 && ($hlast['total'] ?? 0) === $rc['summary']['total'], 'history total excludes the ignored CVE (' . ($hlast['total'] ?? '?') . ')');
$j = (string)file_get_contents("$w/a.json");
$d3 = work($repo, $w, 'h', 'basic', "CVE-2024-0001 x # <script>alert(1)</script>\x01\"\n");
agg($agg, $d3, "$w/h.json");
t(strpos((string)file_get_contents("$w/h.json"), '<script>') === false, 'a hostile reason is hex-escaped in report.json');

// ---- aggregate: the OS target (tests/fixtures/os) and the NVD package match (tests/fixtures/ospkg)
$d = work($repo, $w, 'os', 'os', "CVE-2025-2000 os # accepted\nCVE-2025-1000 os\n");
agg($agg, $d, "$w/os.json"); $r = json_decode((string)file_get_contents("$w/os.json"), true);
$c = []; foreach ($r['cves'] as $x) $c[$x['id']] = $x;
t(!isset($c['CVE-2025-2000']) && ($c['CVE-2025-1000']['image_count'] ?? 0) === 1 && $c['CVE-2025-1000']['affected'][0]['img'] === 0, 'scope os hides the OS findings only, the image copy of the CVE stays');
t(($r['ignored']['count'] ?? 0) === 2 && $r['ignored']['entries'][0]['scope'] === 'os', 'OS ignores are listed');
$d = work($repo, $w, 'pkg', 'ospkg', "CVE-2025-9001 os # backported\n");
agg($agg, $d, "$w/pkg.json"); $r = json_decode((string)file_get_contents("$w/pkg.json"), true);
t(array_column($r['cves'], 'id') === ['CVE-2025-9002', 'CVE-2025-9004'] && ($r['ignored']['entries'][0]['id'] ?? '') === 'CVE-2025-9001', 'scope os covers the NVD package match too');
t(($r['host']['suppressed_count'] ?? 0) === 4, 'os-ignore.txt (os/ignore.txt) still works unchanged next to it');
exit($fail);
