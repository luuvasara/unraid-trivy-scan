<?php
/* unraid-trivy-scan: merge the per-image Trivy JSON results of one run into report.json (one entry per CVE).
 * CLI only: php aggregate.php <workdir> <report.json> [scope=..] [registry=yes|no] [trivy=..] [cache=<dir>]
 * <workdir> holds images.tsv, results.tsv, warnings.txt, local/<n>.json and remote/<n>.json (scripts/trivy-scan),
 * and, when the Unraid OS was scanned, os/result (key=value), os/os.json and os/packages.txt. The OS becomes one
 * more target in 'images' (kind "os"); its Slackware package list goes to 'host' (not CVE-matched by Trivy).
 * Prints new_fixable_critical=<n>: critical CVEs with a fix that were not in the previous report.
 * Every string from Trivy output is treated as untrusted: types are checked, lengths capped, control characters
 * removed, links kept only when they are plain https URLs. The pages escape on output. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
/* A fatal error (memory_limit, ...) ends PHP with exit 255 and, with Unraid's php.ini, prints nothing: say what happened
 * on stderr, which scripts/trivy-scan writes to its log. */
register_shutdown_function(function () {
  $e = error_get_last();
  if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
    fwrite(STDERR, sprintf("PHP fatal error: %s (%s:%d); peak memory %d MB of memory_limit %s\n", $e['message'],
      basename($e['file']), $e['line'], (int)(memory_get_peak_usage(true) / 1048576), ini_get('memory_limit')));
  }
});

const SEV_RANK = ['UNKNOWN' => 0, 'LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];

function s($v, int $max = 200): string {
  if (!is_string($v) && !is_int($v) && !is_float($v)) return '';
  $v = (string)$v;
  if (function_exists('mb_scrub')) $v = mb_scrub($v, 'UTF-8');           // invalid UTF-8 -> '?'
  $v = trim(preg_replace('/[\x00-\x1f\x7f]+/', ' ', $v) ?? '');
  return function_exists('mb_substr') ? mb_substr($v, 0, $max, 'UTF-8') : substr($v, 0, $max);
}
function url_ok($u): string {
  $u = s($u, 500);
  return preg_match('~^https://[A-Za-z0-9.-]+(/[^\s"\'<>\\\\`]*)?$~', $u) ? $u : '';
}
function read_tsv(string $f, int $cols): array {
  $rows = [];
  foreach (@file($f, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
    $r = explode("\t", $line);
    if (count($r) < $cols) $r = array_pad($r, $cols, '');
    $rows[] = $r;
  }
  return $rows;
}
function kv_file(string $f): array {   // key=value lines (written by scripts/trivy-scan); values are data
  $out = [];
  foreach (@file($f, FILE_IGNORE_NEW_LINES) ?: [] as $line) if (preg_match('/^([a-z_]+)=(.*)$/', $line, $m)) $out[$m[1]] = $m[2];
  return $out;
}
function load_json(string $f): ?array {
  $raw = @file_get_contents($f);
  if ($raw === false) return null;
  $j = json_decode($raw, true, 64);
  return is_array($j) ? $j : null;
}
/* All vulnerabilities of one Trivy result: [[id, sev, pkg, installed, fixed, status, target, title, url, path], ...] */
function vulns(array $j, int &$bad): array {
  $out = [];
  foreach ((is_array($j['Results'] ?? null) ? $j['Results'] : []) as $res) {
    if (!is_array($res)) continue;
    $target = preg_replace('/sha256:([0-9a-f]{12})[0-9a-f]{52}/', 'sha256:$1...', s($res['Target'] ?? '', 200)) ?? '';
    foreach ((is_array($res['Vulnerabilities'] ?? null) ? $res['Vulnerabilities'] : []) as $v) {
      if (!is_array($v)) { $bad++; continue; }
      $id = s($v['VulnerabilityID'] ?? '', 100);
      if (!preg_match('/^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,90}$/', $id)) { $bad++; continue; }
      $sev = strtoupper(s($v['Severity'] ?? '', 10));
      if (!isset(SEV_RANK[$sev])) $sev = 'UNKNOWN';
      $out[] = [$id, $sev, s($v['PkgName'] ?? '', 200), s($v['InstalledVersion'] ?? '', 100),
                s($v['FixedVersion'] ?? '', 200), s($v['Status'] ?? '', 30), $target,
                s($v['Title'] ?? '', 300), url_ok($v['PrimaryURL'] ?? ''), s($v['PkgPath'] ?? '', 300)];
    }
  }
  return $out;
}

[$self, $work, $outFile] = array_pad($argv, 3, null);
if (!$work || !$outFile || !is_dir($work)) { fwrite(STDERR, "usage: aggregate.php <workdir> <report.json> [key=value...]\n"); exit(2); }
$opt = ['scope' => 'running', 'registry' => 'no', 'trivy' => '', 'cache' => ''];
foreach (array_slice($argv, 3) as $a) if (preg_match('/^([a-z]+)=(.*)$/', $a, $m) && isset($opt[$m[1]])) $opt[$m[1]] = $m[2];

$images = []; $byIdx = [];
foreach (read_tsv("$work/images.tsv", 8) as [$idx, $id, $disp, $ref, $stale, $dig, $cont, $noref]) {
  if (!preg_match('/^[0-9]+$/', $idx)) continue;
  $byIdx[$idx] = count($images);
  $images[] = [
    'kind' => 'image', 'id' => s($id, 80), 'name' => s($disp, 250), 'ref' => s($ref, 200), 'stale' => $stale === '1',
    'containers' => array_values(array_filter(array_map(fn($c) => s($c, 100), explode(',', $cont)), 'strlen')),
    'digests' => array_values(array_filter(array_map(fn($c) => s($c, 300), explode(',', $dig)), 'strlen')),
    'scan' => 'failed', 'error' => 'no result', 'os' => '', 'vulns' => 0,
    'update' => $opt['registry'] === 'yes' ? 'skipped' : 'off', 'update_note' => s($noref, 200),
  ];
}
foreach (read_tsv("$work/results.tsv", 4) as [$idx, $kind, $res, $why]) {
  if (!isset($byIdx[$idx])) continue;
  $im = &$images[$byIdx[$idx]];
  if ($kind === 'local') { $im['scan'] = $res === 'ok' ? 'ok' : 'failed'; $im['error'] = $res === 'ok' ? '' : s($why, 300); }
  if ($kind === 'remote') {
    if ($res === 'ok') $im['update'] = 'checked';
    elseif ($res === 'failed') { $im['update'] = 'failed'; $im['update_note'] = s($why, 300); }
    else { $im['update'] = 'skipped'; $im['update_note'] = s($why, 200); }
  }
  unset($im);
}

// the Unraid OS, scanned as one more target
$host = null; $osN = null;
if (is_file("$work/os/result")) {
  $kv = kv_file("$work/os/result");
  $ver = s($kv['version'] ?? '', 40);
  if (!preg_match('/^[0-9A-Za-z.+_-]{1,40}$/', $ver)) $ver = 'unknown';
  $pk = [];
  foreach (array_slice(@file("$work/os/packages.txt", FILE_IGNORE_NEW_LINES) ?: [], 0, 3000) as $line) {
    $line = s($line, 200);
    if ($line === '') continue;
    // Slackware package entry: name-version-arch-build (the name itself may contain dashes)
    $pk[] = preg_match('/^(.+)-([^-]+)-([^-]+)-([^-]+)$/', $line, $m) ? [$m[1], $m[2], $m[4]] : [$line, '', ''];
  }
  $host = ['name' => "Unraid OS $ver", 'version' => $ver, 'kernel' => s($kv['kernel'] ?? '', 60),
           'packages' => $pk, 'package_count' => count($pk)];
  $osN = count($images);
  $ok = ($kv['result'] ?? '') === 'ok';
  $images[] = ['kind' => 'os', 'id' => '', 'name' => $host['name'], 'ref' => '', 'stale' => false, 'containers' => [],
               'digests' => [], 'scan' => $ok ? 'ok' : 'failed', 'error' => $ok ? '' : (s($kv['error'] ?? '', 300) ?: 'no result'),
               'os' => 'Slackware-based (OS packages not CVE-matched)', 'vulns' => 0, 'update' => 'na', 'update_note' => ''];
}

$cves = []; $bad = 0;
$targets = $byIdx;
if ($osN !== null) $targets['os'] = $osN;
foreach ($targets as $idx => $n) {
  $im = &$images[$n];
  if ($im['scan'] !== 'ok') { unset($im); continue; }
  $j = load_json($idx === 'os' ? "$work/os/os.json" : "$work/local/$idx.json");
  if ($j === null) { $im['scan'] = 'failed'; $im['error'] = 'Trivy output is not valid JSON'; unset($im); continue; }
  $os = $j['Metadata']['OS'] ?? null;
  if (is_array($os)) $im['os'] = trim(s($os['Family'] ?? '', 30) . ' ' . s($os['Name'] ?? '', 30));
  // registry comparison: CVE ids present in the image the tag points to now
  $remote = null;
  if ($im['update'] === 'checked') {
    $rj = load_json("$work/remote/$idx.json");
    if ($rj === null) { $im['update'] = 'failed'; $im['update_note'] = 'registry scan output is not valid JSON'; }
    else {
      $rd = is_array($rj['Metadata']['RepoDigests'] ?? null) ? array_map(fn($d) => s($d, 300), $rj['Metadata']['RepoDigests']) : [];
      $hashes = fn($list) => array_map(fn($d) => substr($d, strrpos($d, '@') ?: 0), $list);
      if ($rd && array_intersect($hashes($rd), $hashes($im['digests']))) { $im['update'] = 'current'; }
      else {
        $im['update'] = 'newer'; $remote = [];
        $dummy = 0;
        foreach (vulns($rj, $dummy) as $v) $remote[$v[0]] = true;
      }
    }
  }
  $seen = [];
  foreach (vulns($j, $bad) as [$id, $sev, $pkg, $inst, $fix, $st, $tgt, $title, $url, $path]) {
    $key = "$id|$pkg|$inst|$tgt|$path";
    if (isset($seen[$key])) continue;
    $seen[$key] = true;
    if (!isset($cves[$id])) $cves[$id] = ['id' => $id, 'severity' => $sev, 'title' => $title, 'url' => $url,
                                          'fix' => 'none', 'affected' => [], 'images' => []];
    $c = &$cves[$id];
    if (SEV_RANK[$sev] > SEV_RANK[$c['severity']]) $c['severity'] = $sev;
    if ($c['title'] === '' && $title !== '') $c['title'] = $title;
    if ($c['url'] === '' && $url !== '') $c['url'] = $url;
    $inUpdate = $remote === null ? ($im['update'] === 'current' ? 'same' : '') : (isset($remote[$id]) ? 'present' : 'gone');
    $c['affected'][] = ['img' => $n, 'pkg' => $pkg, 'installed' => $inst, 'fixed' => $fix, 'status' => $st,
                        'target' => $tgt, 'path' => $path, 'severity' => $sev, 'update' => $inUpdate];
    $c['images'][$n] = true;
    unset($c);
    $im['vulns']++;
  }
  unset($im, $j, $rj, $remote, $seen);   // a decoded Trivy result can be hundreds of MB: free it before the next one
}

$summary = ['total' => 0, 'fixable' => 0, 'images' => 0, 'failed' => 0, 'invalid_entries' => $bad,
            'os' => $osN === null ? 'off' : $images[$osN]['scan']];
foreach (array_keys(SEV_RANK) as $sv) $summary['by_severity'][$sv] = ['total' => 0, 'fixable' => 0];
foreach ($cves as &$c) {
  $pkgFix = false; $updFix = false;
  foreach ($c['affected'] as $a) { if ($a['fixed'] !== '') $pkgFix = true; if ($a['update'] === 'gone') $updFix = true; }
  $c['fix'] = $pkgFix ? ($updFix ? 'both' : 'package') : ($updFix ? 'update' : 'none');
  $c['image_count'] = count($c['images']); unset($c['images']);
  $summary['total']++; $summary['by_severity'][$c['severity']]['total']++;
  if ($c['fix'] !== 'none') { $summary['fixable']++; $summary['by_severity'][$c['severity']]['fixable']++; }
}
unset($c);
foreach ($images as $im) { if ($im['scan'] !== 'ok') $summary['failed']++; elseif ($im['kind'] === 'image') $summary['images']++; }
usort($cves, fn($a, $b) => [SEV_RANK[$b['severity']], $b['image_count'], $a['id']] <=> [SEV_RANK[$a['severity']], $a['image_count'], $b['id']]);

$db = null;
if ($opt['cache'] !== '' && ($m = load_json($opt['cache'] . '/db/metadata.json'))) {
  $db = ['updated' => s($m['UpdatedAt'] ?? '', 40), 'next' => s($m['NextUpdate'] ?? '', 40)];
}
$warnings = array_values(array_filter(array_map(fn($l) => s($l, 300), @file("$work/warnings.txt", FILE_IGNORE_NEW_LINES) ?: []), 'strlen'));

// new fixable critical CVEs compared with the previous report
$critNow = [];
foreach ($cves as $c) if ($c['severity'] === 'CRITICAL' && $c['fix'] !== 'none') $critNow[$c['id']] = true;
$prev = load_json($outFile);
$critPrev = [];
foreach ((is_array($prev['cves'] ?? null) ? $prev['cves'] : []) as $c) {
  if (is_array($c) && ($c['severity'] ?? '') === 'CRITICAL' && ($c['fix'] ?? 'none') !== 'none' && is_string($c['id'] ?? null)) $critPrev[$c['id']] = true;
}
$new = count(array_diff_key($critNow, $critPrev));

$report = [
  'format' => 1, 'generated' => time(), 'trivy' => s($opt['trivy'], 120), 'db' => $db,
  'scope' => $opt['scope'] === 'all' ? 'all' : 'running', 'registry' => $opt['registry'] === 'yes',
  'summary' => $summary, 'new_fixable_critical' => $new, 'warnings' => $warnings,
  'images' => $images, 'cves' => $cves, 'host' => $host,
];
foreach ($report['images'] as &$im) unset($im['digests']);
unset($im);
$json = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_HEX_TAG | JSON_HEX_AMP);
if ($json === false) { fwrite(STDERR, "json_encode failed\n"); exit(1); }
@mkdir(dirname($outFile), 0755, true);
$tmp = "$outFile.tmp." . getmypid();
if (file_put_contents($tmp, $json) === false || !rename($tmp, $outFile)) { @unlink($tmp); fwrite(STDERR, "cannot write $outFile\n"); exit(1); }
echo "cves={$summary['total']}\nnew_fixable_critical=$new\npeak_memory_mb=" . (int)(memory_get_peak_usage(true) / 1048576) . "\n";
