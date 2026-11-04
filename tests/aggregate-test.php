<?php
/* tests/aggregate-test.php <repo>: include/aggregate.php against tests/fixtures/basic (hand-written Trivy JSON,
 * schema 2). Prints "ok"/"FAIL" lines; exit 1 on any failure. Work files go to tests/.work/agg. */
$repo = $argv[1];
$agg = "$repo/src/usr/local/emhttp/plugins/unraid-cve-lens/include/aggregate.php";
$w = "$repo/tests/.work/agg"; @mkdir($w, 0755, true);
$out = "$w/report.json"; @unlink($out);
$fail = 0;
function t(bool $c, string $m) { global $fail; echo ($c ? "ok   " : "FAIL ") . "aggregate: $m\n"; if (!$c) $fail = 1; }
function run(string $agg, string $work, string $out): string {
  return (string)shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($work) . ' ' . escapeshellarg($out)
    . ' scope=all registry=yes trivy=0.76.1@sha256:x 2>&1');
}
$o1 = run($agg, "$repo/tests/fixtures/basic", $out);
$r = json_decode((string)@file_get_contents($out), true);
t(is_array($r), "report.json written and valid JSON");
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
t(count($c) === 5, "5 distinct CVEs (malformed entries dropped): " . implode(',', array_keys($c)));
t(($r['summary']['invalid_entries'] ?? -1) === 2, "2 malformed vulnerability entries counted");
t(($c['CVE-2024-0001']['severity'] ?? '') === 'CRITICAL', "CVE rated CRITICAL and HIGH by two images takes the highest");
t(($r['summary']['by_severity']['CRITICAL']['total'] ?? 0) === 1 && ($r['summary']['by_severity']['HIGH']['total'] ?? 0) === 1,
  "each CVE counted once, at its highest severity (CRITICAL=1, HIGH=1)");
t(count($c['CVE-2024-0001']['affected'] ?? []) === 2 && ($c['CVE-2024-0001']['image_count'] ?? 0) === 2, "duplicate row removed, 2 images affected");
t(($c['CVE-2024-0001']['fix'] ?? '') === 'package', "fixed version present -> fix=package (newer image still has it)");
t(($c['CVE-2024-0002']['fix'] ?? '') === 'update', "no package fix but gone from the newer image -> fix=update");
t(($c['CVE-2024-0004']['severity'] ?? '') === 'UNKNOWN', "odd severity -> UNKNOWN");
t(($c['CVE-2024-0004']['fix'] ?? '') === 'update' && ($c['CVE-2024-0003']['fix'] ?? '') === 'both', "will_not_fix but absent from newer image -> update; package fix + absent -> both");
t(($c['GHSA-abcd-efgh-ijkl']['url'] ?? '') === 'https://github.com/advisories/GHSA-abcd-efgh-ijkl', "https advisory URL kept");
$ups = []; foreach ($c['CVE-2024-0001']['affected'] as $a) $ups[] = $a['update'];
t($ups === ['present', 'same'], "per-image registry state: present in newer image / image current (" . implode(',', $ups) . ")");
$im = $r['images'] ?? [];
t(($im[0]['update'] ?? '') === 'newer' && ($im[1]['update'] ?? '') === 'current' && ($im[2]['update'] ?? '') === 'skipped', "image registry states newer/current/skipped");
t(($im[2]['scan'] ?? '') === 'failed' && strpos($im[2]['error'] ?? '', 'timed out') === 0, "failed image listed with its reason");
t(($im[1]['stale'] ?? false) === true && ($im[0]['containers'] ?? []) === ['web', 'web-worker'], "stale flag and container list");
t(!isset($im[0]['digests']), "digests are not published in the report");
t(($r['summary']['images'] ?? 0) === 2 && ($r['summary']['failed'] ?? 0) === 1, "summary: 2 scanned, 1 failed");
t(($r['warnings'] ?? []) === ['Java DB update failed: example'], "warnings carried into the report");
t(strpos($o1, 'new_fixable_critical=1') !== false, "first report: 1 new fixable critical");
$ids = array_column($r['cves'], 'id');
t($ids[0] === 'CVE-2024-0001' && end($ids) === 'CVE-2024-0004', "sorted by severity: " . implode(',', $ids));
$o2 = run($agg, "$repo/tests/fixtures/basic", $out);
t(strpos($o2, 'new_fixable_critical=0') !== false, "second run with the same findings: 0 new fixable critical");
// broken local JSON -> image becomes failed, nothing else breaks
$b = "$w/broken"; @mkdir("$b/local", 0755, true);
file_put_contents("$b/images.tsv", "1\tsha256:" . str_repeat('d', 64) . "\tx:1\tx:1\t0\t\tc\t\n");
file_put_contents("$b/results.tsv", "1\tlocal\tok\t\n");
file_put_contents("$b/local/1.json", "{not json");
run($agg, $b, "$w/broken.json");
$rb = json_decode((string)file_get_contents("$w/broken.json"), true);
t(($rb['images'][0]['scan'] ?? '') === 'failed' && ($rb['images'][0]['error'] ?? '') === 'Trivy output is not valid JSON', "invalid Trivy JSON -> image failed with reason");
t(!array_key_exists('host', $r) || $r['host'] === null, "no OS scan -> host is null");
t(($r['summary']['os'] ?? '') === 'off', "no OS scan -> summary.os=off");

// ---- the Unraid OS as a target (tests/fixtures/os)
$o = "$w/os.json"; @unlink($o);
run($agg, "$repo/tests/fixtures/os", $o);
$r = json_decode((string)@file_get_contents($o), true);
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
$im = $r['images'] ?? [];
t(count($im) === 2 && ($im[0]['kind'] ?? '') === 'image' && ($im[1]['kind'] ?? '') === 'os', "OS appended as a second target, kind=os");
t(($im[1]['name'] ?? '') === 'Unraid OS 7.3.4' && ($im[1]['scan'] ?? '') === 'ok' && ($im[1]['update'] ?? '') === 'na', "OS target named 'Unraid OS 7.3.4', scanned, registry not applicable");
t(($im[1]['vulns'] ?? 0) === 4, "OS target: 4 findings (same CVE at two paths counted twice)");
t(($r['summary']['images'] ?? -1) === 1 && ($r['summary']['os'] ?? '') === 'ok' && ($r['summary']['failed'] ?? -1) === 0, "summary: 1 image, OS ok, the OS is not counted as an image");
t(($c['CVE-2025-1000']['image_count'] ?? 0) === 2, "CVE in an image and in the OS -> 2 targets");
$paths = array_column($c['CVE-2025-2000']['affected'] ?? [], 'path');
t($paths === ['usr/local/unraid-api/node_modules/axios/package.json', 'usr/local/lib/node_modules/npm/node_modules/axios/package.json'],
  "Node.js findings keep the file path of each copy (PkgPath)");
t(($c['CVE-2025-2000']['affected'][0]['img'] ?? -1) === 1 && ($c['CVE-2025-2000']['severity'] ?? '') === 'CRITICAL', "OS finding points at the OS target");
t(($c['CVE-2025-3000']['fix'] ?? '') === 'none', "OS finding without a fixed version -> fix=none");
$h = $r['host'] ?? [];
t(($h['kernel'] ?? '') === '6.18.58-Unraid' && ($h['package_count'] ?? 0) === 4, "host: kernel and 4 package entries");
t(($h['packages'][1] ?? null) === ['docker', '29.8.2', '1_LT'] && ($h['packages'][2] ?? null) === ['kernel-firmware', '20261015_abcdef0', '1']
  && ($h['packages'][3] ?? null) === ['oddname', '', ''], "Slackware names split into name/version/build; an odd entry kept as a name");
// failed OS scan, hostile version and package lines
$f = "$w/osfail"; @mkdir("$f/os", 0755, true);
file_put_contents("$f/images.tsv", ''); file_put_contents("$f/results.tsv", '');
file_put_contents("$f/os/result", "result=failed\nerror=timed out after 30 min (setting: Timeout per image)\nversion=7.3.4\"><script>x</script>\nkernel=6.1\n");
file_put_contents("$f/os/packages.txt", "<img src=x onerror=alert(1)>-1-x86_64-1\n\x01\x02bad\n");
run($agg, $f, "$w/osfail.json");
$rf = json_decode((string)file_get_contents("$w/osfail.json"), true);
t(($rf['images'][0]['scan'] ?? '') === 'failed' && strpos($rf['images'][0]['error'] ?? '', 'timed out') === 0 && ($rf['summary']['failed'] ?? 0) === 1
  && ($rf['summary']['os'] ?? '') === 'failed', "failed OS scan listed with its reason and counted as failed");
t(($rf['host']['name'] ?? '') === 'Unraid OS unknown', "an invalid version string becomes 'unknown'");
t(($rf['host']['packages'][1][0] ?? '') === 'bad' && strpos((string)file_get_contents("$w/osfail.json"), '<img') === false,
  "package lines: control characters stripped, markup hex-escaped in the JSON");
t(($rf['host']['pkg_match'] ?? '') === 'off', "no pkg_result in os/result -> OS package match off");

// ---- OS packages matched against NVD CPEs by Grype (tests/fixtures/ospkg): Trivy rootfs failed, the match worked
$o = "$w/ospkg.json"; @unlink($o);
run($agg, "$repo/tests/fixtures/ospkg", $o);
$r = json_decode((string)@file_get_contents($o), true);
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
$h = $r['host'] ?? [];
t(array_keys($c) === ['CVE-2025-9002', 'CVE-2025-9001', 'CVE-2025-9004'], "Grype matches become CVEs, by severity: " . implode(',', array_keys($c)));
t(($r['images'][0]['scan'] ?? '') === 'failed' && ($r['images'][0]['vulns'] ?? 0) === 3, "OS package findings are kept even though the Trivy rootfs scan failed (3 findings)");
$a = $c['CVE-2025-9001']['affected'] ?? [];
t(count($a) === 1, "same CVE, package and version through two CPEs counted once");
t(($a[0]['pkg'] ?? '') === 'openssl' && ($a[0]['installed'] ?? '') === '3.5.4' && ($a[0]['fixed'] ?? '') === '3.5.5' && ($a[0]['status'] ?? '') === 'fixed'
  && ($a[0]['source'] ?? '') === 'cpe' && ($a[0]['path'] ?? '') === 'cpe openssl:openssl' && ($a[0]['img'] ?? -1) === 0,
  "Grype match: package, installed, fixed, status, matched CPE, source=cpe, OS target");
t(($c['CVE-2025-9001']['severity'] ?? '') === 'HIGH' && ($c['CVE-2025-9001']['fix'] ?? '') === 'package'
  && ($c['CVE-2025-9001']['title'] ?? '') === 'A heap overflow in openssl lets a remote peer crash the service.'
  && ($c['CVE-2025-9001']['url'] ?? '') === 'https://nvd.nist.gov/vuln/detail/CVE-2025-9001', "severity, fix, first sentence as title, NVD link");
t(($c['CVE-2025-9002']['severity'] ?? '') === 'CRITICAL' && ($c['CVE-2025-9002']['fix'] ?? '') === 'none'
  && ($c['CVE-2025-9002']['affected'][0]['status'] ?? '') === 'affected', "not-fixed -> status affected, fix=none");
t(($c['CVE-2025-9004']['severity'] ?? '') === 'LOW' && ($c['CVE-2025-9004']['url'] ?? '') === 'https://example.org/advisory',
  "GHSA id -> related CVE id; Negligible -> LOW; javascript: URL skipped for the next https one");
t(!isset($c['CVE-2025-9003']) && !isset($c['CVE-2025-9005']), "os-ignore.txt entry and RPM-changelog backport are hidden");
$sup = []; foreach ($h['suppressed'] ?? [] as $x) $sup[$x[0]] = $x;
t(($h['suppressed_count'] ?? 0) === 4 && strpos($sup['CVE-2025-9003'][2] ?? '', 'os-ignore.txt: fixed by Lime Tech') === 0
  && ($sup['CVE-2025-9005'][1] ?? '') === 'bash' && strpos($sup['CVE-2025-9005'][2] ?? '', 'changelog') !== false, "hidden matches listed with the reason");
t(($sup['CVE-2025-9006'][2] ?? '') === 'NVD gives no version range (lists every version as affected)' && ($sup['CVE-2025-9007'][2] ?? '') === 'disputed (NVD)'
  && !isset($c['CVE-2025-9006']) && !isset($c['CVE-2025-9007']), "'none (unknown)' constraint and ** DISPUTED ** matches are suppressed, not findings");
t(($r['summary']['invalid_entries'] ?? -1) === 2, "malformed Grype matches counted, not reported");
t(($r['grype'] ?? '') === 'v0.121.0@sha256:0123', "Grype version (from os/result) in the report");
t(($h['pkg_match'] ?? '') === 'ok' && ($h['mapped_count'] ?? 0) === 3 && ($h['package_count'] ?? 0) === 5 && ($h['grype_db'] ?? '') === '2026-11-01T04:12:00Z',
  "host: match ok, 3 of 5 packages mapped, Grype DB date");
t(($h['packages'][1] ?? null) === ['openssl', '3.5.4', '1', 'openssl:openssl'] && ($h['packages'][3] ?? null) === ['aaa_base', '16.0', '3', ''],
  "inventory rows carry the CPE mapping (empty = unmapped)");
t(strpos($r['images'][0]['os'] ?? '', 'Slackware-based (3 OS packages matched against NVD)') === 0, "OS column names the base and the match");
t(strpos((string)file_get_contents($o), '<script') === false && strpos((string)file_get_contents($o), '<b>') === false, "markup from Grype output and the inventory hex-escaped");
// Grype output broken
$g = "$w/ospkgbad"; @mkdir("$g/os", 0755, true);
foreach (['images.tsv', 'results.tsv', 'os/result', 'os/inventory.tsv'] as $fn) copy("$repo/tests/fixtures/ospkg/$fn", "$g/$fn");
file_put_contents("$g/os/pkgmatch.json", "{oops");
run($agg, $g, "$w/ospkgbad.json");
$rb = json_decode((string)file_get_contents("$w/ospkgbad.json"), true);
t(($rb['host']['pkg_match'] ?? '') === 'failed' && in_array('OS package CVE match failed: Grype output is not valid JSON', $rb['warnings'] ?? [], true),
  "invalid Grype JSON -> match failed, warning in the report");

// ---- notification rule: OS CPE matches (source cpe) do not count as new fixable critical
function nfc(string $agg, string $dir, string $out): string {
  @unlink($out);
  return run($agg, $dir, $out);
}
function critwork(string $d, bool $withImage): void {
  @mkdir("$d/os", 0755, true); @mkdir("$d/local", 0755, true);
  file_put_contents("$d/warnings.txt", '');
  file_put_contents("$d/os/result", "result=ok\nversion=7.3.4\npkg_result=ok\npkg_base=slackware\n");
  file_put_contents("$d/os/os.json", '{"SchemaVersion":2,"Results":[]}');
  file_put_contents("$d/os/inventory.tsv", "openssl\t3.5.4\t1\topenssl:openssl\tslackware\n");
  file_put_contents("$d/os/pkgmatch.json", json_encode(['matches' => [['vulnerability' => ['id' => 'CVE-2025-7001', 'severity' => 'Critical',
    'description' => 'x', 'fix' => ['versions' => ['3.5.5'], 'state' => 'fixed']], 'matchDetails' => [['searchedBy' => ['cpes' => ['cpe:2.3:a:openssl:openssl:3.5.4:*:*:*:*:*:*:*']], 'found' => ['versionConstraint' => '< 3.5.5']]],
    'artifact' => ['name' => 'openssl', 'version' => '3.5.4']]], 'descriptor' => ['db' => ['status' => ['built' => '2026-11-01T00:00:00Z']]]]));
  if ($withImage) {
    file_put_contents("$d/images.tsv", "1\tsha256:" . str_repeat('a', 64) . "\texample/app:1\texample/app:1\t0\t\tapp\t\n");
    file_put_contents("$d/results.tsv", "1\tlocal\tok\t\n");
    file_put_contents("$d/local/1.json", json_encode(['SchemaVersion' => 2, 'Results' => [['Target' => 't', 'Class' => 'os-pkgs', 'Type' => 'alpine', 'Vulnerabilities' => [
      ['VulnerabilityID' => 'CVE-2025-7001', 'PkgName' => 'libssl3', 'InstalledVersion' => '3.5.4', 'FixedVersion' => '3.5.5', 'Status' => 'fixed', 'Severity' => 'CRITICAL', 'Title' => 'x']]]]]));
  } else { file_put_contents("$d/images.tsv", ''); file_put_contents("$d/results.tsv", ''); }
}
$cw = "$w/crit-cpe"; critwork($cw, false);
$o = nfc($agg, $cw, "$w/crit-cpe.json");
$rc = json_decode((string)file_get_contents("$w/crit-cpe.json"), true);
t(($rc['cves'][0]['severity'] ?? '') === 'CRITICAL' && ($rc['cves'][0]['fix'] ?? '') === 'package' && ($rc['cves'][0]['affected'][0]['source'] ?? '') === 'cpe'
  && strpos($o, 'new_fixable_critical=0') !== false && ($rc['new_fixable_critical'] ?? -1) === 0,
  "fixable CRITICAL found only by the OS CPE match (source cpe) -> not a new fixable critical");
$cw = "$w/crit-both"; critwork($cw, true);
$o = nfc($agg, $cw, "$w/crit-both.json");
$rc = json_decode((string)file_get_contents("$w/crit-both.json"), true);
$srcs = array_column($rc['cves'][0]['affected'] ?? [], 'source'); sort($srcs);
t(count($rc['cves'] ?? []) === 1 && count($srcs) === 2 && $srcs[0] === 'cpe' && $srcs[1] === 'trivy' && strpos($o, 'new_fixable_critical=1') !== false,
  "the same CRITICAL also found in a container image (source trivy) -> counted as new fixable critical");

// ---- OS package base fallback when os/result has no pkg_base
$bw = "$w/base-slack"; @mkdir("$bw/os", 0755, true);
file_put_contents("$bw/images.tsv", ''); file_put_contents("$bw/results.tsv", '');
file_put_contents("$bw/os/result", "result=ok\nversion=7.3.4\n");
file_put_contents("$bw/os/os.json", '{"SchemaVersion":2,"Results":[]}');
file_put_contents("$bw/os/packages.txt", "bash-5.3.003-x86_64-1\n");
run($agg, $bw, "$w/base-slack.json");
$rs = json_decode((string)file_get_contents("$w/base-slack.json"), true);
t(($rs['host']['base'] ?? '') === 'slackware', "no pkg_base but a non-empty packages.txt -> base slackware");
$bw = "$w/base-none"; @mkdir("$bw/os", 0755, true);
file_put_contents("$bw/images.tsv", ''); file_put_contents("$bw/results.tsv", '');
file_put_contents("$bw/os/result", "result=ok\nversion=7.3.4\n");
file_put_contents("$bw/os/os.json", '{"SchemaVersion":2,"Results":[]}');
@unlink("$bw/os/packages.txt");
run($agg, $bw, "$w/base-none.json");
$rn = json_decode((string)file_get_contents("$w/base-none.json"), true);
t(($rn['host']['base'] ?? '') === 'unknown' && strpos($rn['images'][0]['os'] ?? '', 'Package base not recognised') === 0,
  "no pkg_base and no packages.txt -> base unknown, OS label 'Package base not recognised ...' (" . ($rn['images'][0]['os'] ?? '') . ")");

// ---- genuine Grype v0.121.0 output (tests/fixtures/ospkg-real): trimmed to 6 matches of a real Unraid 7.3.4 run
$o = "$w/ospkg-real.json"; @unlink($o);
run($agg, "$repo/tests/fixtures/ospkg-real", $o);
$raw = (string)@file_get_contents($o);
$r = json_decode($raw, true);
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
$h = $r['host'] ?? [];
t(($h['pkg_match'] ?? '') === 'ok' && ($r['images'][0]['vulns'] ?? 0) === 5 && ($h['suppressed_count'] ?? 0) === 2 && ($r['images'][0]['scan'] ?? '') === 'ok', "real Grype output: match ok, 5 findings, 2 not counted");
$want = ['CVE-2026-111497' => 'CRITICAL', 'CVE-2026-7598' => 'CRITICAL', 'CVE-2026-94300' => 'HIGH',
         'CVE-2026-89092' => 'MEDIUM', 'CVE-2026-95818' => 'LOW'];
$got = []; foreach ($want as $id => $sev) $got[$id] = $c[$id]['severity'] ?? 'missing';
t($got === $want, "real Grype output: CVE ids present, Critical/High/Medium/Low mapped to Trivy names: " . json_encode($got));
t(($c['CVE-2026-111497']['affected'][0]['fixed'] ?? '') === '1.0.10, 1.1.1, 1.2.1' && ($c['CVE-2026-94300']['affected'][0]['fixed'] ?? '') === '9.20.30-s1, 9.20.30, 9.21.27'
  && ($c['CVE-2026-89092']['affected'][0]['fixed'] ?? '') === '2.45' && ($c['CVE-2026-111497']['fix'] ?? '') === 'package',
  "real Grype output: fixed versions carried (single and list), fix=package");
t(($c['CVE-2026-7598']['fix'] ?? '') === 'none' && ($c['CVE-2026-7598']['affected'][0]['fixed'] ?? 'x') === '' && ($c['CVE-2026-7598']['affected'][0]['pkg'] ?? '') === 'libssh2',
  "real Grype output: bounded match without a fix version -> fix=none");
$sup = []; foreach ($h['suppressed'] ?? [] as $x) $sup[$x[0]] = $x;
t(!isset($c['CVE-2026-33845']) && !isset($c['CVE-2019-1010022']) && ($sup['CVE-2026-33845'][1] ?? '') === 'gnutls' && ($sup['CVE-2019-1010022'][1] ?? '') === 'glibc'
  && ($sup['CVE-2026-33845'][2] ?? '') === 'NVD gives no version range (lists every version as affected)',
  "real Grype output: 'none (unknown)' matches (gnutls Critical, glibc Critical) are in host.suppressed with the reason, not in cves");
t(($c['CVE-2026-89092']['affected'][0]['pkg'] ?? '') === 'glibc' && ($c['CVE-2026-89092']['affected'][0]['installed'] ?? '') === '2.44'
  && ($c['CVE-2026-89092']['affected'][0]['path'] ?? '') === 'cpe gnu:glibc', "real Grype output: glibc matched through gnu:glibc");
$sup = $sup ?? [];
$srcs = []; foreach ($c as $x) foreach ($x['affected'] as $a) $srcs[$a['source'] ?? ''] = true;
t(array_keys($srcs) === ['cpe'], "real Grype output: every finding has source cpe");
t(($h['grype_db'] ?? '') === '2026-11-03T06:20:47Z', "real Grype output: DB date taken from descriptor.db.status.built (" . ($h['grype_db'] ?? '') . ")");
t(($r['new_fixable_critical'] ?? -1) === 0, "real Grype output: fixable CRITICAL from the CPE match does not notify");
$ctl = false;
array_walk_recursive($r, function ($v) use (&$ctl) { if (is_string($v) && preg_match('/[\x00-\x08\x0b-\x1f\x7f]/', $v)) $ctl = true; });
t(!$ctl && !preg_match('/[\x00-\x08\x0b-\x1f]/', $raw), "real Grype output: no control characters anywhere in the report");

// ---- previous report's critical set follows the same rule
$cw = "$w/crit-both"; critwork($cw, true);
$prevCpe = ['cves' => [['id' => 'CVE-2025-7001', 'severity' => 'CRITICAL', 'fix' => 'package', 'affected' => [['img' => 0, 'source' => 'cpe']]]]];
file_put_contents("$w/crit-prev.json", json_encode($prevCpe));
$o = run($agg, $cw, "$w/crit-prev.json");
t(strpos($o, 'new_fixable_critical=1') !== false, "previous report had the CVE only through source cpe, now also in an image -> new fixable critical");
$prevOld = ['cves' => [['id' => 'CVE-2025-7001', 'severity' => 'CRITICAL', 'fix' => 'package', 'affected' => [['img' => 0]]]]];
file_put_contents("$w/crit-prev2.json", json_encode($prevOld));
$o = run($agg, $cw, "$w/crit-prev2.json");
t(strpos($o, 'new_fixable_critical=0') !== false, "previous report entry without a source key counts as known -> 0 new fixable critical");
// ---- "not counted" only on positive evidence (review findings): grouped per CVE/package/version, anchored marker
$pw = "$w/ospkg-evidence"; @mkdir("$pw/os", 0755, true);
foreach (['images.tsv', 'results.tsv', 'warnings.txt', 'os/result', 'os/os.json', 'os/inventory.tsv', 'os/packages.txt'] as $f)
  if (is_file("$repo/tests/fixtures/ospkg-real/$f")) copy("$repo/tests/fixtures/ospkg-real/$f", "$pw/$f");
$gm = function (string $id, ?string $vc, string $desc) {
  $found = ['cpes' => ['cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*']]; if ($vc !== null) $found['versionConstraint'] = $vc;
  return ['vulnerability' => ['id' => $id, 'severity' => 'High', 'description' => $desc, 'fix' => ['state' => 'unknown']],
          'artifact' => ['name' => 'glibc', 'version' => '2.44'],
          'matchDetails' => [['type' => 'cpe-match', 'searchedBy' => ['cpes' => ['cpe:2.3:a:gnu:glibc:2.44:*:*:*:*:*:*:*']], 'found' => $found]]];
};
file_put_contents("$pw/os/pkgmatch.json", json_encode(['descriptor' => ['db' => ['status' => ['built' => '2026-11-03T06:20:47Z']]], 'matches' => [
  $gm('CVE-2030-0001', null, 'No constraint field at all.'),
  $gm('CVE-2030-0002', 'none (unknown)', 'Listed twice, once without a range.'),
  $gm('CVE-2030-0002', '< 2.45 (unknown)', 'Listed twice, once with a range.'),
  $gm('CVE-2030-0003', '< 2.45 (unknown)', 'A flaw. The vendor says DISPUTED in the middle of the text.'),
  $gm('CVE-2030-0004', '< 2.45 (unknown)', '** DISPUTED ** A flaw that the vendor disputes.'),
  $gm('CVE-2030-0005', 'none (unknown)', 'Only without a range.'),
]]));
run($agg, $pw, "$w/evidence.json");
$r = json_decode((string)@file_get_contents("$w/evidence.json"), true);
$ids = array_column($r['cves'] ?? [], 'id'); sort($ids);
$sup = []; foreach ($r['host']['suppressed'] ?? [] as $x) $sup[$x[0]] = $x[2];
t($ids === ['CVE-2030-0001', 'CVE-2030-0002', 'CVE-2030-0003'], "counted: no constraint field, a range in any duplicate match, 'DISPUTED' not as NVD's leading marker (" . implode(',', $ids) . ")");
t(($sup['CVE-2030-0004'] ?? '') === 'disputed (NVD)' && ($sup['CVE-2030-0005'] ?? '') === 'NVD gives no version range (lists every version as affected)' && count($sup) === 2,
  "not counted: leading '** DISPUTED **' marker; no range in every match (" . json_encode($sup) . ")");
exit($fail);
