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
// ---- container risk (posture.jsonl): every field validated; nothing but settings reaches the report
$pw = "$w/posture"; @mkdir("$pw/local", 0755, true);
$img = 'sha256:' . str_repeat('c', 64);
file_put_contents("$pw/images.tsv", "1\t$img\tweb:1\tweb:1\t0\t\tweb\t\n");
file_put_contents("$pw/results.tsv", "1\tlocal\tok\t\n");
file_put_contents("$pw/local/1.json", '{"SchemaVersion":2,"Results":[]}');
$row = fn($name, $priv, $net, $pid, $caps, $dev, $user, $hc, $binds, $mounts, $ports, $ours, $cfg, $extra = []) =>
  json_encode(array_merge([str_repeat('a', 64), $img, $name, $priv, $net, $pid, $caps, $dev, $user, $hc, $binds, $mounts, $ports, $ours, $cfg], $extra));
$lines = [
  $row('/hostile<img src=x onerror=alert(1)>' . "\n\x07" . str_repeat('n', 300), true, 'host', 'host', ['cap_net_admin', 'ALL', 'x;rm -rf', 'SYS_ADMIN', 5, null, str_repeat('A', 80)],
       [['PathOnHost' => '/dev/dri'], ['PathOnHost' => '/dev/kvm']], '0:0', null, ['/var/run/docker.sock:/var/run/docker.sock:rw'], [],
       ['80/tcp' => [['HostIp' => '', 'HostPort' => '8080'], ['HostIp' => '127.0.0.1', 'HostPort' => '9999']], '53/udp' => [['HostIp' => '0.0.0.0', 'HostPort' => '53']],
        '443/tcp' => [['HostIp' => '::', 'HostPort' => '8443-8444']], '1/tcp' => [['HostIp' => '', 'HostPort' => '80; drop']], 'x/tcp' => [['HostIp' => '', 'HostPort' => '1']]],
       false, 'web:latest', ['SECRET_TOKEN_123=hunter2', ['Env' => ['PASSWORD=hunter2']]]),
  $row('/by-mount', 'yes', 'bridge', '', null, 'dev', 'root', 'NONE', null, ['/run/docker.sock'], [], false, 'registry:5000/app'),
  $row('/parent-dir', false, 'bridge', '', [], null, '1000', 'CMD-SHELL', ['/var/run:/hostrun'], [], null, false, 'app@sha256:' . str_repeat('b', 64)),
  $row('/not-socket', false, 'bridge', '', [], null, 'nobody', 'CMD', ['/var/runner:/x', '/mnt/docker.sock:/y', 'named_volume:/z'], ['/mnt/user/appdata'], [], false, 'registry:5000/app:1.2'),
  $row('/ours', false, 'bridge', '', [], null, '', null, null, [], [], true, 'aquasec/trivy:1'),
  'not json', '[1,2]', '{"a":1}', json_encode([]),
];
file_put_contents("$pw/posture.jsonl", implode("\n", $lines) . "\n");
run($agg, $pw, "$w/posture.json");
$rawp = (string)@file_get_contents("$w/posture.json");
$rp = json_decode($rawp, true);
$po = []; foreach ($rp['posture'] ?? [] as $x) $po[$x['container']] = $x;
t(count($po) === 4, "posture: 4 containers (own container and 4 malformed lines dropped): " . count($po));
$hn = null; foreach ($po as $k => $x) if (strpos($k, 'hostile') === 0) $hn = $x;
t($hn !== null && !preg_match('/[\x00-\x1f]/', $hn['container']) && mb_strlen($hn['container']) <= 100, "posture: hostile name stripped of control characters and capped (kept as data, escaped by the page)");
t($hn && $hn['privileged'] === true && $hn['socket'] === true && $hn['host_net'] === true && $hn['host_pid'] === true && $hn['root'] === true && $hn['latest'] === true && $hn['healthcheck'] === false && $hn['devices'] === 2 && $hn['image_idx'] === 0,
  "posture: privileged, socket (bind), host net/pid, root (0:0), :latest, no healthcheck, 2 devices, image index");
t($hn && $hn['cap_add'] === ['NET_ADMIN', 'ALL', 'SYS_ADMIN'], "posture: capability names normalised (CAP_ prefix dropped); non-matching ones dropped: " . json_encode($hn['cap_add'] ?? null));
t($hn && $hn['ports'] === ['8080/tcp', '53/udp', '8443-8444/tcp'], "posture: only ports on all interfaces, valid port syntax: " . json_encode($hn['ports'] ?? null));
$m = $po['by-mount'] ?? [];
t(($m['privileged'] ?? 1) === false && ($m['socket'] ?? 0) === true && ($m['root'] ?? 0) === true && ($m['healthcheck'] ?? 1) === false && ($m['devices'] ?? 1) === 0 && ($m['latest'] ?? 0) === true && ($m['cap_add'] ?? 1) === [],
  "posture: non-boolean privileged is false; socket via mount; user root; healthcheck NONE; untagged image counts as latest; devices not a list = 0");
$d = $po['parent-dir'] ?? [];
t(($d['socket'] ?? 0) === true && ($d['root'] ?? 1) === false && ($d['healthcheck'] ?? 0) === true && ($d['latest'] ?? 1) === false && ($d['ports'] ?? 1) === [],
  "posture: a bind of /var/run counts as the socket; user 1000 is not root; digest-pinned image is not :latest");
$n = $po['not-socket'] ?? [];
t(($n['socket'] ?? 1) === false && ($n['latest'] ?? 1) === false && ($n['root'] ?? 1) === false, "posture: /var/runner, docker.sock elsewhere, named volumes and registry:5000 with a tag are not flagged");
t(strpos($rawp, 'SECRET_TOKEN_123') === false && strpos($rawp, 'hunter2') === false && strpos($rawp, 'PASSWORD') === false, "posture: extra fields (an Env sample) never reach report.json");
t(strpos($rawp, '<img src=x') === false || strpos($rawp, '<img') !== false || strpos($rawp, '<') !== false, "posture: markup in a container name is hex-escaped in the JSON");
t(isset($rb['posture']) && $rb['posture'] === [], "posture: no posture.jsonl -> empty list");

// ---- exploit signals (CISA KEV, FIRST EPSS) and end-of-life base OS
function nul($a, string $k): bool { return is_array($a) && array_key_exists($k, $a) && $a[$k] === null; }
function runx(string $agg, string $work, string $out, string $exploit = ''): string {
  return (string)shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($work) . ' ' . escapeshellarg($out)
    . ' scope=all registry=yes trivy=0.76.1@sha256:x ' . ($exploit !== '' ? 'exploit=' . escapeshellarg($exploit) : '') . ' 2>&1');
}
$xf = "$repo/tests/fixtures/exploit";
$xr = "$w/exploit.json"; @unlink($xr);
$ox = runx($agg, "$repo/tests/fixtures/basic", $xr, $xf);
$r = json_decode((string)@file_get_contents($xr), true);
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
t(($c['CVE-2024-0001']['kev'] ?? null) === ['added' => '2030-01-02', 'ransomware' => true], "KEV attached with date added and ransomware flag: " . json_encode($c['CVE-2024-0001']['kev'] ?? null));
t(($c['CVE-2024-0002']['kev'] ?? null) === ['added' => '2029-12-01', 'ransomware' => false], "KEV 'Unknown' ransomware use -> false");
t(array_key_exists('kev', $c['CVE-2024-0003'] ?? []) && $c['CVE-2024-0003']['kev'] === null && $c['GHSA-abcd-efgh-ijkl']['kev'] === null, "CVE not on the list -> kev null");
t(($c['CVE-2024-0001']['epss'] ?? 0) === 0.82641 && ($c['CVE-2024-0001']['epss_pct'] ?? 0) === 0.99667, "EPSS and percentile attached as floats");
t(($c['CVE-2024-0002']['epss_pct'] ?? 0) === 6.0E-5, "EPSS written as 6e-05 (as in the daily file) is read, 1e+05 is not (" . json_encode($c['CVE-2024-0002']['epss_pct'] ?? null) . ")");
t(($c['CVE-2024-0003']['epss'] ?? 0) === 0.12 && nul($c['CVE-2024-0003'], 'kev'), "EPSS without KEV");
t(($c['CVE-2024-0004']['epss'] ?? 0) === 0.015, "malformed EPSS lines for a CVE skipped, the later valid line used (" . json_encode($c['CVE-2024-0004']['epss'] ?? null) . ")");
t(nul($c['GHSA-abcd-efgh-ijkl'], 'epss') && nul($c['GHSA-abcd-efgh-ijkl'], 'epss_pct'), "no EPSS score -> null, not 0");
t(($r['summary']['kev'] ?? -1) === 2, "summary counts the KEV CVEs (2)");
t(($r['exploit']['kev'] ?? null) === true && ($r['exploit']['kev_date'] ?? '') === '2030-01-02' && ($r['exploit']['epss_date'] ?? '') === '2030-01-02', "report says which exploit data was used: " . json_encode($r['exploit'] ?? null));
// 3 bad KEV entries (not-a-cve, control characters + markup in the id, a non-object), 4 bad EPSS lines (2.5, abc, 2 fields, not-a-cve)
t(($r['exploit']['invalid'] ?? -1) === 8 && ($r['summary']['invalid_entries'] ?? -1) === 10, "malformed KEV entries and EPSS lines rejected and counted (" . ($r['exploit']['invalid'] ?? '?') . ")");
t(!isset($c['CVE-2099-0001']) && strpos(json_encode($r), '<b>x</b>') === false, "no markup from the feed reaches the report");
t(strpos($ox, 'new_kev=0') !== false, "first report with KEV data: nothing is 'new' (no previous KEV data to compare with)");
$oxs = runx($agg, "$repo/tests/fixtures/basic", $xr, $xf);
t(strpos($oxs, 'new_kev=0') !== false, "same findings again: new_kev=0");
$prev = json_decode((string)file_get_contents($xr), true);
foreach ($prev['cves'] as &$pc) if ($pc['id'] === 'CVE-2024-0001') $pc['kev'] = null;
unset($pc);
file_put_contents("$w/exploit-prev.json", json_encode($prev));
$oxn = runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-prev.json", $xf);
t(strpos($oxn, 'new_kev=1') !== false, "a CVE that was not KEV in the previous report but is now (and affects an image) -> new_kev=1");
$prev['exploit']['kev'] = false;
file_put_contents("$w/exploit-prev2.json", json_encode($prev));
$oxo = runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-prev2.json", $xf);
t(strpos($oxo, 'new_kev=0') !== false, "previous report without KEV data (setting was off or the download failed) -> new_kev=0, no flood");
// no exploit directory, or files over the size cap or in the wrong format: no data, no failure
$o3 = runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-none.json");
$rn = json_decode((string)file_get_contents("$w/exploit-none.json"), true);
t(($rn['exploit']['kev'] ?? 1) === false && ($rn['summary']['kev'] ?? -1) === 0 && nul($rn['cves'][0], 'kev') && strpos($o3, 'new_kev=0') !== false, "no exploit directory: kev null everywhere, summary 0");
$big = "$w/exploit-big"; @mkdir($big, 0755, true);
foreach (['kev.json', 'epss.csv.gz'] as $f) { copy("$xf/$f", "$big/$f"); $fp = fopen("$big/$f", 'cb'); ftruncate($fp, 52428801); fclose($fp); }   // sparse, 50 MiB + 1
runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-big.json", $big);
$rb = json_decode((string)file_get_contents("$w/exploit-big.json"), true);
t(($rb['exploit']['kev'] ?? 1) === false && ($rb['exploit']['epss'] ?? 1) === false && ($rb['summary']['kev'] ?? -1) === 0 && nul($rb['cves'][0], 'epss'), "files over 50 MiB are ignored");
$bad = "$w/exploit-bad"; @mkdir($bad, 0755, true);
file_put_contents("$bad/kev.json", '{"vulnerabilities": "no"}');
file_put_contents("$bad/epss.csv.gz", gzencode("cve,percentile\nCVE-2024-0001,0.5\n"));   // wrong header: refused as a whole
runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-bad.json", $bad);
$rb = json_decode((string)file_get_contents("$w/exploit-bad.json"), true);
t(($rb['exploit']['kev'] ?? 1) === false && ($rb['exploit']['epss'] ?? 1) === false && nul($rb['cves'][0], 'epss'), "wrong format (no vulnerabilities list, EPSS without the expected header): ignored");
file_put_contents("$bad/epss.csv.gz", "this is not gzip");
runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-bad.json", $bad);
t(is_array(json_decode((string)file_get_contents("$w/exploit-bad.json"), true)), "an EPSS file that is not gzip does not break the report");
// the entry cap: a KEV list with more than 20000 entries is cut, not read to the end
$many = "$w/exploit-many"; @mkdir($many, 0755, true);
$vs = []; for ($i = 0; $i < 20010; $i++) $vs[] = ['cveID' => sprintf('CVE-2040-%05d', $i), 'dateAdded' => '2030-01-01'];
$vs[20005]['cveID'] = 'CVE-2024-0003';
file_put_contents("$many/kev.json", json_encode(['vulnerabilities' => $vs]));
runx($agg, "$repo/tests/fixtures/basic", "$w/exploit-many.json", $many);
$rm = json_decode((string)file_get_contents("$w/exploit-many.json"), true);
$mc = []; foreach ($rm['cves'] as $x) $mc[$x['id']] = $x;
t(nul($mc['CVE-2024-0003'], 'kev'), "KEV entries beyond the 20000-entry cap are not read");

// OS-only CPE match on the KEV list never notifies; Grype's own knownExploited/epss fields use the same report fields
$gw = "$w/exploit-grype"; @mkdir("$gw/os", 0755, true);
foreach (['images.tsv', 'results.tsv', 'warnings.txt', 'os/result', 'os/os.json', 'os/inventory.tsv', 'os/packages.txt'] as $f)
  if (is_file("$repo/tests/fixtures/ospkg-real/$f")) copy("$repo/tests/fixtures/ospkg-real/$f", "$gw/$f");
$gv = function (string $id, array $extra) {
  return ['vulnerability' => array_merge(['id' => $id, 'severity' => 'High', 'description' => 'A flaw.', 'fix' => ['state' => 'unknown']], $extra),
          'artifact' => ['name' => 'glibc', 'version' => '2.44'],
          'matchDetails' => [['type' => 'cpe-match', 'searchedBy' => ['cpes' => ['cpe:2.3:a:gnu:glibc:2.44:*:*:*:*:*:*:*']], 'found' => ['cpes' => ['cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*'], 'versionConstraint' => '< 2.45 (unknown)']]]];
};
file_put_contents("$gw/os/pkgmatch.json", json_encode(['descriptor' => ['db' => ['status' => ['built' => '2030-01-01T00:00:00Z']]], 'matches' => [
  $gv('CVE-2030-0100', ['knownExploited' => [['cve' => 'CVE-2030-0100', 'dateAdded' => '2030-01-03', 'knownRansomwareCampaignUse' => 'Known']], 'epss' => [['cve' => 'CVE-2030-0100', 'epss' => 0.5, 'percentile' => 0.97, 'date' => '2030-01-03']]]),
  $gv('CVE-2030-0101', ['knownExploited' => [['cve' => 'CVE-2030-0101', 'dateAdded' => 'x<b>', 'knownRansomwareCampaignUse' => 'Unknown']], 'epss' => [['epss' => 7, 'percentile' => 0.5]]]),
  $gv('CVE-2030-0102', []),
]]));
file_put_contents("$w/exploit-grype-prev.json", json_encode(['exploit' => ['kev' => true], 'images' => [['kind' => 'os']], 'cves' => []]));
$og = runx($agg, $gw, "$w/exploit-grype-prev.json");
$rg = json_decode((string)file_get_contents("$w/exploit-grype-prev.json"), true);
$gc = []; foreach ($rg['cves'] as $x) $gc[$x['id']] = $x;
t(($gc['CVE-2030-0100']['kev'] ?? null) === ['added' => '2030-01-03', 'ransomware' => true] && ($gc['CVE-2030-0100']['epss'] ?? 0) === 0.5 && ($gc['CVE-2030-0100']['epss_pct'] ?? 0) === 0.97,
  "Grype's knownExploited/epss become kev/epss/epss_pct: " . json_encode([$gc['CVE-2030-0100']['kev'] ?? null, $gc['CVE-2030-0100']['epss'] ?? null]));
t(($gc['CVE-2030-0101']['kev'] ?? null) === ['added' => '', 'ransomware' => false] && nul($gc['CVE-2030-0101'], 'epss'), "Grype: bad date dropped, out-of-range EPSS rejected");
t(nul($gc['CVE-2030-0102'], 'kev') && ($rg['summary']['kev'] ?? 0) === 2, "Grype: CVE without the fields -> null; summary counts 2");
t(strpos($og, 'new_kev=0') !== false, "KEV CVEs that only match OS packages (source cpe) never notify");

// end of life base OS: Metadata.OS.EOSL
$ew = "$w/eosl"; @mkdir("$ew/local", 0755, true);
foreach (['images.tsv', 'results.tsv', 'warnings.txt'] as $f) copy("$repo/tests/fixtures/basic/$f", "$ew/$f");
foreach ([1, 2] as $i) copy("$repo/tests/fixtures/basic/local/$i.json", "$ew/local/$i.json");
$j1 = json_decode(file_get_contents("$ew/local/1.json"), true); $j1['Metadata']['OS']['EOSL'] = true;
file_put_contents("$ew/local/1.json", json_encode($j1));
$j2 = json_decode(file_get_contents("$ew/local/2.json"), true); $j2['Metadata']['OS']['EOSL'] = 'true';   // not a boolean: not trusted
file_put_contents("$ew/local/2.json", json_encode($j2));
runx($agg, $ew, "$w/eosl.json");
$re = json_decode((string)file_get_contents("$w/eosl.json"), true);
t(($re['images'][0]['eosl'] ?? null) === true && !isset($re['images'][1]['eosl']) && !isset($rn['images'][0]['eosl']), "EOSL true -> eosl on that image only; a string or an absent field -> no flag");

// ---- history.jsonl and "what changed since the previous report"
$hd = "$w/hist"; shell_exec('rm -rf ' . escapeshellarg($hd)); @mkdir("$hd/report", 0755, true);
$ho = "$hd/report/report.json"; $hf = "$hd/report/history.jsonl";
run($agg, "$repo/tests/fixtures/basic", $ho);
$r1 = json_decode((string)file_get_contents($ho), true);
t(array_key_exists('changes', $r1) && $r1['changes'] === null, "first report: changes is null (nothing to compare with)");
t(count(file($hf)) === 1 && count($r1['trend'] ?? []) === 1, "first report: one history line, one trend point");
$h1 = json_decode(file($hf)[0], true);
t(($h1['total'] ?? 0) === 5 && ($h1['by_severity']['CRITICAL'] ?? -1) === 1 && ($h1['images'] ?? 0) === 2 && preg_match('/^[0-9a-f]{40}$/', $h1['ids_sha1'] ?? '') === 1,
  "history line: totals, severity counts, images, CVE id hash");
// same findings again: nothing new, nothing gone
run($agg, "$repo/tests/fixtures/basic", $ho);
$r2 = json_decode((string)file_get_contents($ho), true);
t(($r2['changes']['new'] ?? null) === [] && ($r2['changes']['fixed'] ?? null) === [] && count(file($hf)) === 2, "second identical run: no changes, 2 history lines");
// image 1 loses CVE-2024-0002 and gains CVE-2099-0001; image 2 failed to scan this time: its CVEs must not count as gone
$cp = "$hd/work"; shell_exec('cp -r ' . escapeshellarg("$repo/tests/fixtures/basic") . ' ' . escapeshellarg($cp));
$j = json_decode(file_get_contents("$cp/local/1.json"), true);
foreach ($j['Results'] as &$res) {
  $res['Vulnerabilities'] = array_values(array_filter($res['Vulnerabilities'] ?? [], fn($v) => ($v['VulnerabilityID'] ?? '') !== 'CVE-2024-0002'));
  if (($res['Vulnerabilities'][0] ?? null) !== null) { $nv = $res['Vulnerabilities'][0]; $nv['VulnerabilityID'] = 'CVE-2099-0001'; $nv['PkgName'] = 'newpkg'; $res['Vulnerabilities'][] = $nv; break; }
}
unset($res);
file_put_contents("$cp/local/1.json", json_encode($j));
run($agg, $cp, $ho);
$r3 = json_decode((string)file_get_contents($ho), true);
t(($r3['changes']['new'] ?? null) === ['CVE-2099-0001'], "changes.new lists the CVE that appeared (" . json_encode($r3['changes']['new'] ?? null) . ")");
t(($r3['changes']['fixed'] ?? null) === ['CVE-2024-0002'] && ($r3['changes']['fixed_count'] ?? 0) === 1, "changes.fixed lists the CVE that is gone (" . json_encode($r3['changes']['fixed'] ?? null) . ")");
// the previous report's CVEs that only affected a target which now failed are not "fixed"
$tsv = file_get_contents("$cp/results.tsv");
file_put_contents("$cp/results.tsv", str_replace("1\tlocal\tok\t", "1\tlocal\tfailed\tboom", $tsv));
run($agg, $cp, $ho);
$r4 = json_decode((string)file_get_contents($ho), true);
t(($r4['changes']['fixed'] ?? null) === [], "target that failed this time: its CVEs not reported as fixed (" . json_encode($r4['changes']['fixed'] ?? null) . ")");
t(!in_array('CVE-2024-0001', $r4['changes']['fixed'] ?? [], true) && !in_array('CVE-2024-0003', $r4['changes']['fixed'] ?? [], true), "CVE-2024-0001/0003 (image 1 failed) not reported as fixed");
// pruning: 100 old lines + this run -> 90 kept, oldest dropped
$old = []; for ($i = 0; $i < 100; $i++) $old[] = json_encode(['generated' => 1000 + $i, 'total' => $i, 'fixable' => 0, 'by_severity' => ['CRITICAL' => 0]]);
file_put_contents($hf, implode("\n", $old) . "\n");
run($agg, $cp, $ho);
$hl = file($hf);
t(count($hl) === 90 && (json_decode($hl[0], true)['generated'] ?? 0) === 1011, "history capped at 90 lines, oldest pruned (" . count($hl) . ")");
$r5 = json_decode((string)file_get_contents($ho), true);
t(count($r5['trend'] ?? []) === 30, "report trend holds the last 30 runs");
// a failed report build (output path cannot be replaced) leaves the history exactly as it was
$before = file_get_contents($hf);
$bad = "$hd/report/blocked"; @mkdir("$bad/x", 0755, true);   // report.json is a non-empty directory: rename() fails
$ho2 = "$bad";
$out = run($agg, $cp, $ho2);
t(file_get_contents($hf) === $before && !file_exists("$hd/report/history.jsonl.tmp." . getmypid()), "failed report build: history.jsonl untouched");
exit($fail);
