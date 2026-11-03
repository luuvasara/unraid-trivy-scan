<?php
/* tests/aggregate-test.php <repo>: include/aggregate.php against tests/fixtures/basic (hand-written Trivy JSON,
 * schema 2). Prints "ok"/"FAIL" lines; exit 1 on any failure. Work files go to tests/.work/agg. */
$repo = $argv[1];
$agg = "$repo/src/usr/local/emhttp/plugins/unraid-trivy-scan/include/aggregate.php";
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
t(($h['suppressed_count'] ?? 0) === 2 && strpos($sup['CVE-2025-9003'][2] ?? '', 'os-ignore.txt: fixed by Lime Tech') === 0
  && ($sup['CVE-2025-9005'][1] ?? '') === 'bash' && strpos($sup['CVE-2025-9005'][2] ?? '', 'changelog') !== false, "hidden matches listed with the reason");
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
exit($fail);
