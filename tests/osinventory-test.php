<?php
/* tests/osinventory-test.php <repo>: include/osinventory.php on tests/fixtures/osinv (a Slackware package list, an RPM
 * query with changelogs, a user CPE map). Prints "ok"/"FAIL" lines; exit 1 on any failure. Work in tests/.work/inv. */
$repo = $argv[1];
$inv = "$repo/src/usr/local/emhttp/plugins/unraid-cve-lens/include/osinventory.php";
$map = "$repo/src/usr/local/emhttp/plugins/unraid-cve-lens/include/cpe-map.txt";
$fx = "$repo/tests/fixtures/osinv";
$w = "$repo/tests/.work/inv";
$fail = 0;
function t(bool $c, string $m) { global $fail; echo ($c ? "ok   " : "FAIL ") . "osinventory: $m\n"; if (!$c) $fail = 1; }
function fresh(string $d, array $files): void {
  @mkdir($d, 0755, true);
  foreach (glob("$d/*") ?: [] as $f) @unlink($f);
  foreach ($files as $src => $dst) copy($src, "$d/$dst");
}
function run(string $inv, array $args): string {
  return (string)shell_exec('php ' . implode(' ', array_map('escapeshellarg', array_merge([$inv], $args))) . ' 2>&1');
}
function rows(string $f): array { return array_map(fn($l) => explode("\t", $l), file($f, FILE_IGNORE_NEW_LINES) ?: []); }

// ---- Slackware (Unraid 7)
$s = "$w/slack"; fresh($s, ["$fx/slack/packages.txt" => 'packages.txt']);
$out = run($inv, [$s, $map, "$fx/user-map.txt", 'kernel=6.18.58-Unraid', 'os=Unraid OS 7.3.4']);
t(strpos($out, "base=slackware\n") !== false && strpos($out, "packages=6\n") !== false, "Slackware list read, odd and hostile lines skipped, kernel added: " . trim(str_replace("\n", ' ', $out)));
$r = []; foreach (rows("$s/inventory.tsv") as $x) $r[$x[0]] = $x;
t(($r['openssh'] ?? [])[3] === 'openbsd:openssh' && ($r['bash'] ?? [])[3] === 'gnu:bash', "names mapped to CPE vendor:product");
t(isset($r['samba']) && $r['samba'][3] === '', "user map '<name> -' switches a mapping off (samba)");
t(isset($r['kernel-firmware']) && $r['kernel-firmware'][3] === '', "unmapped package kept in the inventory with an empty mapping");
t(!isset($r['some$(touch PWN)']) && !file_exists("$s/PWN"), "a package name with shell characters is skipped, nothing executed");
$bom = json_decode((string)file_get_contents("$s/os.cdx.json"), true);
$cmp = []; foreach ($bom['components'] ?? [] as $c) $cmp[$c['name']] = $c;
t(($bom['bomFormat'] ?? '') === 'CycloneDX' && ($bom['specVersion'] ?? '') === '1.5' && ($bom['metadata']['component']['type'] ?? '') === 'application',
  "CycloneDX 1.5, metadata component is an application (no distro for Grype to look up)");
t(array_keys($cmp) == ['bash', 'openssl', 'openssh', 'linux-kernel'], "SBOM holds mapped packages only: " . implode(',', array_keys($cmp)));
t(($cmp['openssh']['cpe'] ?? '') === 'cpe:2.3:a:openbsd:openssh:10.2p1:*:*:*:*:*:*:*' && ($cmp['openssh']['purl'] ?? '') === 'pkg:generic/openssh@10.2p1'
  && ($cmp['openssh']['type'] ?? '') === 'library', "component: CPE 2.3 with the upstream version, generic purl, type library");
t(($cmp['linux-kernel']['cpe'] ?? '') === 'cpe:2.3:o:linux:linux_kernel:6.18.58:*:*:*:*:*:*:*' && ($cmp['linux-kernel']['type'] ?? '') === 'library',
  "kernel=6.18.58-Unraid -> o:linux:linux_kernel:6.18.58");
$out = run($inv, [$s, $map]);
t(strpos($out, "packages=5\n") !== false && strpos((string)file_get_contents("$s/os.cdx.json"), 'linux_kernel') === false, "no kernel= -> kernel not matched");
t(!file_exists("$s/patched.tsv"), "Slackware: no patched.tsv (no changelogs)");

// ---- RPM (Unraid 8, Fedora base)
$p = "$w/rpm"; fresh($p, ["$fx/rpm/rpm.tsv" => 'rpm.tsv', "$fx/rpm/rpm-changelog.txt" => 'rpm-changelog.txt']);
$out = run($inv, [$p, $map, "$w/none.txt"]);
t(strpos($out, "base=rpm\n") !== false && strpos($out, "packages=4\n") !== false && strpos($out, "mapped=3\n") !== false,
  "RPM: binary packages folded into source packages, gpg-pubkey dropped: " . trim(str_replace("\n", ' ', $out)));
$r = []; foreach (rows("$p/inventory.tsv") as $x) $r[$x[0]] = $x;
t(($r['openssl'] ?? [])[1] === '3.2.4' && $r['openssl'][2] === '3.fc42' && $r['openssl'][3] === 'openssl:openssl' && $r['openssl'][4] === 'rpm',
  "openssl-libs + openssl -> one 'openssl' row (source RPM name), version, release, mapping");
t(($r['shadow-utils'] ?? [])[3] === 'shadow-maint:shadow-utils' && ($r['fedora-release'] ?? [])[3] === '', "Fedora source names mapped; release package unmapped");
$cmp = []; foreach (json_decode((string)file_get_contents("$p/os.cdx.json"), true)['components'] ?? [] as $c) $cmp[$c['name']] = $c;
t(($cmp['openssh']['version'] ?? '') === '9.9p1' && ($cmp['openssh']['cpe'] ?? '') === 'cpe:2.3:a:openbsd:openssh:9.9p1:*:*:*:*:*:*:*', "RPM VERSION used as the upstream version (no epoch, no release)");
$pt = file("$p/patched.tsv", FILE_IGNORE_NEW_LINES);
sort($pt);
t($pt === ["CVE-2025-1111\topenssl", "CVE-2025-2222\topenssl"], "CVE ids in a changelog (also on continuation lines) -> patched for the source package: " . implode(' | ', $pt));

// ---- upstream_version(): checked through the SBOM component versions
$vers = ['tv1' => ['2.4_rc1', '2.4-rc1'], 'tv2' => ['1.0_beta2', '1.0-beta2'], 'tv3' => ['6.5_20241228', '6.5'],
         'tv4' => ['20260508_3737842', '20260508'], 'tv5' => ['stable202602', '202602'], 'tv6' => ['v1.2.3', '1.2.3'],
         'tv7' => ['1.2.3+lt', '1.2.3'], 'tv8' => ['3.8.13', '3.8.13']];
$um = "$w/ver-map.txt"; $pl = ''; $ml = '';
foreach ($vers as $n => [$in]) { $pl .= "$n-$in-x86_64-1\n"; $ml .= "$n vendor:$n\n"; }
file_put_contents($um, $ml);
$v = "$w/ver"; fresh($v, []); file_put_contents("$v/packages.txt", $pl);
run($inv, [$v, $map, $um]);
$cmp = []; foreach (json_decode((string)file_get_contents("$v/os.cdx.json"), true)['components'] ?? [] as $c) $cmp[$c['name']] = $c;
foreach ($vers as $n => [$in, $want]) {
  t(($cmp[$n]['version'] ?? null) === $want && ($cmp[$n]['cpe'] ?? '') === "cpe:2.3:a:vendor:$n:$want:*:*:*:*:*:*:*",
    "Slackware version '$in' -> '$want' (got '" . ($cmp[$n]['version'] ?? 'none') . "')");
}
// RPM: the VERSION is already upstream, so '_' stays (a pre-release suffix or snapshot marker is not rewritten)
$rv = "$w/rver"; fresh($rv, []);
file_put_contents("$rv/rpm.tsv", "tr1\t0\t1.0_beta2\t1.fc42\tx86_64\ttr1-1.0_beta2-1.fc42.src.rpm\ntr2\t0\t6.5_20241228\t1.fc42\tx86_64\ttr2-6.5_20241228-1.fc42.src.rpm\n");
file_put_contents($um, "tr1 vendor:tr1\ntr2 vendor:tr2\n");
run($inv, [$rv, $map, $um]);
$cmp = []; foreach (json_decode((string)file_get_contents("$rv/os.cdx.json"), true)['components'] ?? [] as $c) $cmp[$c['name']] = $c;
t(($cmp['tr1']['version'] ?? '') === '1.0_beta2' && ($cmp['tr2']['version'] ?? '') === '6.5_20241228',
  "RPM base leaves '_' in the version untouched (" . ($cmp['tr1']['version'] ?? 'none') . ', ' . ($cmp['tr2']['version'] ?? 'none') . ')');
exit($fail);
