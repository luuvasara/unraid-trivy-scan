<?php
/* unraid-trivy-scan: shared helpers for the pages and endpoints.
 * Settings are plain KEY="value" lines (the format Unraid's update.php writes). They are parsed as data,
 * never executed, and every value is checked against the same rules scripts/trivy-scan uses. */

const UTS_NAME = 'unraid-trivy-scan';

/* Defaults. Keep in sync with DEF in scripts/trivy-scan (tests/unit.sh compares them). */
const UTS_DEFAULTS = [
  'SCHEDULE'       => '',        // empty = no scheduled scan
  'SCOPE'          => 'running', // running | all (running and stopped containers)
  'TIMEOUT'        => '30',      // minutes per image, 5..240
  'JAVA_DB'        => 'yes',     // download the Java index DB (needed for jar files)
  'TRIVY_DB_KEEP'  => 'yes',     // keep the Trivy vulnerability DB in the data dir (no: download every run, delete after)
  'JAVA_DB_KEEP'   => 'yes',     // the same for the Java DB
  'REGISTRY_CHECK' => 'no',      // compare with the image in the registry
  'REGISTRY_AUTH'  => 'no',      // give /root/.docker/config.json to the registry container
  'NOTIFY'         => 'yes',     // notify on new fixable critical CVEs
  'OS_SCAN'        => 'yes',     // also scan the Unraid OS (trivy rootfs over the system directories, read-only)
  'OS_PKG_MATCH'   => 'yes',     // with OS_SCAN: match the OS packages (Slackware or RPM) against NVD CPEs with Grype
  'OS_PKG_DB_KEEP' => 'yes',     // with OS_PKG_MATCH: keep the Grype DB in the data dir (no: download it every run, delete after)
  'OS_KERNEL_MATCH'=> 'no',     // with OS_PKG_MATCH: include the kernel (many NVD entries, mostly backported by Lime Tech/Fedora)
  'SHOW_TAB'       => 'no',      // top-level header tab
  'DASH_TILE'      => 'yes',     // dashboard tile
  'REMOVE_DATA'    => 'no',      // on plugin removal delete the data dir and the pinned image
];

/* Where Docker keeps appdata: DOCKER_APP_CONFIG_PATH in /boot/config/docker.cfg (Settings, Docker, "Default appdata
 * location"; Unraid's own default is /mnt/user/appdata/). Read as data, never executed; the last assignment wins as
 * in parse_ini_file. Only a plain absolute path under /mnt is accepted (letters, digits and . _ + @ -, no dot
 * segments); anything else, or no file, gives /mnt/user/appdata. The same rules are in appdata_root() in
 * scripts/trivy-scan (tests/unit.sh compares both). */
function uts_appdata_root(?string $file = null): string {
  $def = '/mnt/user/appdata';
  $raw = @file_get_contents($file ?? (($v = getenv('UTS_DOCKER_CFG')) !== false && $v !== '' ? $v : '/boot/config/docker.cfg'));
  if ($raw === false) return $def;
  $val = null;
  foreach (preg_split('/\r?\n/', $raw) as $line) {
    if (preg_match('/^DOCKER_APP_CONFIG_PATH=(.*)$/', rtrim($line, "\r"), $m)) $val = $m[1];
  }
  if ($val === null) return $def;
  if (strlen($val) >= 2 && $val[0] === '"' && substr($val, -1) === '"') $val = substr($val, 1, -1);
  $val = rtrim($val, '/');
  if (!preg_match('#^/mnt/[A-Za-z0-9._+@-]+(/[A-Za-z0-9._+@-]+)*$#', $val) || preg_match('#(^|/)\.\.?(/|$)#', $val)) return $def;
  return $val;
}

/* Paths. The UTS_* environment overrides exist for the offline test harness only; Unraid's php-fpm clears
 * the environment, so on a server these are always the literal defaults. */
function uts_path(string $what): string {
  static $p = null;
  if ($p === null) {
    $env = fn($k, $d) => (($v = getenv($k)) !== false && $v !== '') ? $v : $d;
    $p = [
      'cfg'    => $env('UTS_CFG', '/boot/config/plugins/' . UTS_NAME . '/' . UTS_NAME . '.cfg'),
      'data'   => $env('UTS_DATA', uts_appdata_root() . '/' . UTS_NAME),
      'run'    => $env('UTS_RUN', '/var/run/' . UTS_NAME),
      'varini' => $env('UTS_VARINI', '/var/local/emhttp/var.ini'),
      'script' => $env('UTS_SCRIPT', '/usr/local/emhttp/plugins/' . UTS_NAME . '/scripts/trivy-scan'),
    ];
  }
  return $p[$what];
}

/* ---- validation (mirrors valid_value / cron_valid in scripts/trivy-scan) ---- */

function uts_cron_field_ok(string $f, int $min, int $max): bool {
  foreach (explode(',', $f) as $item) {
    if (!preg_match('/^(\*|([0-9]{1,2})(-([0-9]{1,2}))?)(\/([0-9]{1,2}))?$/', $item, $m)) return false;
    if ($m[1] !== '*') {
      $a = (int)$m[2]; $b = isset($m[4]) && $m[4] !== '' ? (int)$m[4] : $a;
      if ($a < $min || $b > $max || $a > $b) return false;
    }
    if (isset($m[6]) && $m[6] !== '' && ((int)$m[6] < 1 || (int)$m[6] > $max)) return false;
  }
  return true;
}

/* Exactly five space-separated fields: minute hour day-of-month month day-of-week, numbers only. */
function uts_cron_valid(string $s): bool {
  if (!preg_match('/^[0-9*\/,-]+( [0-9*\/,-]+){4}$/', $s)) return false;
  [$mi, $h, $dom, $mon, $dow] = explode(' ', $s);
  return uts_cron_field_ok($mi, 0, 59) && uts_cron_field_ok($h, 0, 23) && uts_cron_field_ok($dom, 1, 31)
      && uts_cron_field_ok($mon, 1, 12) && uts_cron_field_ok($dow, 0, 7);
}

/* Whitespace in a typed schedule is collapsed before it is checked and saved. */
function uts_normalize(string $key, string $v): string {
  $v = trim($v);
  return $key === 'SCHEDULE' ? preg_replace('/[ \t]+/', ' ', $v) : $v;
}

function uts_valid(string $key, $v): bool {
  if (!is_string($v) || !array_key_exists($key, UTS_DEFAULTS)) return false;
  switch ($key) {
    case 'SCHEDULE': return $v === '' || uts_cron_valid($v);
    case 'SCOPE':    return $v === 'running' || $v === 'all';
    case 'TIMEOUT':  return preg_match('/^[0-9]{1,3}$/', $v) === 1 && (int)$v >= 5 && (int)$v <= 240;
    default:         return $v === 'yes' || $v === 'no';
  }
}

/* Read the settings file as data. Unknown keys are ignored; an invalid value falls back to its default and is
 * reported in $problems (key => raw value). Accepts KEY="value", KEY=value and CRLF line ends. */
function uts_config(?array &$problems = null, ?string $file = null): array {
  $cfg = UTS_DEFAULTS; $problems = [];
  $raw = @file_get_contents($file ?? uts_path('cfg'));
  if ($raw === false) return $cfg;
  foreach (preg_split('/\r?\n/', $raw) as $line) {
    if (!preg_match('/^([A-Z_]+)=(.*)$/', rtrim($line, "\r"), $m)) continue;
    [$k, $v] = [$m[1], $m[2]];
    if (!array_key_exists($k, UTS_DEFAULTS)) continue;
    if (strlen($v) >= 2 && $v[0] === '"' && substr($v, -1) === '"') $v = substr($v, 1, -1);
    if (uts_valid($k, $v)) $cfg[$k] = $k === 'TIMEOUT' ? (string)(int)$v : $v; else $problems[$k] = $v;
  }
  return $cfg;
}

/* ---- output helpers ---- */

function uts_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

/* <option> list; a current value that is not in the list (a hand-edited file) is kept as "Custom". */
function uts_options(array $opts, string $cur): string {
  $out = ''; $found = false;
  foreach ($opts as $val => $label) {
    $sel = ((string)$val === $cur) ? ' selected' : '';
    if ($sel) $found = true;
    $out .= '<option value="' . uts_h($val) . '"' . $sel . '>' . uts_h($label) . "</option>\n";
  }
  if (!$found) $out .= '<option value="' . uts_h($cur) . '" selected>' . uts_h("Custom: $cur") . "</option>\n";
  return $out;
}

/* ---- run state ---- */

/* key=value file written by scripts/trivy-scan (progress, last run). Values are data. */
function uts_kv_file(string $file): array {
  $out = [];
  $raw = @file_get_contents($file);
  if ($raw === false) return $out;
  foreach (explode("\n", $raw) as $line) {
    if (preg_match('/^([a-z_]+)=(.*)$/', $line, $m)) $out[$m[1]] = $m[2];
  }
  return $out;
}

/* Is a scan running? The pid file must name a live process whose command line is our script. */
function uts_running(): bool {
  $pid = trim((string)@file_get_contents(uts_path('run') . '/pid'));
  if (!preg_match('/^[0-9]{1,9}$/', $pid)) return false;
  $cmd = @file_get_contents("/proc/$pid/cmdline");
  return $cmd !== false && strpos($cmd, 'trivy-scan') !== false;
}

function uts_status(): array {
  $p = uts_kv_file(uts_path('run') . '/progress');
  $l = uts_kv_file(uts_path('data') . '/report/last-run');
  $running = uts_running();
  return [
    'running' => $running,
    'phase'   => $running ? (string)($p['phase'] ?? '') : '',
    'done'    => $running ? (int)($p['done'] ?? 0) : 0,
    'total'   => $running ? (int)($p['total'] ?? 0) : 0,
    'current' => $running ? (string)($p['current'] ?? '') : '',
    'last'    => [
      'result'  => (string)($l['result'] ?? ''),
      'ended'   => (int)($l['ended'] ?? 0),
      'message' => (string)($l['message'] ?? ''),
    ],
  ];
}

/* The aggregated report (written by include/aggregate.php), or null. */
function uts_report(): ?array {
  $raw = @file_get_contents(uts_path('data') . '/report/report.json');
  if ($raw === false) return null;
  $r = json_decode($raw, true);
  return is_array($r) ? $r : null;
}

function uts_date(int $t): string { return $t > 0 ? date('Y-m-d H:i', $t) : '-'; }

/* ---- database sizes (settings page) ---- */

/* Output of "trivy-scan db-sizes": <key>_now / <key>_last in KiB; anything else is ignored. */
function uts_db_sizes(string $out): array {
  $s = [];
  foreach (explode("\n", $out) as $l) {
    if (preg_match('/^(trivy|java|grype)_(now|last)=([0-9]{1,12})$/', trim($l), $m)) $s["$m[1]_$m[2]"] = (int)$m[3];
  }
  return $s;
}
function uts_kib(int $k): string { return $k >= 1048576 ? sprintf('%.1f GB', $k / 1048576) : sprintf('%d MB', max(1, (int)round($k / 1024))); }
/* "On disk: 1.6 GB" when present, else the size at the last download, else the estimate. */
function uts_db_size(array $s, string $k, string $estimate): string {
  if (isset($s["{$k}_now"])) return 'On disk: ' . uts_kib($s["{$k}_now"]);
  if (isset($s["{$k}_last"])) return 'Not on disk now; ' . uts_kib($s["{$k}_last"]) . ' at its last download';
  return "Not downloaded yet; about $estimate (estimate)";
}
