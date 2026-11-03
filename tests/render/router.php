<?php
/* Local render harness (php -S, build host only; NOT the Unraid webGui). It mimics what the pages rely on:
 * <html class="Theme--<theme>">, Unraid's stylesheets in DefaultPageLayout order then themes/<theme>.css, the
 * global csrf_token, the tabbed layout of an xmenu page (nav.tabs + section.tab-content, MainContentTabbed.php) and
 * the dashboard grid (div.tile > table.dashboard, customTiles()). The page bodies run unmodified, as PageBuilder
 * evaluates them; the plugin's endpoints run unmodified too, against the UTS_* paths set by render-test.sh. */
$theme = getenv('THEME') ?: 'black';
$webroot = getenv('WEBROOT');
$plug = "$webroot/plugins/unraid-cve-lens";
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (preg_match('~^/plugins/unraid-cve-lens/include/(status|report|action)\.php$~', $uri, $m)) {
  require "$plug/include/{$m[1]}.php";
  return true;
}
if (strpos($uri, '/plugins/') === 0 || strpos($uri, '/webGui/') === 0) return false;   // static files
// the pages show the data directory; screenshots go into docs/, so show the default location, not this checkout's path
if (($dataDir = getenv('UTS_DATA')) !== false && $dataDir !== '') ob_start(fn($o) => str_replace($dataDir, '/mnt/user/appdata/unraid-cve-lens', $o));

$docroot = $webroot;
$var = @parse_ini_file(getenv('UTS_VARINI')) ?: [];
function page_body(string $f): string { return explode("\n---\n", file_get_contents($f), 2)[1]; }
/* run a page body the way PageBuilder does (prefix a closing PHP tag, evaluate); local harness only */
function run_page(string $f): void {
  global $docroot, $var, $mytiles;
  eval('?>' . page_body($f));
}
$styles = ['default-fonts', 'default-cases', 'font-awesome', 'default-color-palette', 'default-base', 'default-dynamix', "themes/$theme"];
?><!DOCTYPE html>
<html lang="en" class="Theme--<?=htmlspecialchars($theme)?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>harness <?=htmlspecialchars($uri)?></title>
<?php foreach ($styles as $c): ?><link rel="stylesheet" href="/webGui/styles/<?=$c?>.css">
<?php endforeach; ?>
<script>var csrf_token = <?=json_encode($var['csrf_token'] ?? '')?>; function done() {}</script>
<style>body { padding: 16px; background: var(--background-color); color: var(--text-color); }</style>
</head>
<body>
<?php if ($uri === '/Dashboard'): ?>
<div class="frame"><div class="grid"><div class="tile" id="tile3"><table id="db_box3" class="dashboard">
<?php run_page("$plug/CveLensDash.page"); foreach (($mytiles ?? []) as $t) echo $t['column3'] ?? ''; ?>
</table></div></div></div>
<?php else: $sel = (int)($_GET['tab'] ?? 1); ?>
<div id="displaybox">
  <nav class="tabs" role="tablist" aria-label="Page Tabs"><div class="tabs-container">
    <?php foreach ([1 => 'Report', 2 => 'Settings'] as $i => $t): ?>
    <button role="tab" id="tab<?=$i?>" aria-controls="tab<?=$i?>-panel" aria-selected="<?=$i === $sel ? 'true' : 'false'?>"
            onclick="location.search='?tab=<?=$i?>'"><?=$t?></button>
    <?php endforeach; ?>
  </div></nav>
  <section id="tab<?=$sel?>-panel" role="tabpanel" aria-labelledby="tab<?=$sel?>" class="tab-content content" tabindex="0" style="display:block">
    <?php /* display:block stands in for Unraid's tab script, which reveals the selected panel */ ?>
    <?php run_page($sel === 2 ? "$plug/CveLensSettings.page" : "$plug/CveLensReport.page"); ?>
  </section>
</div>
<?php endif; ?>
</body></html>
