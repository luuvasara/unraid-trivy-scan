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

if (preg_match('~^/plugins/unraid-cve-lens/include/(status|report|action|log|image)\.php$~', $uri, $m)) {
  if (($rl = getenv('UTS_RUN')) !== false && $rl !== '') @file_put_contents(dirname($rl) . '/requests.log', $m[1] . ' ' . ($_SERVER['QUERY_STRING'] ?? '') . "\n", FILE_APPEND);   // which endpoints the page really called
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
$legacy = getenv('WEBGUI') === '6.12';   // the 6.12.15 webGui layout (fetch-webgui.sh 6.12)
$styles = $legacy ? ['default-fonts', 'default-cases', 'font-awesome', "default-$theme", "dynamix-$theme"]
                  : ['default-fonts', 'default-cases', 'font-awesome', 'default-color-palette', 'default-base', 'default-dynamix', "themes/$theme"];
/* 6.12: DashStats.page's own inline styles (font size of the tile icons, ...), PHP removed */
$dashStyle = '';
if ($legacy && preg_match('~<style>(.*?)</style>~s', (string)@file_get_contents("$docroot/plugins/dynamix/DashStats.page"), $m)) {
  $dashStyle = preg_replace('~<\?.*?\?>~s', '', $m[1]);
}
?><!DOCTYPE html>
<html lang="en" class="Theme--<?=htmlspecialchars($theme)?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>harness <?=htmlspecialchars($uri)?></title>
<?php foreach ($styles as $c): ?><link rel="stylesheet" href="/webGui/styles/<?=$c?>.css">
<?php endforeach; ?>
<script>var csrf_token = <?=json_encode($var['csrf_token'] ?? '')?>; function done() {}</script>
<?php if (isset($_GET['probe'])): /* writes the computed text-transform and font of the first example button into <html> */ ?>
<script>window.addEventListener('load', function () { setTimeout(function () { var b = document.querySelector('button.uts-ex'), c = b && getComputedStyle(b); document.documentElement.setAttribute('data-ex', c ? c.textTransform + '|' + c.fontFamily.split(',')[0].replace(/["']/g, '') + '|' + b.getBoundingClientRect().width : 'none'); }, 1500); });</script>
<?php endif; ?>
<?php if (isset($_GET['fake_terminal'])): /* stands in for the webGui's openTerminal(); records the call, then "clicks" every View log link */ ?>
<script>function openTerminal(t, n, m) { var h = document.documentElement; h.setAttribute('data-term', (h.getAttribute('data-term') || '') + '[' + [t, n, m].join('|') + ']'); }
setTimeout(function () { document.querySelectorAll('a.uts-loglink').forEach(function (a) { a.click(); }); }, 2500);</script>
<?php endif; ?>
<?php if ($legacy): /* div.tile is shown by the 6.12 dashboard script; shown here directly */ ?><style>body { padding: 16px; }<?=$dashStyle?> div.tile { display: block; }</style>
<?php else: ?><style>body { padding: 16px; background: var(--background-color); color: var(--text-color); }</style>
<?php endif; ?>
</head>
<body>
<?php if ($uri === '/Dashboard'): ?>
<div class="frame"><div class="grid"><div class="tile" id="tile3"><table id="db_box3" class="<?=$legacy ? 'share_status dashboard' : 'dashboard'?>">
<?php run_page("$plug/CveLensDash.page"); foreach (($mytiles ?? []) as $t) echo $t['column3'] ?? ''; ?>
</table></div></div></div>
<?php elseif (isset($_GET['compose'])): /* Unraid's composition (DefaultPageLayout.php): every tab's page body, one after the other, in one document: div.tabs > div.tab > input radio + label + div.content; the pages that are not selected are hidden. Each page includes its own script tag, so report.js is included once per tab. */ ?>
<div class="tabs">
<?php foreach ([1 => ['Report', 'CveLensReport'], 2 => ['Settings', 'CveLensSettings'], 3 => ['Scan an image', 'CveLensImage'], 4 => ['About', 'CveLensAbout']] as $i => [$t, $f]): if (isset($_GET['without']) && $_GET['without'] === $f) continue; ?>
  <div class='tab'><input type='radio' id='tab<?=$i?>' name='tabs' <?=$i === (int)($_GET['tab'] ?? 1) ? 'checked' : ''?>><label for='tab<?=$i?>'><?=$t?></label><div class='content' style='display:<?=$i === (int)($_GET['tab'] ?? 1) ? 'block' : 'none'?>'>
<?php run_page("$plug/$f.page"); ?>
  </div></div>
<?php endforeach; ?>
</div>
<?php else: $sel = (int)($_GET['tab'] ?? 1); ?>
<div id="displaybox">
  <nav class="tabs" role="tablist" aria-label="Page Tabs"><div class="tabs-container">
    <?php foreach ([1 => 'Report', 2 => 'Settings', 3 => 'Scan an image', 4 => 'About'] as $i => $t): ?>
    <button role="tab" id="tab<?=$i?>" aria-controls="tab<?=$i?>-panel" aria-selected="<?=$i === $sel ? 'true' : 'false'?>"
            onclick="location.search='?tab=<?=$i?>'"><?=$t?></button>
    <?php endforeach; ?>
  </div></nav>
  <section id="tab<?=$sel?>-panel" role="tabpanel" aria-labelledby="tab<?=$sel?>" class="tab-content content" tabindex="0" style="display:block">
    <?php /* display:block stands in for Unraid's tab script, which reveals the selected panel */ ?>
    <?php run_page($sel === 4 ? "$plug/CveLensAbout.page" : ($sel === 3 ? "$plug/CveLensImage.page" : ($sel === 2 ? "$plug/CveLensSettings.page" : "$plug/CveLensReport.page"))); ?>
  </section>
</div>
<?php endif; ?>
</body></html>
