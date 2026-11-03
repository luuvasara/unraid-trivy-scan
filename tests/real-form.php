<?php
// real-form.php <settings.page> [KEY=value ...] - renders the Settings page body (as PageBuilder evaluates it) and prints
// what a browser would POST for its <form>: every named input/select, selected option values, with KEY=value overrides.
// Prints the form's action on the first line. Test tooling only. $docroot must hold plugins/unraid-cve-lens (cwd).
$page = $argv[1]; $over = [];
foreach (array_slice($argv, 2) as $a) { [$k, $v] = explode('=', $a, 2); $over[$k] = $v; }
$docroot = getcwd(); $var = ['csrf_token' => 'SHOULD-NOT-BE-USED'];
ob_start(); eval('?>' . explode("\n---\n", file_get_contents($page), 2)[1]); $html = ob_get_clean();
$d = new DOMDocument(); @$d->loadHTML('<?xml encoding="utf-8"?>' . $html);
$form = $d->getElementById('uts-form'); $out = [];
foreach ($form->getElementsByTagName('input') as $i) {
  $n = $i->getAttribute('name'); if ($n === '' || in_array($i->getAttribute('type'), ['submit', 'button'], true)) continue;
  $out[$n] = $i->getAttribute('value');
}
foreach ($form->getElementsByTagName('select') as $s) {
  $n = $s->getAttribute('name'); if ($n === '') continue; $val = '';
  foreach ($s->getElementsByTagName('option') as $o) if ($o->hasAttribute('selected') || $val === '') $val = $o->getAttribute('value');
  $out[$n] = $val;
}
echo $form->getAttribute('action'), "\n", http_build_query(array_merge($out, $over)), "\n";
