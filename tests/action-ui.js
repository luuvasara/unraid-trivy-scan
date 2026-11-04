// action-ui.js <base-url> - assets/report.js parseActionResponse() against a server whose request prologue is a copy of
// Unraid 7.3.4's real local_prepend.php (started by tests/real-unraid-test.sh). Prints one "ok"/"FAIL" line per check.
global.document = { getElementById: () => null };   // report.js returns early without its page
const path = require('path');
const { parseActionResponse } = require(process.env.UTS_REPORT_JS || path.join(__dirname, '..', 'src/usr/local/emhttp/plugins/unraid-cve-lens/assets/report.js'));
const base = process.argv[2];
let fail = 0;
const check = (name, cond, got) => { console.log((cond ? 'ok   ' : 'FAIL ') + name + (cond ? '' : ': ' + JSON.stringify(got))); if (!cond) fail = 1; };
const post = (body, headers) => fetch(base + '/plugins/unraid-cve-lens/include/action.php', { method: 'POST', body, headers });
(async () => {
  let r = await post(new URLSearchParams({ action: 'start', csrf_token: 'WRONGWRONGWRONG0' }), {});
  const raw = await r.clone().text();
  check('real prologue answers a wrong token with HTTP 200 and an empty body (the premise of the fix)', r.status === 200 && raw === '', [r.status, raw]);
  let a = await parseActionResponse(r);
  check('rejected token -> clear "reload the page" message, not "HTTP 200"', a.ok === false && /reload the page/i.test(a.error) && !/HTTP 200/.test(a.error), a);
  r = await post(new URLSearchParams({ action: 'start', csrf_token: '0123456789ABCDEF' }), {});
  a = await parseActionResponse(r);
  check('valid token -> the action answer is passed through', a.ok === true, a);
  r = await post(new URLSearchParams({ action: 'rm-rf', csrf_token: '0123456789ABCDEF' }), {});
  a = await parseActionResponse(r);
  check('JSON error answer (400) is passed through', a.ok === false && a.error === 'unknown action', a);
  a = await parseActionResponse(new Response('<html>502 Bad Gateway</html>', { status: 502 }));
  check('non-JSON body -> "Unexpected answer (HTTP 502)"', a.ok === false && a.error === 'Unexpected answer (HTTP 502)', a);
  a = await parseActionResponse(new Response('', { status: 502 }));
  check('empty body with an error status -> HTTP 502', a.ok === false && a.error === 'HTTP 502', a);
  process.exit(fail);
})().catch(e => { console.log('FAIL exception ' + e); process.exit(1); });
