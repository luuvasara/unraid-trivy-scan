#!/usr/bin/env python3
"""hostile.py <outdir>: a run work dir, settings file and state files full of markup/script payloads.
Every payload, if it ever ran, sets data-pwned on <html>. MARK strings test single escaping: they must show up as
literal text (<b>MARK...</b>), never as markup and never double-escaped (&amp;lt;)."""
import json, os, sys
out = sys.argv[1]
P = [
    '<img src=x onerror="document.documentElement.setAttribute(\'data-pwned\',\'img\')">',
    '"><svg/onload=document.documentElement.setAttribute(\'data-pwned\',\'svg\')>',
    "'><script>document.documentElement.setAttribute('data-pwned','script')</script>",
    '</script><script>document.documentElement.setAttribute("data-pwned","close")</script>',
]
def mark(n): return '<b>MARK%s</b>&amp;' % n
os.makedirs(out + '/work/local', exist_ok=True); os.makedirs(out + '/work/remote', exist_ok=True)
os.makedirs(out + '/data/report', exist_ok=True); os.makedirs(out + '/run', exist_ok=True)
def v(i, sev, extra):
    d = {"VulnerabilityID": "CVE-2024-%04d" % (100 + i), "Severity": sev, "PkgName": P[i % 4] + mark('pkg%d' % i),
         "InstalledVersion": P[(i + 1) % 4], "FixedVersion": "1.0" + P[(i + 2) % 4] if i % 2 else "",
         "Status": P[3], "Title": mark('title%d' % i) + P[i % 4]}
    d.update(extra); return d
vulns = [v(0, "CRITICAL", {"PrimaryURL": "javascript:document.documentElement.setAttribute('data-pwned','href')"}),
         v(1, "HIGH", {"PrimaryURL": "https://x.test/\" onmouseover=\"document.documentElement.setAttribute('data-pwned','attr')"}),
         v(2, "MEDIUM", {"PrimaryURL": "https://example.test/advisory?id=1&x=2"}),
         v(3, "<script>x</script>", {}),
         {"VulnerabilityID": "CVE-2024-0001\"><img src=x onerror=alert(1)>", "Severity": "HIGH", "PkgName": "dropped"}]
doc = {"SchemaVersion": 2, "Metadata": {"OS": {"Family": P[0], "Name": mark('os')}},
       "Results": [{"Target": P[1] + mark('target'), "Vulnerabilities": vulns}]}
json.dump(doc, open(out + '/work/local/1.json', 'w'))
T = '\t'
open(out + '/work/images.tsv', 'w').write(
    T.join(['1', 'sha256:' + 'e' * 64, P[0] + mark('image'), 'x:1', '1', '', P[1] + ',' + mark('cont'), P[2]]) + '\n' +
    T.join(['2', 'sha256:' + 'f' * 64, P[2] + mark('failedimg'), '', '0', '', 'c2', P[3] + mark('noref')]) + '\n')
open(out + '/work/results.tsv', 'w').write(
    '1\tlocal\tok\t\n2\tlocal\tfailed\t' + P[3] + mark('reason') + '\n1\tremote\tfailed\t' + P[1] + mark('regfail') + '\n')
open(out + '/work/warnings.txt', 'w').write(P[0] + mark('warn') + '\n')
# the Unraid OS target: file paths, kernel and Slackware package names are untrusted too
os.makedirs(out + '/work/os', exist_ok=True)
osdoc = {"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": [{"Target": "Node.js", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0101", "Severity": "HIGH", "PkgName": "axios", "InstalledVersion": "1.0",
     "FixedVersion": "1.1", "PkgPath": P[2] + mark('ospath'), "Title": "t"}]}]}
json.dump(osdoc, open(out + '/work/os/os.json', 'w'))
open(out + '/work/os/result', 'w').write('result=ok\nerror=\nversion=7.3.4\nkernel=' + mark('kernel') + '\npkg_result=failed\npkg_error=' + mark('pkgerr') + '\n')
open(out + '/work/os/packages.txt', 'w').write(P[0] + mark('ospkg') + '-1.0-x86_64-1\n' + 'bash-5.3-x86_64-1\n')
open(out + '/cfg', 'w').write('SCHEDULE="' + P[1] + mark('cfg') + '"\nSCOPE="all"\nSHOW_TAB="yes"\nPATH="/evil"\n')
open(out + '/run/progress', 'w').write('phase=scan\ndone=1\ntotal=2\ncurrent=' + P[0] + mark('current') + '\n')
open(out + '/data/report/last-run', 'w').write('result=failed\nended=1767225600\nmessage=' + P[2] + mark('lastrun') + '\n')
open(out + '/varini', 'w').write('csrf_token="0123456789ABCDEF"\n')

open(out + '/work/posture.jsonl', 'w').write(json.dumps(
    ['a' * 64, 'sha256:' + 'e' * 64, '/' + P[1] + mark('pname'), True, 'host', 'host', ['SYS_ADMIN', P[0]], [{}], '', 'CMD',
     ['/var/run/docker.sock:/x'], [], {'80/tcp': [{'HostIp': '', 'HostPort': '8080'}]}, False, P[2] + ':latest']) + '\n')
