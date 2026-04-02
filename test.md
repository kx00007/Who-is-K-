<div align="center">

```
 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗      ██╗  ██╗██╗  ██╗██╗  ██╗██╗  ██╗
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██╔════╝     ╚██╗██╔╝ ╚██╗██╔╝╚██╗██╔╝╚██╗██╔╝
██║     ██║   ██║█████╗       █████╔╝██║██╔██║ █████╔╝███████╗      ╚███╔╝   ╚███╔╝  ╚███╔╝  ╚███╔╝ 
██║     ╚██╗ ██╔╝██╔══╝      ██╔═══╝ ████╔╝██║██╔═══╝ ██╔══██║      ██╔██╗   ██╔██╗  ██╔██╗  ██╔██╗ 
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗╚█████╔╝     ██╔╝ ██╗ ██╔╝ ██╗██╔╝ ██╗██╔╝ ██╗
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

### `CVE-2026-XXXXX` · Chamilo LMS · OS Command Injection → RCE

<br>

![CVE](https://img.shields.io/badge/CVE-2026--XXXXX-FF0000?style=flat-square&logo=databricks&logoColor=white)
![CVSS](https://img.shields.io/badge/CVSSv3.1-8.8_HIGH-FF6600?style=flat-square)
![CWE](https://img.shields.io/badge/CWE-78-FFD700?style=flat-square)
![Auth](https://img.shields.io/badge/Auth-Required-4A90D9?style=flat-square)
![Type](https://img.shields.io/badge/Type-OS_Command_Injection-8B0000?style=flat-square)
![Shell](https://img.shields.io/badge/Shell-RCE_Confirmed-success?style=flat-square&logo=gnu-bash&logoColor=white)

<br>

> **Researcher:** [K](https://github.com/kx00007) &nbsp;|&nbsp; **Product:** Chamilo LMS `< 2.0` (Confirmed `v1.11.32`) &nbsp;|&nbsp; **Auth:** Authenticated User w/ Poisoned Session

</div>

---

## `[01]` Vulnerability Overview

| Field | Value |
|---|---|
| **Product** | Chamilo LMS |
| **Version** | `< 2.0` (Confirmed on `v1.11.32`) |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Impact** | Authenticated Remote Code Execution (RCE) |
| **Severity** | 🔴 Critical |
| **Auth Required** | Yes — Authenticated User with poisoned session |
| **CVSSv3.1 Score** | `8.8 HIGH` |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Vulnerable File** | `main/inc/ajax/gradebook.ajax.php` |

---

## `[02]` Description

A critical OS Command Injection vulnerability exists in the `main/inc/ajax/gradebook.ajax.php` endpoint of Chamilo LMS `v1.11.32`. The `export_all_certificates` action handles the export of course certificates by executing a background PHP script via `shell_exec`.

The application retrieves the course code using `api_get_course_id()`, which derives its value from the `$_SESSION['_cid']` session variable. This value is subsequently concatenated directly into a shell command string **without any sanitization or escaping** (e.g., using `escapeshellarg()`). If an attacker can manipulate or poison their session data to inject arbitrary shell metacharacters into the `$_SESSION['_cid']` variable, they can achieve arbitrary command execution on the underlying server.

---

## `[03]` Technical Details

> **Vulnerable File:** `/main/inc/ajax/gradebook.ajax.php`  
> **Vulnerable Function:** `export_all_certificates` case

### Root Cause Analysis

When a user triggers the `export_all_certificates` action, the script attempts to run a background process for processing certificates:

```php
$courseCode = api_get_course_id(); // Retrieves the value from $_SESSION['_cid']
$sessionId = api_get_session_id();
// ...
$commandScript = api_get_path(SYS_CODE_PATH).'gradebook/cli/export_all_certificates.php';
$userList = implode(',', $userList);

// Flaw: Variables like $courseCode are passed directly to the shell without escapeshellarg()
shell_exec("php $commandScript $courseCode $sessionId $categoryId $userList > /dev/null &");
```

Because the application **implicitly trusts the contents of the session variables** and fails to properly escape them before sending them to the system shell, an attacker with a manipulated session can append and execute malicious commands. For example, if `_cid` contains `"; touch /tmp/rce_confirmed; #"`, the command interpreted by the bash/sh shell becomes:

```bash
php /path/to/script.php ; touch /tmp/rce_confirmed; # ... > /dev/null &
```

The shell executes the CLI script, followed by the injected payload, and ignores the rest of the intended command string.

---

## `[04]` Proof of Concept Strategy

**1. Session Poisoning**

The attacker must first influence the `$_SESSION['_cid']` variable. This can be achieved by chaining this flaw with a session poisoning vulnerability or by manipulating the course code value through an IDOR or insecure parameter handling elsewhere in the application to update their session context.

**2. Payload Injection**

Set the `_cid` session variable to:

```
"; [MALICIOUS_COMMAND]; #"
```

**3. Execution**

Send a `GET` request to the vulnerable endpoint with the poisoned session cookie:

```http
GET /main/inc/ajax/gradebook.ajax.php?a=export_all_certificates&cat_id=1 HTTP/1.1
Host: <TARGET>
Cookie: PHPSESSID=<POISONED_SESSION>
```

**4. Result**

The server blindly executes the injected command with the privileges of the web application user (`www-data`).

---

## `[05]` Impact Analysis

| Pillar | Impact |
|---|---|
| 🔴 **Confidentiality** | Attacker gets full access to read system files, application source code, and configuration files containing database credentials |
| 🔴 **Integrity** | Attacker can alter, deface, or sabotage the application, database, and filesystem |
| 🔴 **Availability** | Attacker can bring down the server by deleting files, exhausting resources, or installing ransomware |
| ⚙️ **CVSSv3.1** | `8.8 (HIGH)` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |

---

## `[06]` Recommendations & Remediation

### Apply `escapeshellarg()`

Wrap all user-derived variables (like `$courseCode`, `$sessionId`, and `$userList`) with PHP's `escapeshellarg()` before passing them to `shell_exec()` to neutralize arbitrary OS metacharacters:

```php
shell_exec(
    "php " . escapeshellarg($commandScript) .
    " " . escapeshellarg($courseCode) .
    " " . escapeshellarg($sessionId) .
    " " . escapeshellarg($categoryId) .
    " " . escapeshellarg($userList) .
    " > /dev/null &"
);
```

### Strict Session Validation

Ensure variables stored in the session state (e.g., `$_SESSION['_cid']`) are rigidly typed and sanitized so that potential **Session Poisoning** or IDOR chaining attacks are blocked at the entry point.

### Enforce Least Privilege

Configure the web server service (`www-data`) with restrictive filesystem write permissions and limit application access to essential Linux shell binaries to mitigate post-exploitation capabilities.

---

<div align="center">

**Researcher** · [K](https://github.com/kx00007) &nbsp;·&nbsp; Phnom Penh, Cambodia  
*Responsible disclosure conducted in accordance with coordinated vulnerability disclosure best practices.*  
*PoC details withheld until vendor patch is available.*

</div>
