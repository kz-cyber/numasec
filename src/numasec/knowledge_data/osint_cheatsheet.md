# OSINT Cheatsheet (Open Source Intelligence)

## 🔍 Google Dorks (Motori di Ricerca)
Usa questi operatori su Google per trovare file esposti o informazioni.

- `site:target.com` -> Cerca solo nel dominio target.
- `filetype:pdf` (o `docx`, `xlsx`, `txt`) -> Cerca file specifici.
- `intitle:"index of"` -> Cerca Directory Listing aperte.
- `inurl:admin` -> Cerca URL che contengono "admin".
- `"password" filetype:txt site:target.com` -> Cerca file di testo con password.
- `cache:target.com` -> Vedi la versione cache del sito (se è offline).

## 👤 Username & Social Media
Se hai un username (es. `sloth_ctf`), cercalo ovunque.

1. **URL Check Manuale**:
   - `instagram.com/username`
   - `twitter.com/username`
   - `github.com/username`
   - `facebook.com/username`
   - `reddit.com/user/username`
   - `t.me/username` (Telegram)

2. **Tool Online**:
   - [Namechk](https://namechk.com/)
   - [Sherlock](https://github.com/sherlock-project/sherlock) (Tool python potente)
   - [WhatsMyName](https://whatsmyname.app/)

## 🖼️ Image Intelligence (IMINT)
Se hai una foto:

1. **Reverse Image Search**:
   - [Google Images](https://images.google.com/)
   - [Yandex Images](https://yandex.com/images/) (Il migliore per la Russia/Est Europa).
   - [TinEye](https://tineye.com/)
   - [Bing Visual Search](https://www.bing.com/visualsearch)

2. **Geolocalizzazione**:
   - Guarda i cartelli stradali, le targhe, l'architettura.
   - Guarda l'ombra (lunghezza e direzione indicano l'ora).
   - [GeoGuessr](https://www.geoguessr.com/) (per allenarsi).

3. **EXIF Data**:
   - Usa `exiftool image.jpg` per vedere coordinate GPS, modello fotocamera, data scatto.

## 📧 Email OSINT
- [HaveIBeenPwned](https://haveibeenpwned.com/) -> Controlla se l'email è in un leak.
- [Hunter.io](https://hunter.io/) -> Trova pattern email aziendali.
- [Epios](https://epios.com/) -> Trova account Google/Calendar collegati all'email.

## 🗺️ Maps & Satelliti
- Google Maps / Street View.
- Google Earth Pro (Desktop).
- Yandex Maps.
- Baidu Maps (Cina).

## 📡 WayBack Machine
- [Archive.org](https://web.archive.org/) -> Vedi versioni vecchie del sito. Spesso trovi flag rimosse o commenti cancellati.
