<p align="center">
  <a href="https://numasec.ai">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="Numasec logo">
    </picture>
  </a>
</p>
<p align="center">Numasec je open source AI agent za programiranje.</p>
<p align="center">
  <a href="https://numasec.ai/discord"><img alt="Discord" src="https://img.shields.io/discord/1391832426048651334?style=flat-square&label=discord" /></a>
  <a href="https://www.npmjs.com/package/numasec"><img alt="npm" src="https://img.shields.io/npm/v/numasec?style=flat-square" /></a>
  <a href="https://github.com/anomalyco/numasec/actions/workflows/publish.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/anomalyco/numasec/publish.yml?style=flat-square&branch=dev" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zht.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.bs.md">Bosanski</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.br.md">Português (Brasil)</a> |
  <a href="README.th.md">ไทย</a> |
  <a href="README.tr.md">Türkçe</a> |
  <a href="README.uk.md">Українська</a> |
  <a href="README.bn.md">বাংলা</a> |
  <a href="README.gr.md">Ελληνικά</a> |
  <a href="README.vi.md">Tiếng Việt</a>
</p>

[![Numasec Terminal UI](packages/web/src/assets/lander/screenshot.png)](https://numasec.ai)

---

### Instalacija

```bash
# YOLO
curl -fsSL https://numasec.ai/install | bash

# Package manageri
npm i -g numasec@latest        # ili bun/pnpm/yarn
scoop install numasec             # Windows
choco install numasec             # Windows
brew install anomalyco/tap/numasec # macOS i Linux (preporučeno, uvijek ažurno)
brew install numasec              # macOS i Linux (zvanična brew formula, rjeđe se ažurira)
sudo pacman -S numasec            # Arch Linux (Stable)
paru -S numasec-bin               # Arch Linux (Latest from AUR)
mise use -g numasec               # Bilo koji OS
nix run nixpkgs#numasec           # ili github:anomalyco/numasec za najnoviji dev branch
```

> [!TIP]
> Ukloni verzije starije od 0.1.x prije instalacije.

### Desktop aplikacija (BETA)

Numasec je dostupan i kao desktop aplikacija. Preuzmi je direktno sa [stranice izdanja](https://github.com/anomalyco/numasec/releases) ili sa [numasec.ai/download](https://numasec.ai/download).

| Platforma             | Preuzimanje                           |
| --------------------- | ------------------------------------- |
| macOS (Apple Silicon) | `numasec-desktop-darwin-aarch64.dmg` |
| macOS (Intel)         | `numasec-desktop-darwin-x64.dmg`     |
| Windows               | `numasec-desktop-windows-x64.exe`    |
| Linux                 | `.deb`, `.rpm`, ili AppImage          |

```bash
# macOS (Homebrew)
brew install --cask numasec-desktop
# Windows (Scoop)
scoop bucket add extras; scoop install extras/numasec-desktop
```

#### Instalacijski direktorij

Instalacijska skripta koristi sljedeći redoslijed prioriteta za putanju instalacije:

1. `$NUMASEC_INSTALL_DIR` - Prilagođeni instalacijski direktorij
2. `$XDG_BIN_DIR` - Putanja usklađena sa XDG Base Directory specifikacijom
3. `$HOME/bin` - Standardni korisnički bin direktorij (ako postoji ili se može kreirati)
4. `$HOME/.numasec/bin` - Podrazumijevana rezervna lokacija

```bash
# Primjeri
NUMASEC_INSTALL_DIR=/usr/local/bin curl -fsSL https://numasec.ai/install | bash
XDG_BIN_DIR=$HOME/.local/bin curl -fsSL https://numasec.ai/install | bash
```

### Agenti

Numasec uključuje dva ugrađena agenta između kojih možeš prebacivati tasterom `Tab`.

- **build** - Podrazumijevani agent sa punim pristupom za razvoj
- **plan** - Agent samo za čitanje za analizu i istraživanje koda
  - Podrazumijevano zabranjuje izmjene datoteka
  - Traži dozvolu prije pokretanja bash komandi
  - Idealan za istraživanje nepoznatih codebase-ova ili planiranje izmjena

Uključen je i **general** pod-agent za složene pretrage i višekoračne zadatke.
Koristi se interno i može se pozvati pomoću `@general` u porukama.

Saznaj više o [agentima](https://numasec.ai/docs/agents).

### Dokumentacija

Za više informacija o konfiguraciji Numasec-a, [**pogledaj dokumentaciju**](https://numasec.ai/docs).

### Doprinosi

Ako želiš doprinositi Numasec-u, pročitaj [upute za doprinošenje](./CONTRIBUTING.md) prije slanja pull requesta.

### Gradnja na Numasec-u

Ako radiš na projektu koji je povezan s Numasec-om i koristi "numasec" kao dio naziva, npr. "numasec-dashboard" ili "numasec-mobile", dodaj napomenu u svoj README da projekat nije napravio Numasec tim i da nije povezan s nama.

### FAQ

#### Po čemu se razlikuje od Claude Code-a?

Po mogućnostima je vrlo sličan Claude Code-u. Ključne razlike su:

- 100% open source
- Nije vezan za jednog provajdera. Iako preporučujemo modele koje nudimo kroz [Numasec Zen](https://numasec.ai/zen), Numasec možeš koristiti s Claude, OpenAI, Google ili čak lokalnim modelima. Kako modeli napreduju, razlike među njima će se smanjivati, a cijene padati, zato je nezavisnost od provajdera važna.
- LSP podrška odmah po instalaciji
- Fokus na TUI. Numasec grade neovim korisnici i kreatori [terminal.shop](https://terminal.shop); pomjeraćemo granice onoga što je moguće u terminalu.
- Klijent/server arhitektura. To, recimo, omogućava da Numasec radi na tvom računaru dok ga daljinski koristiš iz mobilne aplikacije, što znači da je TUI frontend samo jedan od mogućih klijenata.

---

**Pridruži se našoj zajednici** [Discord](https://discord.gg/numasec) | [X.com](https://x.com/numasec)
