<p align="center">
  <a href="https://numasec.ai">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="شعار Numasec">
    </picture>
  </a>
</p>
<p align="center">وكيل برمجة بالذكاء الاصطناعي مفتوح المصدر.</p>
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

### التثبيت

```bash
# YOLO
curl -fsSL https://numasec.ai/install | bash

# مديري الحزم
npm i -g numasec@latest        # او bun/pnpm/yarn
scoop install numasec             # Windows
choco install numasec             # Windows
brew install anomalyco/tap/numasec # macOS و Linux (موصى به، دائما محدث)
brew install numasec              # macOS و Linux (صيغة brew الرسمية، تحديث اقل)
sudo pacman -S numasec            # Arch Linux (Stable)
paru -S numasec-bin               # Arch Linux (Latest from AUR)
mise use -g numasec               # اي نظام
nix run nixpkgs#numasec           # او github:anomalyco/numasec لاحدث فرع dev
```

> [!TIP]
> احذف الاصدارات الاقدم من 0.1.x قبل التثبيت.

### تطبيق سطح المكتب (BETA)

يتوفر Numasec ايضا كتطبيق سطح مكتب. قم بالتنزيل مباشرة من [صفحة الاصدارات](https://github.com/anomalyco/numasec/releases) او من [numasec.ai/download](https://numasec.ai/download).

| المنصة                | التنزيل                               |
| --------------------- | ------------------------------------- |
| macOS (Apple Silicon) | `numasec-desktop-darwin-aarch64.dmg` |
| macOS (Intel)         | `numasec-desktop-darwin-x64.dmg`     |
| Windows               | `numasec-desktop-windows-x64.exe`    |
| Linux                 | `.deb` او `.rpm` او AppImage          |

```bash
# macOS (Homebrew)
brew install --cask numasec-desktop
# Windows (Scoop)
scoop bucket add extras; scoop install extras/numasec-desktop
```

#### مجلد التثبيت

يحترم سكربت التثبيت ترتيب الاولوية التالي لمسار التثبيت:

1. `$NUMASEC_INSTALL_DIR` - مجلد تثبيت مخصص
2. `$XDG_BIN_DIR` - مسار متوافق مع مواصفات XDG Base Directory
3. `$HOME/bin` - مجلد الثنائيات القياسي للمستخدم (ان وجد او امكن انشاؤه)
4. `$HOME/.numasec/bin` - المسار الافتراضي الاحتياطي

```bash
# امثلة
NUMASEC_INSTALL_DIR=/usr/local/bin curl -fsSL https://numasec.ai/install | bash
XDG_BIN_DIR=$HOME/.local/bin curl -fsSL https://numasec.ai/install | bash
```

### Agents

يتضمن Numasec وكيليْن (Agents) مدمجين يمكنك التبديل بينهما باستخدام زر `Tab`.

- **build** - الافتراضي، وكيل بصلاحيات كاملة لاعمال التطوير
- **plan** - وكيل للقراءة فقط للتحليل واستكشاف الكود
  - يرفض تعديل الملفات افتراضيا
  - يطلب الاذن قبل تشغيل اوامر bash
  - مثالي لاستكشاف قواعد كود غير مألوفة او لتخطيط التغييرات

بالاضافة الى ذلك يوجد وكيل فرعي **general** للبحث المعقد والمهام متعددة الخطوات.
يستخدم داخليا ويمكن استدعاؤه بكتابة `@general` في الرسائل.

تعرف على المزيد حول [agents](https://numasec.ai/docs/agents).

### التوثيق

لمزيد من المعلومات حول كيفية ضبط Numasec، [**راجع التوثيق**](https://numasec.ai/docs).

### المساهمة

اذا كنت مهتما بالمساهمة في Numasec، يرجى قراءة [contributing docs](./CONTRIBUTING.md) قبل ارسال pull request.

### البناء فوق Numasec

اذا كنت تعمل على مشروع مرتبط بـ Numasec ويستخدم "numasec" كجزء من اسمه (مثل "numasec-dashboard" او "numasec-mobile")، يرجى اضافة ملاحظة في README توضح انه ليس مبنيا بواسطة فريق Numasec ولا يرتبط بنا بأي شكل.

### FAQ

#### ما الفرق عن Claude Code؟

هو مشابه جدا لـ Claude Code من حيث القدرات. هذه هي الفروقات الاساسية:

- 100% مفتوح المصدر
- غير مقترن بمزود معين. نوصي بالنماذج التي نوفرها عبر [Numasec Zen](https://numasec.ai/zen)؛ لكن يمكن استخدام Numasec مع Claude او OpenAI او Google او حتى نماذج محلية. مع تطور النماذج ستتقلص الفجوات وستنخفض الاسعار، لذا من المهم ان يكون مستقلا عن المزود.
- دعم LSP جاهز للاستخدام
- تركيز على TUI. تم بناء Numasec بواسطة مستخدمي neovim ومنشئي [terminal.shop](https://terminal.shop)؛ وسندفع حدود ما هو ممكن داخل الطرفية.
- معمارية عميل/خادم. على سبيل المثال، يمكن تشغيل Numasec على جهازك بينما تقوده عن بعد من تطبيق جوال. هذا يعني ان واجهة TUI هي واحدة فقط من العملاء الممكنين.

---

**انضم الى مجتمعنا** [Discord](https://discord.gg/numasec) | [X.com](https://x.com/numasec)
