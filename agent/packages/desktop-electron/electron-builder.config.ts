import type { Configuration } from "electron-builder"

const channel = (() => {
  const raw = process.env.NUMASEC_CHANNEL
  if (raw === "dev" || raw === "beta" || raw === "prod") return raw
  return "dev"
})()

const getBase = (): Configuration => ({
  artifactName: "numasec-electron-${os}-${arch}.${ext}",
  directories: {
    output: "dist",
    buildResources: "resources",
  },
  files: ["out/**/*", "resources/**/*"],
  extraResources: [
    {
      from: "resources/",
      to: "",
      filter: ["numasec-cli*"],
    },
    {
      from: "native/",
      to: "native/",
      filter: ["index.js", "index.d.ts", "build/Release/mac_window.node", "swift-build/**"],
    },
  ],
  mac: {
    category: "public.app-category.developer-tools",
    icon: `resources/icons/icon.icns`,
    hardenedRuntime: true,
    gatekeeperAssess: false,
    entitlements: "resources/entitlements.plist",
    entitlementsInherit: "resources/entitlements.plist",
    notarize: true,
    target: ["dmg", "zip"],
  },
  dmg: {
    sign: true,
  },
  protocols: {
    name: "Numasec",
    schemes: ["numasec"],
  },
  win: {
    icon: `resources/icons/icon.ico`,
    target: ["nsis"],
  },
  nsis: {
    oneClick: false,
    allowToChangeInstallationDirectory: true,
    installerIcon: `resources/icons/icon.ico`,
    installerHeaderIcon: `resources/icons/icon.ico`,
  },
  linux: {
    icon: `resources/icons`,
    category: "Development",
    target: ["AppImage", "deb", "rpm"],
  },
})

function getConfig() {
  const base = getBase()

  switch (channel) {
    case "dev": {
      return {
        ...base,
        appId: "ai.numasec.desktop.dev",
        productName: "Numasec Dev",
        rpm: { packageName: "numasec-dev" },
      }
    }
    case "beta": {
      return {
        ...base,
        appId: "ai.numasec.desktop.beta",
        productName: "Numasec Beta",
        protocols: { name: "Numasec Beta", schemes: ["numasec"] },
        publish: { provider: "github", owner: "anomalyco", repo: "numasec-beta", channel: "latest" },
        rpm: { packageName: "numasec-beta" },
      }
    }
    case "prod": {
      return {
        ...base,
        appId: "ai.numasec.desktop",
        productName: "Numasec",
        protocols: { name: "Numasec", schemes: ["numasec"] },
        publish: { provider: "github", owner: "anomalyco", repo: "numasec", channel: "latest" },
        rpm: { packageName: "numasec" },
      }
    }
  }
}

export default getConfig()
