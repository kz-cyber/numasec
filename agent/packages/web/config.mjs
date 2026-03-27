const stage = process.env.SST_STAGE || "dev"

export default {
  url: stage === "production" ? "https://numasec.com" : `https://${stage}.numasec.com`,
  console: stage === "production" ? "https://numasec.com/auth" : `https://${stage}.numasec.com/auth`,
  email: "contact@anoma.ly",
  socialCard: "https://social-cards.sst.dev",
  github: "https://github.com/numasec/numasec",
  discord: "https://numasec.com/discord",
  headerLinks: [
    { name: "app.header.home", url: "/" },
    { name: "app.header.docs", url: "/docs/" },
  ],
}
