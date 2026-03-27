/**
 * Application-wide constants and configuration
 */
export const config = {
  // Base URL
  baseUrl: "https://numasec.ai",

  // GitHub
  github: {
    repoUrl: "https://github.com/anomalyco/numasec",
    starsFormatted: {
      compact: "120K",
      full: "120,000",
    },
  },

  // Social links
  social: {
    twitter: "https://x.com/numasec",
    discord: "https://discord.gg/numasec",
  },

  // Static stats (used on landing page)
  stats: {
    contributors: "800",
    commits: "10,000",
    monthlyUsers: "5M",
  },
} as const
