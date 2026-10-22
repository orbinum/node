import { defineConfig } from 'vitepress'
import { footnote } from "@mdit/plugin-footnote";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Orbinum",
  description: "Privacy-focused Substrate network with EVM compatibility and a ZK shielded pool",
  base: '/node',
  cleanUrls: true,

  themeConfig: {
    docsDir: 'docs',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Overview', link: '/overview' },
      { text: 'API', link: 'https://orbinum.github.io/node/rustdocs/pallet_shielded_pool/' }
    ],

    sidebar: [
      {
        text: 'Overview',
        items: [
          { text: 'Overview', link: '/overview' },
          { text: 'Accounts', link: '/accounts' }
        ]
      },
      {
        text: 'Guides',
        items: [
          { text: 'Optimization', link: '/optimization' },
          { text: 'Development workflow', link: '/development-workflow' },
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/orbinum/node' }
    ],

    footer: {
      message: 'Dual-licensed under Apache-2.0 and GPL-3.0',
      copyright: 'Copyright © 2025-present, Orbinum contributors'
    },
  },

  markdown: {
    toc: { level: [1, 2] },
    config: (md) => {
      md.use(footnote);
    },
  }
})
