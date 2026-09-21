// Stegcore documentation site.
//
// The pages here are the same markdown files the repository has always shipped, so a reader
// browsing them on GitHub and a reader on the built site see the same words. That is why the
// pages sit at the root of this directory rather than under a `guide/` folder: `docs/cli-
// reference.md` is a path people already have bookmarked.
//
// `ignoreDeadLinks` is deliberately NOT set, so the build fails on a broken internal link.
// Links to files outside this directory (LICENSE, AUP.md, CHANGELOG.md) are written as full
// GitHub URLs, because a relative path out of `docs/` resolves on GitHub and nowhere else.

const BASE = process.env.DOCS_BASE || '/'

const REPO = 'https://github.com/The-Malware-Files/Stegcore'

export default {
  title: 'Stegcore',
  description:
    'Hide encrypted messages inside ordinary pictures and sound files, and check '
    + 'files for hidden content. Offline, no account, one native binary.',
  lang: 'en-GB',
  base: BASE,
  cleanUrls: true,
  lastUpdated: true,

  srcExclude: ['private/**', 'node_modules/**'],

  head: [
    ['link', { rel: 'icon', href: `${BASE}favicon.svg`, type: 'image/svg+xml' }],
    ['meta', { name: 'theme-color', content: '#F5F5F7' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Stegcore' }],
    ['meta', {
      property: 'og:description',
      content: 'Hide encrypted messages inside ordinary files.',
    }],
    // No `og:image` yet. Pointing one at a file that was never drawn gives
    // every share a blank preview, which is worse than no tag at all. Add the
    // tag and `public/social-card.png` in the same commit.
  ],

  themeConfig: {
    siteTitle: 'Stegcore',

    nav: [
      { text: 'Guide', link: '/what-it-is' },
      { text: 'CLI reference', link: '/cli-reference' },
      {
        text: 'Project',
        items: [
          { text: 'Releases', link: `${REPO}/releases` },
          { text: 'Acceptable Use Policy', link: `${REPO}/blob/main/AUP.md` },
          { text: 'Licence (AGPL-3.0-or-later)', link: `${REPO}/blob/main/LICENSE` },
          { text: 'Commercial licence', link: `${REPO}/blob/main/COMMERCIAL.md` },
        ],
      },
    ],

    sidebar: {
      '/': [
        {
          text: 'Start here',
          items: [
            { text: 'What it is', link: '/what-it-is' },
            { text: 'Install', link: '/install' },
          ],
        },
        {
          text: 'Using it',
          items: [
            { text: 'Hiding and recovering', link: '/user-guide' },
            { text: 'Analysing files', link: '/analysing' },
          ],
        },
        {
          text: 'Going further',
          items: [
            { text: 'The security model', link: '/security-model' },
            { text: 'CLI reference', link: '/cli-reference' },
            { text: 'How it compares', link: '/vs-alternatives' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: REPO },
    ],

    outline: { level: [2, 3], label: 'On this page' },

    editLink: {
      pattern: `${REPO}/edit/main/docs/:path`,
      text: 'Suggest a change to this page',
    },

    footer: {
      message:
        'Dual licensed: AGPL-3.0-or-later, or a commercial licence. '
        + 'The Acceptable Use Policy applies either way.',
      copyright: '© 2026 Daniel Iwugo',
    },

    search: { provider: 'local' },

    docFooter: { prev: 'Previous', next: 'Next' },
  },
}
