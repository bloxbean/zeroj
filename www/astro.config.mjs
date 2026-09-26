// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import { SITE_URL, REPO_URL } from './site.config.mjs';
import remarkVersions from './scripts/remark-versions.mjs';
import aiArtifacts from './scripts/ai-integration.mjs';

export default defineConfig({
  site: SITE_URL,
  trailingSlash: 'always',
  markdown: {
    // unified (remark/rehype) processor so the version-token plugin runs before Expressive Code.
    processor: unified({ remarkPlugins: [remarkVersions] }),
  },
  integrations: [
    starlight({
      title: 'ZeroJ',
      description:
        'Zero-knowledge proofs for the JVM. Define circuits in Java, prove with a pure-Java Groth16 prover, and verify in Java or on Cardano.',
      logo: { src: './public/zeroj-icon.svg', alt: 'ZeroJ' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: REPO_URL }],
      editLink: { baseUrl: `${REPO_URL}/edit/main/www/` },
      lastUpdated: false,
      customCss: ['./src/styles/docs.css'],
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
        PageTitle: './src/components/DocTitle.astro',
      },
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
        styleOverrides: { borderRadius: '10px' },
      },
      sidebar: [
        { label: 'Start here', items: [{ autogenerate: { directory: 'start' } }] },
        {
          label: 'Learn ZK',
          badge: { text: 'New to ZK?', variant: 'tip' },
          items: [{ autogenerate: { directory: 'learn' } }],
        },
        { label: 'Tutorials', items: [{ autogenerate: { directory: 'tutorials' } }] },
        {
          label: 'Guides',
          items: [
            { label: 'Circuits', items: [{ autogenerate: { directory: 'guides/circuits' } }] },
            { label: 'Proving', items: [{ autogenerate: { directory: 'guides/proving' } }] },
            { label: 'Verifying', items: [{ autogenerate: { directory: 'guides/verifying' } }] },
            {
              label: 'Credentials & state',
              items: [{ autogenerate: { directory: 'guides/credentials' } }],
            },
          ],
        },
        { label: 'Use cases', items: [{ autogenerate: { directory: 'use-cases' } }] },
        { label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
        { label: 'Build with AI', items: [{ autogenerate: { directory: 'ai' } }] },
      ],
      head: [
        { tag: 'link', attrs: { rel: 'icon', href: '/favicon.ico', sizes: '32x32' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
        {
          tag: 'link',
          attrs: { rel: 'alternate', type: 'text/plain', href: '/llms.txt', title: 'llms.txt' },
        },
        { tag: 'meta', attrs: { property: 'og:image', content: `${SITE_URL}/social.png` } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
      ],
    }),
    aiArtifacts(),
  ],
});
