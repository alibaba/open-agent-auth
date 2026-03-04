import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: 'Open Agent Auth',
  description: 'Enterprise-Grade AI Agent Operation Authorization Framework',

  base: '/open-agent-auth/',
  srcDir: '.',
  outDir: '.vitepress/dist',

  srcExclude: [
    'README.md',
    'README.zh-CN.md',
    'CONTRIBUTING.md',
    'LICENSE',
    '**/node_modules/**',
    '**/open-agent-auth-*/**',
    '**/src/**',
    '**/target/**',
    '**/pom.xml',
    '**/*.java',
    '**/*.xml',
    '**/*.yml',
    '**/*.yaml',
    '**/*.properties',
    '**/*.gradle',
    '**/*.sh',
    '**/*.bat',
    '**/scripts/**',
    'docs/standard/**',
    'docs/guide/start/**',
    'docs/guide/configuration/**',
    'docs/guide/extension/**',
    'docs/guide/test/**',
  ],

  head: [
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', { href: 'https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300..700;1,9..40,300..700&family=JetBrains+Mono:wght@400;500;600&display=swap', rel: 'stylesheet' }],
  ],

  markdown: {
    lineNumbers: true,
    image: {
      lazyLoading: true,
    },
  },

  themeConfig: {
    logo: '/logo.png',
    siteTitle: 'Open Agent Auth',

    nav: [
      { text: 'Guide', link: '/docs/guide/01-quick-start', activeMatch: '/docs/guide/' },
      { text: 'API', link: '/docs/api/00-api-overview', activeMatch: '/docs/api/' },
      { text: 'Architecture', link: '/docs/architecture/', activeMatch: '/docs/architecture/' },
      { text: 'Blog', link: '/blogs/', activeMatch: '/blogs/' },
    ],

    sidebar: {
      '/docs/guide/': [
        {
          text: 'Getting Started',
          collapsed: false,
          items: [
            { text: 'Quick Start', link: '/docs/guide/01-quick-start' },
            { text: 'Mock LLM Guide', link: '/docs/guide/02-mock-llm-guide' },
          ],
        },
        {
          text: 'Integration',
          collapsed: false,
          items: [
            { text: 'Integration Guide', link: '/docs/guide/03-integration-guide' },
            { text: 'Configuration Reference', link: '/docs/guide/04-configuration' },
            { text: 'Integration Testing', link: '/docs/guide/07-integration-testing' },
          ],
        },
        {
          text: 'Extensions',
          collapsed: false,
          items: [
            { text: 'Policy Evaluator', link: '/docs/guide/05-policy-evaluator' },
            { text: 'Prompt Protection', link: '/docs/guide/06-prompt-protection' },
          ],
        },
      ],

      '/docs/api/': [
        {
          text: 'API Reference',
          collapsed: false,
          items: [
            { text: 'Overview', link: '/docs/api/00-api-overview' },
            { text: 'Actor API', link: '/docs/api/01-role-actor' },
            { text: 'Executor API', link: '/docs/api/02-aap-executor' },
            { text: 'Spring Boot Starter', link: '/docs/api/03-spring-boot-starter' },
          ],
        },
      ],

      '/docs/architecture/': [
        {
          text: 'Core Architecture',
          collapsed: false,
          items: [
            { text: 'Overview', link: '/docs/architecture/' },
            { text: 'Token Reference', link: '/docs/architecture/01-token' },
            { text: 'Identity & Workload', link: '/docs/architecture/02-identity' },
            { text: 'Authorization Flow', link: '/docs/architecture/03-authorization' },
            { text: 'Security', link: '/docs/architecture/04-security' },
          ],
        },
        {
          text: 'Protocol & Integration',
          collapsed: false,
          items: [
            { text: 'Agent Auth Flow', link: '/docs/architecture/05-agent-authorization-flow' },
            { text: 'MCP Protocol Adapter', link: '/docs/architecture/06-protocol-mcp' },
            { text: 'Spring Boot Integration', link: '/docs/architecture/07-spring-boot-integration' },
            { text: 'Infrastructure', link: '/docs/architecture/08-integration-infrastructure' },
          ],
        },
      ],

      '/blogs/': [
        {
          text: 'Blog',
          collapsed: false,
          items: [
            { text: 'All Posts', link: '/blogs/' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/alibaba/open-agent-auth' },
    ],

    footer: {
      message: 'Released under the Apache 2.0 License.',
      copyright: 'Copyright © 2026-present Alibaba Group',
    },

    search: {
      provider: 'local',
      options: {
        detailedView: true,
      },
    },

    editLink: {
      pattern: 'https://github.com/alibaba/open-agent-auth/edit/main/:path',
      text: 'Edit this page on GitHub',
    },

    lastUpdated: {
      text: 'Last updated',
    },

    outline: {
      level: [2, 3],
      label: 'On this page',
    },
  },
}))
