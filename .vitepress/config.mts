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
    ['link', { rel: 'icon', type: 'image/png', href: '/open-agent-auth/favicon.png' }],
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
    logo: '/public/logo.png',
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
            {
              text: 'Quick Start',
              link: '/docs/guide/01-quick-start',
              collapsed: false,
              items: [
                { text: 'Prerequisites', link: '/docs/guide/01-quick-start#2-prerequisites' },
                { text: 'Quick Start (5 Min)', link: '/docs/guide/01-quick-start#3-quick-start-5-minutes' },
                { text: 'Service Endpoints', link: '/docs/guide/01-quick-start#4-service-endpoints' },
                { text: 'Core Features', link: '/docs/guide/01-quick-start#5-core-features' },
                { text: 'Core Concepts', link: '/docs/guide/01-quick-start#6-core-concepts' },
                { text: 'Troubleshooting', link: '/docs/guide/01-quick-start#9-troubleshooting' },
              ],
            },
            { text: 'Mock LLM Guide', link: '/docs/guide/02-mock-llm-guide' },
          ],
        },
        {
          text: 'Integration',
          collapsed: false,
          items: [
            {
              text: 'Integration Guide',
              link: '/docs/guide/03-integration-guide',
              collapsed: false,
              items: [
                { text: 'Prerequisites', link: '/docs/guide/03-integration-guide#2-prerequisites' },
                { text: 'Role-Based Integration', link: '/docs/guide/03-integration-guide#3-role-based-integration' },
                { text: 'Additional Roles', link: '/docs/guide/03-integration-guide#4-additional-roles' },
                { text: 'Common Configuration', link: '/docs/guide/03-integration-guide#5-common-configuration' },
                { text: 'Deployment', link: '/docs/guide/03-integration-guide#6-deployment-considerations' },
              ],
            },
            {
              text: 'Configuration Reference',
              link: '/docs/guide/04-configuration',
              collapsed: false,
              items: [
                { text: 'Configuration Architecture', link: '/docs/guide/04-configuration#configuration-architecture' },
                { text: 'Infrastructure', link: '/docs/guide/04-configuration#infrastructure-configuration' },
                { text: 'Key Management', link: '/docs/guide/04-configuration#key-management-configuration' },
                { text: 'JWKS', link: '/docs/guide/04-configuration#jwks-configuration' },
                { text: 'Capabilities', link: '/docs/guide/04-configuration#capabilities-configuration' },
                { text: 'Roles', link: '/docs/guide/04-configuration#roles-configuration' },
                { text: 'Common Patterns', link: '/docs/guide/04-configuration#common-configuration-patterns' },
                { text: 'Troubleshooting', link: '/docs/guide/04-configuration#troubleshooting' },
              ],
            },
            {
              text: 'Integration Testing',
              link: '/docs/guide/07-integration-testing',
              collapsed: false,
              items: [
                { text: 'Preparing Environment', link: '/docs/guide/07-integration-testing#preparing-the-test-environment' },
                { text: 'Starting Services', link: '/docs/guide/07-integration-testing#starting-required-services' },
                { text: 'Running via CLI', link: '/docs/guide/07-integration-testing#running-integration-tests-via-command-line' },
                { text: 'Running from IDE', link: '/docs/guide/07-integration-testing#running-integration-tests-from-ide' },
                { text: 'Troubleshooting', link: '/docs/guide/07-integration-testing#troubleshooting-test-failures' },
              ],
            },
            {
              text: 'Admin Dashboard',
              link: '/docs/guide/08-admin-dashboard',
              collapsed: false,
              items: [
                { text: 'Enabling the Dashboard', link: '/docs/guide/08-admin-dashboard#enabling-the-admin-dashboard' },
                { text: 'Access Control', link: '/docs/guide/08-admin-dashboard#access-control' },
                { text: 'Dashboard Pages', link: '/docs/guide/08-admin-dashboard#dashboard-pages' },
                { text: 'Customizing Endpoints', link: '/docs/guide/08-admin-dashboard#customizing-endpoint-paths' },
                { text: 'Configuration Reference', link: '/docs/guide/08-admin-dashboard#complete-configuration-reference' },
                { text: 'Architecture', link: '/docs/guide/08-admin-dashboard#architecture' },
                { text: 'Troubleshooting', link: '/docs/guide/08-admin-dashboard#troubleshooting' },
              ],
            },
          ],
        },
        {
          text: 'Extensions',
          collapsed: false,
          items: [
            {
              text: 'Policy Evaluator',
              link: '/docs/guide/05-policy-evaluator',
              collapsed: false,
              items: [
                { text: 'Policy Evaluator Interface', link: '/docs/guide/05-policy-evaluator#policy-evaluator-interface' },
                { text: 'Custom Evaluators', link: '/docs/guide/05-policy-evaluator#custom-policy-evaluators-and-builders' },
                { text: 'Available Evaluators', link: '/docs/guide/05-policy-evaluator#available-policy-evaluators' },
                { text: 'Configuration & Usage', link: '/docs/guide/05-policy-evaluator#configuration-and-usage' },
                { text: 'Spring Boot Integration', link: '/docs/guide/05-policy-evaluator#integration-with-spring-boot' },
              ],
            },
            {
              text: 'Prompt Protection',
              link: '/docs/guide/06-prompt-protection',
              collapsed: false,
              items: [
                { text: 'Three Layers of Protection', link: '/docs/guide/06-prompt-protection#how-it-works-three-layers-of-protection' },
                { text: 'Setting It Up', link: '/docs/guide/06-prompt-protection#setting-it-up' },
                { text: 'Using in Code', link: '/docs/guide/06-prompt-protection#using-it-in-your-code' },
                { text: 'Security Standards', link: '/docs/guide/06-prompt-protection#working-with-security-standards' },
                { text: 'Real-World Examples', link: '/docs/guide/06-prompt-protection#real-world-examples' },
              ],
            },
          ],
        },
      ],

      '/docs/api/': [
        {
          text: 'API Reference',
          collapsed: false,
          items: [
            { text: 'Overview', link: '/docs/api/00-api-overview' },
            {
              text: 'Actor API',
              link: '/docs/api/01-role-actor',
              collapsed: false,
              items: [
                { text: 'Actor Architecture', link: '/docs/api/01-role-actor#🎭-actor-architecture' },
                { text: 'Agent Actor', link: '/docs/api/01-role-actor#🤖-agent-actor' },
                { text: 'ResourceServer Actor', link: '/docs/api/01-role-actor#🛡️-resourceserver-actor' },
                { text: 'AuthorizationServer Actor', link: '/docs/api/01-role-actor#🔐-authorizationserver-actor' },
                { text: 'UserIdentityProvider Actor', link: '/docs/api/01-role-actor#👤-useridentityprovider-actor' },
                { text: 'AgentIdentityProvider Actor', link: '/docs/api/01-role-actor#🤖-agentidentityprovider-actor' },
                { text: 'Actor Interactions', link: '/docs/api/01-role-actor#🔄-actor-interactions' },
              ],
            },
            {
              text: 'Executor API',
              link: '/docs/api/02-aap-executor',
              collapsed: false,
              items: [
                { text: 'Complete Workflow', link: '/docs/api/02-aap-executor#🔄-complete-workflow' },
                { text: 'Executor Interface', link: '/docs/api/02-aap-executor#🏗️-executor-interface' },
                { text: 'Method Guide', link: '/docs/api/02-aap-executor#📖-detailed-method-guide' },
                { text: 'Usage Example', link: '/docs/api/02-aap-executor#🎯-complete-usage-example' },
                { text: 'State Management', link: '/docs/api/02-aap-executor#🔄-workflow-state-management' },
                { text: 'Error Handling', link: '/docs/api/02-aap-executor#📊-error-handling' },
              ],
            },
            {
              text: 'Spring Boot Starter',
              link: '/docs/api/03-spring-boot-starter',
              collapsed: false,
              items: [
                { text: 'Controller Architecture', link: '/docs/api/03-spring-boot-starter#🏗️-controller-architecture' },
                { text: 'Controller Reference', link: '/docs/api/03-spring-boot-starter#📖-controller-reference' },
                { text: 'Quick Start', link: '/docs/api/03-spring-boot-starter#🚀-quick-start' },
                { text: 'Configuration', link: '/docs/api/03-spring-boot-starter#🔧-configuration' },
                { text: 'Customization', link: '/docs/api/03-spring-boot-starter#🎨-customization' },
              ],
            },
          ],
        },
      ],

      '/docs/architecture/': [
        {
          text: 'Core Architecture',
          collapsed: false,
          items: [
            { text: 'Overview', link: '/docs/architecture/' },
            {
              text: 'Token Reference',
              link: '/docs/architecture/01-token',
              collapsed: false,
              items: [
                { text: 'ID Token', link: '/docs/architecture/01-token#id-token' },
                { text: 'Workload Identity Token', link: '/docs/architecture/01-token#workload-identity-token-wit' },
                { text: 'Workload Proof Token', link: '/docs/architecture/01-token#workload-proof-token-wpt' },
                { text: 'PAR-JWT', link: '/docs/architecture/01-token#par-jwt-pushed-authorization-request-jwt' },
                { text: 'Verifiable Credential', link: '/docs/architecture/01-token#verifiable-credential-vc' },
                { text: 'Agent OA Token', link: '/docs/architecture/01-token#agent-operation-authorization-token' },
                { text: 'Token Flow', link: '/docs/architecture/01-token#token-flow-and-relationships' },
              ],
            },
            {
              text: 'Identity & Workload',
              link: '/docs/architecture/02-identity',
              collapsed: false,
              items: [
                { text: 'Authentication Architecture', link: '/docs/architecture/02-identity#identity-authentication-architecture' },
                { text: 'Workload Isolation', link: '/docs/architecture/02-identity#workload-isolation-model' },
                { text: 'Identity Binding', link: '/docs/architecture/02-identity#identity-binding-mechanism' },
                { text: 'WIT Structure', link: '/docs/architecture/02-identity#workload-identity-token-wit-structure' },
              ],
            },
            {
              text: 'Authorization Flow',
              link: '/docs/architecture/03-authorization',
              collapsed: false,
              items: [
                { text: 'OAuth 2.0 Flow', link: '/docs/architecture/03-authorization#oauth-2-0-authorization-code-flow' },
                { text: 'Agent OA Token Structure', link: '/docs/architecture/03-authorization#agent-oa-token-structure' },
                { text: 'Five-Layer Verification', link: '/docs/architecture/03-authorization#five-layer-verification-architecture' },
                { text: 'Security Considerations', link: '/docs/architecture/03-authorization#security-considerations' },
              ],
            },
            {
              text: 'Security',
              link: '/docs/architecture/04-security',
              collapsed: false,
              items: [
                { text: 'Cryptographic Protection', link: '/docs/architecture/04-security#cryptographic-protection' },
                { text: 'Identity Binding', link: '/docs/architecture/04-security#identity-binding-and-consistency' },
                { text: 'Key Management', link: '/docs/architecture/04-security#key-management' },
                { text: 'Threat Mitigation', link: '/docs/architecture/04-security#threat-mitigation' },
                { text: 'Audit & Compliance', link: '/docs/architecture/04-security#audit-and-compliance' },
              ],
            },
          ],
        },
        {
          text: 'Protocol & Integration',
          collapsed: false,
          items: [
            {
              text: 'Agent Auth Flow',
              link: '/docs/architecture/05-agent-authorization-flow',
              collapsed: false,
              items: [
                { text: 'Phase 1: User Auth', link: '/docs/architecture/05-agent-authorization-flow#phase-1-user-authentication' },
                { text: 'Phase 2: Workload Creation', link: '/docs/architecture/05-agent-authorization-flow#phase-2-workload-creation' },
                { text: 'Phase 3: OAuth DCR', link: '/docs/architecture/05-agent-authorization-flow#phase-3-oauth-client-registration-dcr' },
                { text: 'Phase 4: Authorization Request', link: '/docs/architecture/05-agent-authorization-flow#phase-4-authorization-request' },
                { text: 'Phase 5: User Authorization', link: '/docs/architecture/05-agent-authorization-flow#phase-5-user-authorization' },
                { text: 'Phase 6: Token & Execution', link: '/docs/architecture/05-agent-authorization-flow#phase-6-token-exchange-tool-execution' },
              ],
            },
            {
              text: 'MCP Protocol Adapter',
              link: '/docs/architecture/06-protocol-mcp',
              collapsed: false,
              items: [
                { text: 'MCP Fundamentals', link: '/docs/architecture/06-protocol-mcp#mcp-protocol-fundamentals' },
                { text: 'Server Design', link: '/docs/architecture/06-protocol-mcp#openagentauthmcpserver-design' },
                { text: 'Tool Registration', link: '/docs/architecture/06-protocol-mcp#tool-registration-and-execution' },
                { text: 'Error Handling', link: '/docs/architecture/06-protocol-mcp#error-handling-and-response' },
              ],
            },
            {
              text: 'Spring Boot Integration',
              link: '/docs/architecture/07-spring-boot-integration',
              collapsed: false,
              items: [
                { text: 'Role Detection', link: '/docs/architecture/07-spring-boot-integration#role-detection-mechanism' },
                { text: 'Autoconfiguration', link: '/docs/architecture/07-spring-boot-integration#autoconfiguration-principles' },
                { text: 'Configuration Properties', link: '/docs/architecture/07-spring-boot-integration#configuration-properties-system' },
                { text: 'Bean Lifecycle', link: '/docs/architecture/07-spring-boot-integration#bean-lifecycle-management' },
                { text: 'Customization', link: '/docs/architecture/07-spring-boot-integration#customization-and-extension' },
              ],
            },
            {
              text: 'Infrastructure',
              link: '/docs/architecture/08-integration-infrastructure',
              collapsed: false,
              items: [
                { text: 'Key Resolution SPI', link: '/docs/architecture/08-integration-infrastructure#key-resolution-spi' },
                { text: 'Peers Configuration', link: '/docs/architecture/08-integration-infrastructure#peers-configuration-convention-over-configuration' },
                { text: 'OAA Discovery', link: '/docs/architecture/08-integration-infrastructure#oaa-configuration-discovery' },
              ],
            },
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
