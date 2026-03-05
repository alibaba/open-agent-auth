---
layout: home

hero:
  name: Open Agent Auth
  text: Enterprise-Grade AI Agent Authorization
  tagline: Cryptographic identity binding, fine-grained authorization, and semantic audit trails for AI agents operating on behalf of users.
  image:
    src: /logo.png
    alt: Open Agent Auth
  actions:
    - theme: brand
      text: Get Started →
      link: /docs/guide/01-quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/alibaba/open-agent-auth

features:
  - icon: 🔐
    title: WIMSE Workload Identity
    details: Request-level isolation with temporary key pairs following the WIMSE protocol. Each user request operates in an independent virtual workload environment.
  - icon: 🔗
    title: Cryptographic Identity Binding
    details: Three-layer cryptographic binding (ID Token → WIT → AOAT) ensures end-to-end identity consistency from user authentication to resource access.
  - icon: 🎯
    title: Dynamic Policy Evaluation
    details: Runtime policy updates with OPA, RAM, ACL, and Scope evaluators — no service restart required. Fine-grained authorization for every agent operation.
  - icon: 🛡️
    title: Multi-Layer Verification
    details: Five-layer security validation at the Resource Server — workload authentication, request integrity, user authentication, identity consistency, and policy evaluation.
  - icon: 📝
    title: Semantic Audit Trail
    details: W3C VC-based verifiable credentials recording complete context from user input to resource operation, enabling transparent and auditable agent operations.
  - icon: 🌐
    title: Standard Protocols
    details: Built on OAuth 2.0, OpenID Connect, WIMSE, and MCP for seamless integration with existing infrastructure and identity providers.
---

<div class="oaa-overview">

## How It Works

When AI agents operate on behalf of users, Open Agent Auth ensures every action is **authenticated**, **authorized**, and **auditable** through a standards-based flow:

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant AgentIDP
    participant AgentUserIDP
    participant AuthServer
    participant ResourceServer

    User->>Agent: Natural Language Request
    Agent->>User: Should Execute User Login
    User->>AgentUserIDP: User Login
    AgentUserIDP-->>Agent: ID Token (After Login)
    Agent->>AgentIDP: Create Virtual Workload
    AgentIDP-->>Agent: WIT (Workload Identity Token)
    Agent->>AuthServer: PAR Request (with Operation Proposal JWT, contains ID Token and WIT)
    AuthServer-->>Agent: request_uri
    Agent->>User: Redirect to /authorize?request_uri=...
    User->>AuthServer: Approve Authorization
    AuthServer-->>Agent: AOAT (Agent Operation Authorization Token)
    Agent->>ResourceServer: Tool Call (WIT + AOAT + WPT)
    ResourceServer->>ResourceServer: Multi-Layer Verification
    ResourceServer-->>Agent: Execution Result
    Agent-->>User: Display Result
```

Built on [IETF Draft: Agent Operation Authorization](https://github.com/maxpassion/IETF-Agent-Operation-Authorization-draft), extending upon OAuth 2.0, OpenID Connect, WIMSE, and MCP protocols.

<div class="oaa-badges">

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Java](https://img.shields.io/badge/Java-17+-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3+-green.svg)
![Coverage](https://img.shields.io/badge/coverage-83%25-brightgreen)

</div>

</div>

<style>
.oaa-overview {
  max-width: 780px;
  margin: 2rem auto 4rem;
  padding: 0 1.5rem;
}
.oaa-overview h2 {
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  text-align: center;
  margin-bottom: 1rem;
}
.oaa-overview p {
  color: var(--vp-c-text-2);
  line-height: 1.7;
  text-align: center;
  margin-bottom: 2rem;
}
.oaa-badges {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 2rem;
}
.oaa-badges p {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  justify-content: center;
}
</style>
