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

<HomeContent />
