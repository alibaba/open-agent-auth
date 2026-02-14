# Identity and Workload Management

This directory contains documentation about the identity and workload management architecture in the Open Agent Auth framework.

## Overview

The Identity and Workload Management layer provides the foundational identity infrastructure for the Open Agent Auth framework, implementing a dual-layer identity model that separates user identity from workload identity.

## Documentation

- [Overview](overview.md) - Identity and workload management overview
- [Identity Authentication Architecture](identity-authentication-architecture.md) - Agent User IDP, AS User IDP, and Agent IDP
- [Workload Isolation and Binding](workload-isolation-and-binding.md) - Virtual workload pattern, request-level isolation, and identity binding mechanism
- [Workload Identity Token Structure](workload-identity-token-structure.md) - WIT structure and claims
- [Implementation Details](implementation-details.md) - Component implementation details
- [Security and Performance](security-and-performance.md) - Security considerations and performance optimization

## Key Features

- **Dual-Layer Identity Model** - Separates user identity from workload identity
- **WIMSE Protocol** - Standardized workload authentication
- **Request-Level Isolation** - Fine-grained security boundaries
- **Cryptographic Identity Binding** - Unforgeable relationships between tokens
- **Virtual Workload Pattern** - Temporary, isolated workloads for each request

## Related Documentation

- [Token Reference](../token/README.md) - Learn about ID Tokens and Workload Identity Tokens
- [Authorization Flow](../authorization/README.md) - Understand how identity is used in authorization
- [Security and Audit](../security/README.md) - Security mechanisms

---

**Document Version**: 2.0.0  
**Last Updated**: 2026-02-09  
**Maintainer**: Open Agent Auth Team
