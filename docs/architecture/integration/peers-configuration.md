## Peers Configuration (Convention over Configuration)

### Overview

The `peers` configuration provides a simplified way to declare peer services in the trust domain. A single `peers` declaration automatically expands into JWKS consumers, service discovery entries, and key definitions.

### How It Works

```yaml
open-agent-auth:
  peers:
    agent-idp:
      issuer: http://localhost:8082
```

The `RoleAwareConfigurationPostProcessor` automatically:

1. Creates a **JWKS consumer** for the peer
2. Creates a **service discovery entry** for the peer
3. **Infers key definitions** based on the enabled role's profile
4. Ensures a **default key provider** exists (in-memory) if none is configured
5. Enables the **JWKS provider** if the role profile requires it

### Before vs After

**Before (explicit — 50+ lines):**

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: wimse://default.trust.domain
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp
        aoat-verification:
          key-id: aoat-signing-key
          algorithm: RS256
          jwks-consumer: authorization-server
    jwks:
      provider:
        enabled: true
      consumers:
        agent-idp:
          enabled: true
          issuer: http://localhost:8082
        authorization-server:
          enabled: true
          issuer: http://localhost:8085
    service-discovery:
      services:
        agent-idp:
          base-url: http://localhost:8082
        authorization-server:
          base-url: http://localhost:8085
  roles:
    resource-server:
      enabled: true
      issuer: http://localhost:8086
```

**After (simplified — 12 lines):**

```yaml
open-agent-auth:
  roles:
    resource-server:
      enabled: true
      issuer: http://localhost:8086
  peers:
    agent-idp:
      issuer: http://localhost:8082
    authorization-server:
      issuer: http://localhost:8085
```

### Precedence

Explicit configuration always takes precedence. If you manually configure a key, JWKS consumer, or service discovery entry, the post-processor will **not** overwrite it.

### Role Profiles

Each role has a built-in profile (`RoleProfileRegistry`) defining its default requirements:

| Role | Signing Keys | Verification Keys | Encryption Keys | Required Peers |
|------|-------------|-------------------|-----------------|----------------|
| `agent-idp` | wit-signing | id-token-verification | — | agent-user-idp |
| `agent` | par-jwt-signing, vc-signing | wit-verification, id-token-verification | jwe-encryption | agent-idp, agent-user-idp, authorization-server |
| `authorization-server` | aoat-signing | wit-verification | jwe-decryption | as-user-idp, agent |
| `resource-server` | — | wit-verification, aoat-verification | — | agent-idp, authorization-server |
| `agent-user-idp` | id-token-signing | — | — | (none) |
| `as-user-idp` | id-token-signing | — | — | (none) |
