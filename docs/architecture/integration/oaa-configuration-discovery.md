## OAA Configuration Discovery

### Overview

The `/.well-known/oaa-configuration` endpoint exposes service metadata for automatic peer discovery and capability negotiation. Inspired by OIDC Discovery but tailored for multi-role agent authorization.

### Endpoint

```
GET /.well-known/oaa-configuration
```

### Response Format

```json
{
  "issuer": "http://localhost:8082",
  "roles": ["agent-idp"],
  "trust_domain": "wimse://default.trust.domain",
  "protocol_version": "1.0",
  "jwks_uri": "http://localhost:8082/.well-known/jwks.json",
  "signing_algorithms_supported": ["ES256"],
  "capabilities": {
    "workload_identity": { "enabled": true }
  },
  "endpoints": {
    "jwks": "http://localhost:8082/.well-known/jwks.json",
    "authorization": "http://localhost:8082/oauth/authorize"
  },
  "peers_required": ["agent-user-idp"]
}
```

### Protocol Versioning

The `protocol_version` field uses semantic versioning (e.g., `"1.0"`). Clients should check this field before processing the metadata.

### Discovery Client

`PeerConfigurationDiscoveryClient` provides robust peer metadata fetching:

- **Retry with exponential backoff** — Up to 3 retries (500ms → 1s → 2s)
- **Fail-fast mode** — Throws `IllegalStateException` on failure to prevent startup with incomplete configuration
- **Caching** — Successful results are cached to avoid redundant requests
- **Graceful degradation** — Returns `null` for 404 responses, allowing fallback to explicit configuration
