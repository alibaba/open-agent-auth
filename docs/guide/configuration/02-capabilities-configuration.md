# Capabilities Configuration Guide

## Introduction

Capabilities represent reusable functional features in the Open Agent Auth framework. Each capability provides a specific set of functionality that can be composed by roles to create complete, working applications.

## Configuration Overview

Capabilities are configured under `open-agent-auth.capabilities`:

```yaml
open-agent-auth:
  capabilities:
    oauth2-server: {...}
    oauth2-client: {...}
    workload-identity: {...}
    operation-authorization: {...}
    user-authentication: {...}
    audit: {...}
```

### Available Capabilities

| Capability | Description | Typical Use Cases                           |
|------------|-------------|---------------------------------------------|
| **oauth2-server** | OAuth 2.0 authorization server functionality | Authorization Server, Agent User IDP, AS User IDP |
| **oauth2-client** | OAuth 2.0 client functionality | Agent, Resource Server                      |
| **workload-identity** | Workload identity management | Agent IDP, Agent, Resource Server           |
| **operation-authorization** | Fine-grained authorization for agent operations | Agent, Authorization Server                 |
| **user-authentication** | User identity and login | Agent User IDP, AS User IDP                 |
| **audit** | Audit logging for security events | Authorization Server                        |

---

## OAuth 2.0 Server Capability

### Overview

The OAuth 2.0 Server capability provides complete OAuth 2.0 authorization server functionality, including authorization flows, token issuance, and client management. It supports standard OAuth 2.0 flows such as authorization code, implicit, and client credentials.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      endpoints:
        oauth2:
          authorize: /oauth2/authorize
          token: /oauth2/token
          par: /par
          userinfo: /oauth2/userinfo
          dcr: /oauth2/register
          logout: /oauth2/logout
      token:
        accessTokenExpiry: 3600
        refreshTokenExpiry: 2592000
        idTokenExpiry: 3600
        authorizationCodeExpiry: 600
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether OAuth 2.0 Server capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `oauth2.authorize` | String | Authorization endpoint path | `/oauth2/authorize` |
| `oauth2.token` | String | Token endpoint path | `/oauth2/token` |
| `oauth2.par` | String | PAR endpoint path | `/par` |
| `oauth2.userinfo` | String | Userinfo endpoint path | `/oauth2/userinfo` |
| `oauth2.dcr` | String | DCR endpoint path | `/oauth2/register` |
| `oauth2.logout` | String | Logout endpoint path | `/oauth2/logout` |

#### Token Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `accessTokenExpiry` | Integer | Access token expiry in seconds | `3600` |
| `refreshTokenExpiry` | Integer | Refresh token expiry in seconds | `2592000` |
| `idTokenExpiry` | Integer | ID token expiry in seconds | `3600` |
| `authorizationCodeExpiry` | Integer | Authorization code expiry in seconds | `600` |

#### Auto-Register Clients Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether auto-register clients is enabled | `false` |
| `clients` | List | List of client configurations | Empty list |

#### Client Configuration Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `clientName` | String | Human-readable client name | Yes |
| `clientId` | String | OAuth 2.0 client ID | Yes |
| `clientSecret` | String | OAuth 2.0 client secret | Yes |
| `redirectUris` | List | Allowed redirect URIs | Yes |
| `grantTypes` | List | Allowed grant types | Yes |
| `responseTypes` | List | Allowed response types | Yes |
| `tokenEndpointAuthMethod` | String | Token endpoint auth method | No |
| `scopes` | List | Allowed scopes | Yes |

### Supported Grant Types

| Grant Type | Description |
|------------|-------------|
| `authorization_code` | Authorization code flow (recommended) |
| `implicit` | Implicit flow |
| `client_credentials` | Client credentials flow |
| `refresh_token` | Refresh token flow |

### Supported Response Types

| Response Type | Description |
|---------------|-------------|
| `code` | Authorization code |
| `token` | Access token (implicit flow) |
| `id_token` | ID token (implicit flow) |

### Supported Token Endpoint Auth Methods

| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic authentication |
| `client_secret_post` | Client credentials in POST body |
| `private_key_jwt` | JWT-based authentication |
| `none` | Public client (no authentication) |

### Best Practices

1. **Use Authorization Code Flow**: Prefer authorization code flow with PKCE for security
2. **Set Appropriate Token Expiry**: Balance security and user experience
3. **Use HTTPS**: Always use HTTPS in production
4. **Validate Redirect URIs**: Strictly validate redirect URIs to prevent open redirect attacks
5. **Enable PAR**: Use Pushed Authorization Request (PAR) for enhanced security

---

## OAuth 2.0 Client Capability

### Overview

The OAuth 2.0 Client capability enables applications to act as OAuth 2.0 clients and obtain tokens from authorization servers. It provides authentication for protected endpoints and handles OAuth 2.0 authorization flows.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      enabled: true
      authentication:
        enabled: true
        include-paths:
          - /api/**
          - /tools/**
        exclude-paths:
          - /health
          - /public/**
      callback:
        enabled: true
        endpoint: /callback
        client-id: agent-client-id
        client-secret: agent-client-secret
        auto-register: true
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether OAuth 2.0 Client capability is enabled | `false` |

#### Authentication Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether authentication is enabled | `true` |
| `include-paths` | List | Paths requiring authentication | `["/**"]` |
| `exclude-paths` | List | Paths excluded from authentication | `["/login", "/callback", "/public/**", "/oauth2/consent", "/oauth2/authorize", "/.well-known/**"]` |

#### Callback Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether callback is enabled | `false` |
| `endpoint` | String | Callback endpoint path | `/callback` |
| `auto-register` | Boolean | Whether to auto-register client | `false` |

> **Note**: Client credentials (`client-id`, `client-secret`) are now configured at the `oauth2-client` top level, not within `callback`. See [OAuth2 Client Properties](#properties) above.

### Path Matching

The framework supports Ant-style path patterns for path matching:

| Pattern | Description | Example Matches |
|---------|-------------|-----------------|
| `/**` | All paths | All paths |
| `/api/**` | All paths under `/api` | `/api/users`, `/api/posts` |
| `/api/v1/**` | All paths under `/api/v1` | `/api/v1/users`, `/api/v1/posts` |
| `/public/**` | All paths under `/public` | `/public/index.html` |
| `*.html` | All HTML files | `index.html`, `about.html` |

### Best Practices

1. **Use Specific Include Paths**: Be specific about which paths require authentication
2. **Exclude OAuth2 Endpoints**: Default exclude paths already include OAuth2 endpoints, health, and public paths
3. **Secure Client Credentials**: Store client secrets in environment variables
4. **Use Auto-Register**: Enable auto-register for dynamic client registration
5. **Monitor Authentication**: Monitor authentication failures for security

---

## Workload Identity Capability

### Overview

The Workload Identity capability provides workload identity management and token issuance for applications and services. It enables workloads to obtain identity tokens for authentication and authorization within the trust domain.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    workload-identity:
      enabled: true
      endpoints:
        workload:
          revoke: /api/v1/workloads/revoke
          retrieve: /api/v1/workloads/get
          issue: /api/v1/workloads/token/issue
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Workload Identity capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `workload.revoke` | String | Revoke workload endpoint path | `/api/v1/workloads/revoke` |
| `workload.retrieve` | String | Retrieve workload endpoint path | `/api/v1/workloads/get` |
| `workload.issue` | String | Issue workload token endpoint path | `/api/v1/workloads/token/issue` |

### Workload Identity Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Workload Identity Flow                       │
└─────────────────────────────────────────────────────────────────┘

1. Workload Token Issuance
   └─> POST /api/v1/workloads/token/issue
       └─> Returns Workload Identity Token (WIT)

2. Workload Query
   └─> POST /api/v1/workloads/get
       └─> Returns workload information

3. Workload Revocation
   └─> POST /api/v1/workloads/revoke
       └─> Invalidates workload and tokens
```

### Use Cases

- **Service-to-Service Authentication**: Enable services to authenticate with each other
- **Kubernetes Workloads**: Provide identity to Kubernetes pods and services
- **Microservices**: Enable secure communication between microservices
- **Batch Jobs**: Provide identity to batch jobs and scheduled tasks

### Best Practices

1. **Use Short-Lived Tokens**: Issue tokens with short expiry for security
2. **Implement Rotation**: Regularly rotate workload identities
3. **Audit Usage**: Monitor workload identity usage for security
4. **Secure Endpoints**: Protect workload identity endpoints with authentication
5. **Document Workflows**: Document workload identity creation and usage workflows

---

## Operation Authorization Capability

### Overview

The Operation Authorization capability provides fine-grained authorization for agent operations, including prompt protection, policy evaluation, and binding management. It enables agents to request authorization for specific operations based on policies and user bindings.

### Configuration
```yaml
open-agent-auth:
  capabilities:
    operation-authorization:
      enabled: true
      endpoints:
        policy:
          registry: /api/v1/policies/register
          retrieve: /api/v1/policies/get
          delete: /api/v1/policies/delete
        binding:
          registry: /api/v1/bindings/register
          retrieve: /api/v1/bindings/get
          delete: /api/v1/bindings/delete
      prompt-encryption:
        enabled: true
        encryption-key-id: null
        encryption-algorithm: RSA-OAEP-256
        content-encryption-algorithm: A256GCM
        jwks-consumer: authorization-server
      prompt-protection:
        enabled: true
        encryption-enabled: true
        sanitization-level: MEDIUM
      agent-context:
        default-client: my-agent-client
        default-channel: web
        default-language: zh-CN
        default-platform: my-agent-platform
        default-device-fingerprint: my-device-fingerprint
      authorization:
        require-user-interaction: false
        expiration-seconds: 3600
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Operation Authorization capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `policy.registry` | String | Policy registry endpoint path | `/api/v1/policies/register` |
| `policy.retrieve` | String | Retrieve policy by ID endpoint path | `/api/v1/policies/get` |
| `policy.delete` | String | Delete policy endpoint path | `/api/v1/policies/delete` |
| `binding.registry` | String | Binding registry endpoint path | `/api/v1/bindings/register` |
| `binding.retrieve` | String | Retrieve binding by ID endpoint path | `/api/v1/bindings/get` |
| `binding.delete` | String | Delete binding endpoint path | `/api/v1/bindings/delete` |

#### Prompt Encryption Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether prompt encryption is enabled | `false` |
| `encryption-key-id` | String | Encryption key ID | `null` |
| `encryption-algorithm` | String | Key encryption algorithm | `RSA-OAEP-256` |
| `content-encryption-algorithm` | String | Content encryption algorithm | `A256GCM` |
| `jwks-consumer` | String | JWKS consumer name for fetching public key | Optional |

#### Prompt Protection Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether prompt protection is enabled | `true` |
| `encryption-enabled` | Boolean | Whether encryption is enabled | `true` |
| `sanitization-level` | String | Sanitization level | `MEDIUM` |

#### Agent Context Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `default-client` | String | Default agent client identifier | `null` |
| `default-channel` | String | Default channel type | `web` |
| `default-language` | String | Default language preference | `zh-CN` |
| `default-platform` | String | Default platform identifier | `null` |
| `default-device-fingerprint` | String | Default device fingerprint | `null` |

> **Note**: OAuth 2.0 client credentials (`client-id`, `client-secret`) are now configured at the `capabilities.oauth2-client` top level, shared across all OAuth 2.0 flows. The `oauth2-client` sub-section has been removed from `operation-authorization`.

#### Authorization Behavior Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `require-user-interaction` | Boolean | Whether user interaction is required | `false` |
| `expiration-seconds` | Integer | Expiration time in seconds | `3600` |

### Sanitization Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `LOW` | Minimal sanitization | Development, testing |
| `MEDIUM` | Standard sanitization | Recommended for most cases |
| `HIGH` | Strict sanitization | High-security environments |

### Supported Encryption Algorithms

| Algorithm | Type | Description |
|-----------|------|-------------|
| `RSA-OAEP-256` | Key encryption | RSA with OAEP padding and SHA-256 |
| `RSA-OAEP` | Key encryption | RSA with OAEP padding and SHA-1 |
| `ECDH-ES` | Key encryption | Elliptic Curve Diffie-Hellman |

| Algorithm | Type | Description |
|-----------|------|-------------|
| `A256GCM` | Content encryption | AES-GCM with 256-bit key |
| `A128GCM` | Content encryption | AES-GCM with 128-bit key |
| `A256CBC-HS512` | Content encryption | AES-CBC with HMAC-SHA-512 |

### Operation Authorization Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              Operation Authorization Flow                        │
└─────────────────────────────────────────────────────────────────┘

1. Agent Request
   └─> Agent requests authorization for operation
       └─> Prompt is sanitized and encrypted

2. Authorization Request
   └─> POST /oauth2/authorize
       └─> Includes workload identity, operation details

3. Policy Evaluation
   └─> GET /api/v1/policies
       └─> Retrieves applicable policies

4. Binding Check
   └─> GET /api/v1/bindings/{bindingInstanceId}
       └─> Checks user bindings and permissions

5. User Approval (if required)
   └─> User approves or denies operation
       └─> Interactive consent flow

6. Token Issuance
   └─> Agent Operation Authorization Token (AOAT) issued
       └─> Token includes operation permissions

7. Operation Execution
   └─> Agent executes operation with AOAT
       └─> Resource server validates token
```

### Best Practices

1. **Enable Prompt Encryption**: Always encrypt prompts in production
2. **Use Appropriate Sanitization**: Choose sanitization level based on security requirements
3. **Require User Interaction**: Enable for sensitive operations
4. **Set Short Token Expiry**: Use short-lived tokens for security
5. **Monitor Authorizations**: Audit authorization requests and decisions

---

## User Authentication Capability

### Overview

The User Authentication capability provides user identity authentication including login page, user registry, and session management. It supports multiple user registry types and customizable login pages.

### Configuration
```yaml
open-agent-auth:
  capabilities:
    user-authentication:
      enabled: true
      loginPage:
        enabled: true
        pageTitle: Identity Provider - Login
        title: Identity Provider
        subtitle: Please sign in to continue
        usernameLabel: Username
        passwordLabel: Password
        buttonText: Sign In
        showDemoUsers: false
        demoUsers: ""
        footerText: © 2024 My Company
        template: classpath:/templates/login.html
      userRegistry:
        enabled: true
        type: in-memory
        presetUsers:
          - username: admin
            password: admin123
            subject: user_admin_001
            email: admin@example.com
            name: Admin User
          - username: user
            password: user123
            subject: user_001
            email: user@example.com
            name: Regular User
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether User Authentication capability is enabled | `false` |

#### Login Page Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether default login page is enabled | `true` |
| `pageTitle` | String | Page title displayed in browser tab | `Identity Provider - Login` |
| `title` | String | Main title displayed on login page | `Identity Provider` |
| `subtitle` | String | Subtitle displayed below main title | `Please sign in to continue` |
| `usernameLabel` | String | Label for username field | `Username` |
| `passwordLabel` | String | Label for password field | `Password` |
| `buttonText` | String | Text for login button | `Sign In` |
| `showDemoUsers` | Boolean | Whether to display demo users | `false` |
| `demoUsers` | String | Demo users in format "username:password;..." | Empty string |
| `footerText` | String | Footer text displayed at bottom | Empty string |
| `template` | String | Login page template path | `classpath:/templates/login.html` |

#### User Registry Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether user registry is enabled | `true` |
| `type` | String | User registry type | `in-memory` |
| `presetUsers` | List | List of preset users | Empty list |

#### Preset User Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `username` | String | Username for authentication | Yes |
| `password` | String | Password for authentication | Yes |
| `subject` | String | Subject identifier | No |
| `email` | String | User email address | No |
| `name` | String | User display name | No |

### User Registry Types

| Type | Description | Use Case |
|------|-------------|----------|
| `in-memory` | Users stored in memory | Development, testing |

### Custom Login Page

To provide a custom login page:

1. Create a custom template at `classpath:/templates/custom-login.html`
2. Configure the template path:

```yaml
open-agent-auth:
  capabilities:
    user-authentication:
      loginPage:
        template: classpath:/templates/custom-login.html
```

### Best Practices

1. **Secure Passwords**: Hash passwords using strong algorithms (bcrypt, Argon2)
3. **Customize Login Page**: Customize login page for branding
4. **Disable Demo Users**: Never enable demo users in production
5. **Implement MFA**: Consider multi-factor authentication for enhanced security

---

Capabilities are designed to be composed by roles to create complete applications. Here are some common compositions:

### Authorization Server Composition

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
    operation-authorization:
      enabled: true
    workload-identity:
      enabled: true
  roles:
    authorization-server:
      enabled: true
      capabilities:
        - oauth2-server
        - operation-authorization
        - workload-identity
```

### Agent Composition

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      enabled: true
    operation-authorization:
      enabled: true
  roles:
    agent:
      enabled: true
      capabilities:
        - oauth2-client
        - operation-authorization
```

### Agent IDP Composition

```yaml
open-agent-auth:
  capabilities:
    workload-identity:
      enabled: true
  roles:
    agent-idp:
      enabled: true
      capabilities:
        - workload-identity
```

---

## Audit Capability

### Overview

The Audit capability provides audit logging functionality for tracking security events, user actions, agent operations, and system activities across the Idem Agent Auth framework.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    audit:
      enabled: true
      provider: logging
      endpoints:
        event:
          retrieve: /api/v1/audit/events/get
          list: /api/v1/audit/events/list
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Audit capability is enabled | `false` |

#### Provider Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `provider` | String | Audit provider implementation | `logging` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `event.retrieve` | String | Retrieve audit event by ID endpoint path | `/api/v1/audit/events/get` |
| `event.list` | String | List audit events endpoint path | `/api/v1/audit/events/list` |

### Supported Providers

| Provider | Description | Use Case |
|----------|-------------|----------|
| `logging` | Logs audit events to application logs | Development, testing |

### Best Practices

1. **Enable in Production**: Always enable audit logging in production deployments
2. **Monitor Audit Events**: Monitor audit events for security incidents
4. **Secure Audit Logs**: Protect audit logs from unauthorized access
5. **Regular Backup**: Regularly backup audit logs for compliance

---

## Best Practices

### 1. Enable Only Needed Capabilities

Only enable the capabilities that your role actually needs:

```yaml
# Good: Enable only needed capabilities
capabilities:
  oauth2-server:
    enabled: true
  # Other capabilities remain disabled
```

```yaml
# Bad: Enable all capabilities unnecessarily
capabilities:
  oauth2-server:
    enabled: true
  oauth2-client:
    enabled: true  # Not needed for authorization server
  workload-identity:
    enabled: true
  # ...
```

### 2. Use Role-Specific Overrides

Override capability configuration at the role level:

```yaml
capabilities:
  oauth2-server:
    enabled: true
    token:
      access-token-expiry: 3600
roles:
  authorization-server:
    enabled: true
    capabilities:
      - oauth2-server
    config:
      oauth2-server:
        token:
          access-token-expiry: 7200  # Role-specific override
```

### 3. Secure Sensitive Configuration

Use environment variables for sensitive configuration:

```yaml
capabilities:
  oauth2-client:
    client-id: ${CLIENT_ID}
    client-secret: ${CLIENT_SECRET}
```

### 4. Document Custom Configuration

Add comments when overriding defaults:

```yaml
capabilities:
  oauth2-server:
    token:
      # Extended token lifetime for mobile clients
      access-token-expiry: 7200
```

### 5. Test Capability Configuration

Test your configuration before deploying:

```bash
# Test OAuth 2.0 endpoints
curl http://localhost:8085/oauth2/authorize

# Test workload identity endpoints
curl http://localhost:8082/api/v1/workloads/token/issue

# Test audit endpoints
curl http://localhost:8085/api/v1/audit/events
```

---

## Troubleshooting

### Common Issues

#### 1. Capability Not Enabled

**Symptoms**: Capability features are not available

**Solutions**:
- Verify the capability is enabled in `capabilities.<capability-name>.enabled`
- Check if the capability is listed in the role's `capabilities` array
- Ensure required infrastructure (trust domain, keys) is configured

#### 2. Endpoint Not Found

**Symptoms**: 404 errors when calling capability endpoints

**Solutions**:
- Verify the endpoint path is correct
- Check if the capability is enabled
- Ensure the service is running
- Review the endpoint configuration

#### 3. Authentication Fails

**Symptoms**: Token verification fails

**Solutions**:
- Verify OAuth 2.0 client credentials are correct
- Check if the authorization server is accessible
- Ensure JWKS endpoint is configured correctly
- Review token expiration settings

### Debug Logging

Enable debug logging for capabilities:

```yaml
logging:
  level:
    com.alibaba.openagentauth.core.capabilities: DEBUG
    com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities: DEBUG
```

---

## Next Steps

- **[Roles Configuration Guide](03-roles-configuration.md)**: Learn how to compose roles from capabilities
- **[Infrastructure Configuration Guide](01-infrastructure-configuration.md)**: Configure trust domain, keys, and JWKS

---

## Additional Resources

- **[Configuration Overview](00-configuration-overview.md)**: Introduction to configuration architecture
- **[OAuth 2.0 Specification](https://oauth.net/2/)**: OAuth 2.0 protocol specification
- **[OpenID Connect Specification](https://openid.net/connect/)**: OpenID Connect specification
