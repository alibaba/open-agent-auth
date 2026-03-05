# Admin Dashboard Guide

## Introduction

Open Agent Auth provides a built-in Admin Dashboard — a web-based management console for monitoring and managing the authorization framework's runtime state. The dashboard dynamically detects which capabilities are available in your application and presents the relevant management pages accordingly.

The Admin Dashboard is **disabled by default** following the principle of least privilege. It must be explicitly enabled by the application operator and supports fine-grained access control to restrict who can access the admin pages.

## Enabling the Admin Dashboard

To enable the Admin Dashboard, add the following configuration to your `application.yml`:

```yaml
open-agent-auth:
  admin:
    enabled: true
```

Once enabled, the dashboard is accessible at `/admin` by default.

> **Security Warning**: Enabling the admin dashboard without access control exposes management endpoints to all users. Always configure access control in production environments.

## Access Control

The Admin Dashboard provides a session-based access control mechanism that integrates with the framework's existing user authentication flow. When access control is enabled, only authenticated users whose session subject matches one of the configured allowed subjects can access admin pages.

### Configuration

```yaml
open-agent-auth:
  admin:
    enabled: true
    access-control:
      enabled: true                    # Enable access control (default: true)
      allowed-session-subjects:        # Allowlist of user subjects
        - admin
        - operator
```

### Security Model

The access control follows a **fail-closed** design:

- **Access control disabled** (`enabled: false`): All requests are allowed without authentication. Not recommended for production.
- **Access control enabled, no subjects configured**: All requests are denied. This prevents accidental exposure when access control is enabled but not yet configured.
- **Access control enabled with subjects**: Only authenticated users whose subject matches the allowlist are granted access.

The interceptor chain enforces two layers of security in order:

1. **User Authentication**: Verifies the user has an active authenticated session. If no session exists, the user is redirected to the configured User IDP for OAuth 2.0 login.
2. **Admin Authorization**: Checks the authenticated user's subject against the `allowed-session-subjects` allowlist.

### Authentication Resolution

The admin authentication interceptor is resolved automatically based on your application's configuration:

1. **Existing interceptor**: If your application already has a `UserAuthenticationInterceptor` bean (e.g., from Agent or Authorization Server role configurations), it is reused for admin authentication.
2. **Fallback interceptor**: If no authentication bean exists (e.g., for Agent IDP roles), the framework creates a fallback interceptor by discovering a User IDP peer service (`agent-user-idp` or `as-user-idp`) from the JWKS consumer configuration. This enables roles without built-in user authentication to delegate admin login to an external User IDP.

If neither option is available, admin pages will not require user login, and a warning is logged.

## Dashboard Pages

The Admin Dashboard consists of a main dashboard page with a left sidebar navigation and a content area. The navigation menu is built dynamically at runtime based on which capability beans are registered in the Spring application context.

### Dashboard Overview (`/admin`)

The main dashboard page provides a unified navigation view. It detects available capabilities and renders the sidebar accordingly. Each sub-page is loaded in an iframe for seamless navigation without full page reloads.

### Binding Instances (`/admin/bindings`)

**Available when**: `BindingInstanceStore` bean is present in the application context.

Provides a web-based management interface for viewing, creating, and deleting binding instances. Binding instances represent the associations between users, agents, and authorization policies that govern how agents operate on behalf of users.

### Policy Registry (`/admin/policies`)

**Available when**: `PolicyRegistry` bean is present in the application context.

Provides a management interface for viewing, registering, and deleting authorization policies. Policies define the rules that govern agent operations, supporting multiple policy engines including OPA (Rego), RAM, ACL, and Scope-based policies.

### Audit Events (`/admin/audit`)

**Available when**: `AuditService` bean is present in the application context.

Provides a read-only interface for viewing and searching audit trail events. Audit events capture the complete context of agent operations, from user input to resource access, using W3C Verifiable Credentials for tamper-evident recording.

### Workload Identity (`/admin/workloads`)

**Available when**: `WorkloadRegistry` bean is present in the application context.

Provides a management interface for viewing workload identities, issuing Workload Identity Tokens (WIT), and revoking workloads. This page operates in one of two modes depending on the application's role:

- **Read-Write mode**: When `AgentIdentityProvider` is present (Agent IDP role), the page provides full management capabilities including issuing and revoking workload identities.
- **Read-Only mode**: When only `WorkloadRegistry` is present (Agent role with `RemoteWorkloadRegistry`), the page displays workload information without modification capabilities.

## Customizing Endpoint Paths

All admin endpoint paths are configurable through the `endpoints` property:

```yaml
open-agent-auth:
  admin:
    enabled: true
    endpoints:
      dashboard: /admin                # Main dashboard page
      workloads: /admin/workloads      # Workload identity management
      bindings: /admin/bindings        # Binding instance management
      policies: /admin/policies        # Policy registry management
      audit: /admin/audit              # Audit event viewer
```

This is useful when you need to avoid path conflicts with existing application routes or when integrating behind a reverse proxy with specific path requirements.

## Complete Configuration Reference

Below is the complete configuration with all available options and their default values:

```yaml
open-agent-auth:
  admin:
    # Whether the admin console is enabled (default: false)
    enabled: false

    # Access control configuration
    access-control:
      # Whether access control is enabled (default: true)
      enabled: true
      # List of user subjects allowed to access admin pages
      allowed-session-subjects: []

    # Endpoint path configuration
    endpoints:
      dashboard: /admin
      workloads: /admin/workloads
      bindings: /admin/bindings
      policies: /admin/policies
      audit: /admin/audit
```

## Architecture

### Auto-Configuration

The Admin Dashboard is powered by `AdminAutoConfiguration`, which is activated only when `open-agent-auth.admin.enabled=true`. This auto-configuration:

1. Registers the `AdminAccessInterceptor` for access control enforcement on all admin paths.
2. Resolves or creates a `UserAuthenticationInterceptor` for admin page authentication.
3. Provides fallback OAuth2 callback beans for roles that do not have their own `OAuth2CallbackService` (e.g., Agent IDP), enabling the OAuth2 login flow for admin authentication.

### Controller Activation

Each admin controller is conditionally activated based on two criteria:

| Controller | Condition Property | Required Bean |
|---|---|---|
| `AdminDashboardController` | `open-agent-auth.admin.enabled=true` | None (always active when admin is enabled) |
| `BindingInstanceAdminController` | `open-agent-auth.admin.enabled=true` | `BindingInstanceStore` |
| `PolicyRegistryAdminController` | `open-agent-auth.admin.enabled=true` | `PolicyRegistry` |
| `AuditAdminController` | `open-agent-auth.admin.enabled=true` | `AuditService` |
| `WorkloadAdminController` | `open-agent-auth.admin.enabled=true` | `WorkloadRegistry` |

This design ensures that only relevant management pages are exposed based on the capabilities actually configured in your application.

### Interceptor Chain

The request processing pipeline for admin endpoints follows this order:

```
Request → UserAuthenticationInterceptor → AdminAccessInterceptor → Controller
```

1. **UserAuthenticationInterceptor**: Ensures the user has an active authenticated session. Redirects to the User IDP for login if not authenticated.
2. **AdminAccessInterceptor**: Validates the authenticated user's subject against the configured allowlist. Returns HTTP 403 if the user is not authorized.

## Troubleshooting

### Admin pages return 403 Forbidden

**Symptom**: After logging in, admin pages return "Access Denied: Insufficient privileges".

**Cause**: The authenticated user's subject is not in the `allowed-session-subjects` list.

**Solution**: Add the user's subject to the allowlist:

```yaml
open-agent-auth:
  admin:
    access-control:
      allowed-session-subjects:
        - your-username
```

### Admin pages redirect to login but login fails

**Symptom**: Accessing `/admin` redirects to a login page, but the login flow fails or loops.

**Cause**: No User IDP peer is configured for the admin authentication fallback.

**Solution**: Ensure a User IDP peer is configured in your JWKS consumers and that the OAuth2 client credentials are set:

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      client-id: your-client-id
      client-secret: your-client-secret
  peers:
    agent-user-idp:
      issuer: https://your-user-idp.example.com
```

### Some admin pages are missing

**Symptom**: The dashboard sidebar does not show all expected navigation items.

**Cause**: The corresponding capability beans are not registered in the application context. Each admin page requires its associated service bean to be present.

**Solution**: Verify that the required capabilities are enabled in your configuration. For example, to see the Audit Events page, ensure `AuditService` is configured. Check the [Controller Activation](#controller-activation) table for the complete mapping.

### Warning: "Admin pages will not require user login"

**Symptom**: Log message warns that admin pages will not require user login.

**Cause**: No `UserAuthenticationInterceptor` bean is available and no User IDP peer is configured.

**Solution**: Either configure a role that provides user authentication (e.g., Agent, Authorization Server) or configure a User IDP peer for the fallback authentication mechanism.
