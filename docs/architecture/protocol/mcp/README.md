# MCP Protocol Adapter

This directory contains documentation about the Model Context Protocol (MCP) adapter architecture in the Open Agent Auth framework.

## Overview

The Model Context Protocol (MCP) adapter layer provides seamless integration between the Open Agent Auth framework's security capabilities and the MCP protocol, enabling AI agents to securely access tools and resources while maintaining comprehensive authorization and auditability.

## Documentation

- [Overview](overview.md) - MCP adapter architecture overview and introduction
- [MCP Protocol Fundamentals](mcp-protocol-fundamentals.md) - MCP protocol architecture and security requirements
- [OpenAgentAuthMcpServer Design](openagentauth-mcserver-design.md) - Server architecture, authentication interceptor, and resource server integration
- [Tool Registration and Execution](tool-registration-and-execution.md) - Tool registration process and invocation flow
- [Error Handling and Response](error-handling-and-response.md) - Validation error responses and retry mechanisms
- [Implementation Details](implementation-details.md) - Core components, Spring Boot integration, and tool security metadata
- [Security and Performance](security-and-performance.md) - Header security, token security, audit logging, and performance considerations

## Key Features

- **Seamless Integration** - Transparent integration with standard MCP servers
- **Five-Layer Verification** - Comprehensive security validation for all tool invocations
- **Non-Invasive** - Works with existing MCP servers without modifications
- **Comprehensive Auditing** - Complete audit trail for all tool executions
- **Error Handling** - Structured error responses with detailed diagnostics
- **Spring Boot Support** - Autoconfiguration for easy integration

## Architecture

The MCP adapter follows the decorator pattern, wrapping standard MCP server implementations and adding security capabilities:

```
AI Agent
    ↓ (tools/call request)
OpenAgentAuthMcpServer
    ↓ (intercept)
McpAuthInterceptor
    ↓ (validateRequest)
ResourceServer
    ↓ (five-layer verification)
FiveLayerVerifier
    ↓ (authorization decision)
Tool Implementation
```

## Related Documentation

- [Token Reference](../../../token/README.md) - Learn about tokens used in MCP authentication
- [Authorization Flow](../../../authorization/README.md) - Understand the authorization process
- [Security and Audit](../../../security/README.md) - Security mechanisms and audit logging

---

**Document Version**: 2.0.0  
**Last Updated**: 2026-02-09  
**Maintainer**: Open Agent Auth Team
