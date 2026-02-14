## Implementation Details

### Core Components

The MCP adapter functionality is implemented in the `open-agent-auth-mcp-adapter` module, which provides the integration layer between MCP protocol handling and the Open Agent Auth framework. The module contains two main classes: `OpenAgentAuthMcpServer` and `McpAuthInterceptor`.

The `OpenAgentAuthMcpServer` class implements the server-side integration, wrapping MCP server implementations and adding security capabilities. The class is designed to be framework-agnostic, working with any standard MCP server implementation that follows the JSON-RPC 2.0 specification. The server maintains references to the ResourceServer for authorization decisions and an audit logger for recording tool invocation events.

The `McpAuthInterceptor` class implements the request interception logic, extracting authentication credentials from HTTP headers and preparing verification requests. The class is responsible for header parsing, format validation, and ResourceRequest construction. It also handles error response generation, ensuring that clients receive clear, actionable error messages when verification fails.

The module includes comprehensive test coverage for all components, including unit tests for individual classes and integration tests for end-to-end flows. These tests validate correct behavior for various scenarios including successful invocations, verification failures, malformed requests, and error conditions.

### Spring Boot Integration

The MCP adapter provides Spring Boot autoconfiguration for seamless integration with Spring-based applications. The autoconfiguration is activated when the `open-agent-auth.mcp.enabled` property is set to true, creating an `OpenAgentAuthMcpServer` bean that can be injected into MCP server implementations.

The autoconfiguration requires a ResourceServer bean to be available, which is typically provided by the `ResourceServerAutoConfiguration` when `open-agent-auth.role` is set to `resource-server`. This ensures that the MCP adapter has access to the five-layer verification capabilities without requiring manual configuration.

Configuration properties for the MCP adapter are defined in the `McpAdapterProperties` class, which supports configuration of header names, error handling behavior, and logging options. These properties can be configured through YAML or properties files, providing flexibility for different deployment scenarios.

The framework provides sample implementations demonstrating how to integrate the MCP adapter with existing MCP servers. The sample resource server includes a `ShoppingMcpServerConfig` class that configures an MCP server with shopping-related tools and integrates it with the OpenAgentAuthMcpServer for security.

### Tool Security Metadata

The framework supports extending tool metadata with security-related information that helps agents understand authorization requirements. This metadata can be added during tool registration and included in the `tools/list` response.

Security metadata includes the required scopes field, which lists the OAuth 2.0 scopes that must be present in the Agent OA Token for the tool to be invoked. The sensitivity level field indicates the sensitivity of the tool's operations, with values such as public, internal, confidential, or restricted. The policy identifier field references the specific OPA policy that should be evaluated for this tool, enabling fine-grained policy selection.

Agents can use this metadata to guide their authorization flow. Before invoking a tool, the agent can check the required scopes and ensure that the Agent OA Token includes these scopes. The agent can also consider the sensitivity level when presenting authorization requests to users, providing more context for sensitive operations.

The framework also supports dynamic policy selection, where different policies can be applied based on the tool's input parameters. For example, a data access tool might use different policies based on the data type or access level requested. This dynamic selection enables more nuanced access control without requiring multiple tool definitions.

