## OpenAgentAuthMcpServer Design

### Server Architecture

The OpenAgentAuthMcpServer class serves as the primary integration point between MCP protocol handling and Agent Operation Authorization. It wraps standard MCP server implementations and intercepts all incoming requests to perform security validation before allowing tool execution. This design follows the decorator pattern, where the OpenAgentAuthMcpServer adds security capabilities to existing MCP servers without requiring modifications to their core functionality.

The server architecture consists of three main components: the authentication interceptor, the resource server orchestrator, and the audit logger. The authentication interceptor (McpAuthInterceptor) extracts authentication credentials from HTTP headers and performs initial validation. The resource server orchestrator executes the five-layer verification and makes authorization decisions. The audit logger records all tool invocation attempts and outcomes for compliance and security monitoring.

This separation of concerns enables independent evolution of each component. The authentication interceptor can be extended to support additional authentication methods or header formats without affecting the verification logic. The resource server orchestrator can be upgraded to new verification algorithms without changing the MCP protocol handling. The audit logger can be enhanced to support additional logging destinations or formats without impacting the core authorization flow.

### Authentication Interceptor

The McpAuthInterceptor is responsible for extracting authentication credentials from HTTP requests and preparing them for verification. It implements a non-invasive interception mechanism that works with standard HTTP-based MCP servers, requiring only that the client include specific headers in their requests.

The interceptor expects three authentication headers: the Authorization header containing the Agent OA Token in Bearer token format, the X-Workload-Identity header containing the WIT, and the X-Workload-Proof header containing the WPT. These headers are extracted and validated for presence and format before being passed to the resource server for comprehensive verification.

The interceptor constructs a ResourceRequest object containing all the information needed for verification, including the extracted tokens, HTTP method, URI, headers, and body. This request object is passed to the resource server's validateRequest method, which performs the five-layer verification and returns a ValidationResult indicating whether the request should be allowed.

The interceptor handles various error scenarios gracefully. If required headers are missing, it returns a clear error message indicating which header is missing. If token extraction fails due to malformed headers, it returns an appropriate error. If verification fails at any layer, it returns the error details from the verification result. This comprehensive error handling ensures that clients receive actionable feedback when their requests are rejected.

### Resource Server Integration

The OpenAgentAuthMcpServer integrates with the ResourceServer interface to leverage the framework's five-layer verification architecture. This integration is achieved through dependency injection, where the ResourceServer implementation is provided to the OpenAgentAuthMcpServer constructor and used for all authorization decisions.

The ResourceServer interface defines a single method, validateRequest, which takes a ResourceRequest object and returns a ValidationResult. The ValidationResult contains a boolean indicating whether the request is valid, a list of error messages if validation failed, and extracted identity and policy information if validation succeeded. This simple interface abstracts away the complexity of the five-layer verification, allowing the MCP adapter to focus on protocol-specific concerns.

The integration enables the MCP adapter to benefit from all the security capabilities of the ResourceServer, including WIT validation, WPT verification, Agent OA Token validation, identity consistency checking, and policy evaluation. This means that MCP tools automatically inherit the same strong security guarantees as other resource access mechanisms in the framework.

