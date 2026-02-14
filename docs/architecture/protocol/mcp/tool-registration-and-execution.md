## Error Handling and Response

### Validation Error Responses

When tool invocation requests fail verification, the OpenAgentAuthMcpServer returns structured error responses that help agents understand and potentially correct the issue. Error responses follow the JSON-RPC 2.0 error format, including an error code, message, and optional data field with additional details.

The error codes are organized by verification layer, enabling agents to quickly identify which security check failed. Layer 1 errors (error codes 1000-1099) indicate WIT validation failures, such as invalid signature, expired token, or untrusted issuer. Layer 2 errors (error codes 1100-1199) indicate WPT validation failures, such as invalid signature or timestamp mismatch. Layer 3 errors (error codes 1200-1299) indicate Agent OA Token validation failures, such as invalid signature, expired token, or insufficient scope. Layer 4 errors (error codes 1300-1399) indicate identity consistency failures, where the user and workload identities don't match as expected. Layer 5 errors (error codes 1400-1499) indicate policy evaluation failures, where the OPA policy denies access.

The error message provides a human-readable description of the failure, helping developers diagnose issues during integration and testing. The data field includes additional details such as the specific claim that failed validation, the expected value, and the actual value received. This detailed information enables agents to provide meaningful feedback to users and potentially retry the request with corrected credentials.

### Retry and Recovery

The framework supports retry mechanisms for certain types of failures, particularly transient failures such as network timeouts or temporary service unavailability. Agents can implement exponential backoff retry logic for these scenarios, gradually increasing the delay between retries to avoid overwhelming the server.

However, for security-related failures such as invalid credentials, insufficient permissions, or policy denials, retry is unlikely to succeed without corrective action. In these cases, the error response should guide the user or agent to take appropriate action, such as re-authenticating, obtaining additional authorization, or modifying the request parameters.

The framework also supports token refresh mechanisms, where agents can obtain new Agent OA Tokens using refresh tokens when the current token expires. This enables long-running agent sessions without requiring repeated user authentication, while still maintaining security through time-limited access tokens.

