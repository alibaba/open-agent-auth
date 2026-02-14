/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.framework.executor;

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.response.RequestAuthUrlResponse;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.role.ApplicationRole;

/**
 * Executor for Agent Operation Authorization Protocol (AOA) flow.
 * <p>
 * This interface defines the contract for executing the Agent Operation Authorization
 * Protocol (AOA) flow, which enables AI agents to obtain authorization to perform
 * operations on behalf of users. The executor manages the complete authorization
 * lifecycle from user authentication to context preparation and cleanup.
 * </p>
 *
 * <h3>Protocol Flow:</h3>
 * <ol>
 *   <li>Initiate user authentication with {@link #initiateUserAuth(InitiateAuthorizationRequest)}</li>
 *   <li>Exchange authorization code for ID Token with {@link #exchangeUserIdToken(ExchangeCodeForTokenRequest)}</li>
 *   <li>Request authorization URL with {@link #requestAuthUrl(RequestAuthUrlRequest)}</li>
 *   <li>Exchange authorization code for Agent OA Token with {@link #exchangeAgentAuthToken(AuthorizationResponse)}</li>
 *   <li>Build authorization context with {@link #buildAuthContext(PrepareAuthorizationContextRequest)}</li>
 *   <li>Cleanup resources with {@link #cleanup(WorkloadContext)}</li>
 * </ol>
 *
 * <h3>Usage Example:</h3>
 * <pre>
 * AgentAapExecutor executor = ...;
 *
 * // Step 1: Initiate user authentication
 * InitiateAuthorizationRequest authRequest = InitiateAuthorizationRequest.builder()
 *     .redirectUri("https://example.com/callback")
 *     .state("random-state-value")
 *     .build();
 * String authUrl = executor.initiateUserAuth(authRequest);
 *
 * // Step 2: Exchange authorization code for ID Token
 * ExchangeCodeForTokenRequest exchangeRequest = ExchangeCodeForTokenRequest.builder()
 *     .code("authorization-code-from-callback")
 *     .state("random-state-value")
 *     .build();
 * executor = executor.exchangeUserIdToken(exchangeRequest);
 *
 * // Step 3: Request authorization URL
 * WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
 *     .operationType("query")
 *     .resourceId("product-catalog")
 *     .build();
 * RequestAuthUrlRequest authUrlRequest = RequestAuthUrlRequest.builder()
 *     .userIdentityToken(idToken) // from Step 2
 *     .userOriginalInput("I want to buy winter clothes, please give me some suggestions")
 *     .workloadContext(workloadContext)
 *     .sessionId("random-state-value")
 *     .build();
 * String authUrl = executor.requestAuthUrl(authUrlRequest);
 *
 * // Step 4: Exchange authorization code for Agent OA Token
 * AuthorizationResponse authResponse = AuthorizationResponse.builder()
 *     .authorizationCode("authorization-code")
 *     .state("random-state-value")
 *     .build();
 * executor = executor.exchangeAgentAuthToken(authResponse);
 *
 * // Step 5: Build authorization context
 * PrepareAuthorizationContextRequest contextRequest = PrepareAuthorizationContextRequest.builder()
 *     .contextId("context-id")
 *     .build();
 * ToolAuthorizationContext authContext = executor.buildAuthContext(contextRequest);
 *
 * // Step 6: Cleanup
 * WorkloadContext workloadContext = executor.getWorkloadContext();
 * executor.cleanup(workloadContext);
 * </pre>
 *
 * <h3>Role-Specific Executors:</h3>
 * <p>
 * This interface is specifically for the Agent role. Other roles may have their
 * own executor implementations:
 * </p>
 * <ul>
 *   <li>{@link AgentAapExecutor} - Agent role executor (this interface)</li>
 *   <li>AgentIdpAapExecutor - Agent IDP role executor</li>
 *   <li>ResourceServerAapExecutor - Resource Server role executor</li>
 * </ul>
 *
 * @see Agent
 * @see ApplicationRole#AGENT
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-liu-agent-operation-authorization">Agent Operation Authorization Protocol</a>
 * @since 1.0
 */
public interface AgentAapExecutor {

    /**
     * Initiates the user authentication flow by generating the authorization URL.
     * <p>
     * This method generates the authorization URL for the OIDC authorization code flow.
     * The frontend should redirect the user to this URL to start the authentication process.
     * </p>
     *
     * <h4>Authorization Flow:</h4>
     * <ol>
     *   <li>Frontend calls this method to get the authorization URL</li>
     *   <li>Frontend redirects user to the authorization URL</li>
     *   <li>User authenticates at Agent User IDP</li>
     *   <li>Agent User IDP returns authorization code via callback</li>
     *   <li>Frontend calls {@link #exchangeUserIdToken(ExchangeCodeForTokenRequest)} to exchange code for ID Token</li>
     * </ol>
     *
     * <h4>Parameters:</h4>
     * <ul>
     *   <li><b>redirectUri:</b> The callback URL where the authorization code will be sent</li>
     *   <li><b>state:</b> A random value to prevent CSRF attacks</li>
     * </ul>
     *
     * @param request the initiate authorization request containing redirectUri and state
     * @return the authorization URL to redirect the user to
     */
    String initiateUserAuth(InitiateAuthorizationRequest request);

    /**
     * Exchanges the authorization code for an ID Token.
     * <p>
     * This method completes the OIDC authorization code flow by exchanging the
     * authorization code for an ID Token. This is a backend-to-backend operation
     * that should be called by the Agent after receiving the authorization code.
     * </p>
     *
     * <h4>Token Exchange Flow:</h4>
     * <ol>
     *   <li>Agent receives authorization code from Agent User IDP callback</li>
     *   <li>Agent calls this method with the authorization code</li>
     *   <li>Executor exchanges code for ID Token with Agent User IDP</li>
     *   <li>Executor validates and stores the ID Token</li>
     *   <li>Executor returns updated instance for chaining</li>
     * </ol>
     *
     * <h4>Parameters:</h4>
     * <ul>
     *   <li><b>code:</b> The authorization code received from the callback</li>
     *   <li><b>state:</b> The state parameter for CSRF validation</li>
     * </ul>
     *
     * @param request the exchange code request containing code and state
     * @return the updated executor instance with ID Token
     */
    AgentAapExecutor exchangeUserIdToken(ExchangeCodeForTokenRequest request);

    /**
     * Requests the authorization redirect URL.
     * <p>
     * This method aggregates the complete authorization URL request flow, which internally
     * performs the following operations:
     * </p>
     * <ul>
     *   <li>Workload creation - creating a virtual workload for the user request</li>
     *   <li>WIT issuance - issuing a Workload Identity Token for the workload</li>
     *   <li>OAuth Client Registration - registering the OAuth client using WIMSE protocol</li>
     *   <li>PAR construction - building the Pushed Authorization Request with Prompt VC</li>
     *   <li>PAR submission - submitting the PAR to the Authorization Server</li>
     *   <li>Auth URL construction - building the final authorization redirect URL</li>
     * </ul>
     * <p>
     * The framework manages configuration that remains constant during the software lifecycle
     * (e.g., VC signing keys, Agent IDP endpoints, Authorization Server endpoints). Developers
     * only need to provide request-specific parameters.
     * </p>
     * <p>
     * For Prompt VC generation, developers only need to provide the {@code userOriginalInput}.
     * The framework will use the configured signing keys and issuer information to sign the VC.
     * </p>
     *
     * <h4>Authorization Flow:</h4>
     * <ol>
     *   <li>Caller provides user input and operation details</li>
     *   <li>Framework creates virtual workload and issues WIT</li>
     *   <li>Framework registers OAuth client using WIMSE protocol</li>
     *   <li>Framework generates Prompt VC from user input</li>
     *   <li>Framework constructs and submits PAR request</li>
     *   <li>Framework returns authorization redirect URL with request_uri</li>
     *   <li>Caller redirects user to the returned authorization URL</li>
     *   <li>User authenticates and authorizes at Authorization Server</li>
     *   <li>Authorization Server redirects back to callback URL</li>
     * </ol>
     *
     * <h4>Parameters:</h4>
     * <ul>
     *   <li><b>userIdentityToken:</b> The user's ID Token from Agent User IDP (REQUIRED)</li>
     *   <li><b>userOriginalInput:</b> The user's original natural language input (REQUIRED)</li>
     *   <li><b>operationType:</b> The operation type for the workload (REQUIRED)</li>
     *   <li><b>resourceId:</b> The resource identifier (OPTIONAL but recommended)</li>
     *   <li><b>metadata:</b> Additional metadata for policy evaluation (OPTIONAL)</li>
     *   <li><b>clientName:</b> The client name for OAuth registration (OPTIONAL)</li>
     *   <li><b>expirationSeconds:</b> PAR-JWT expiration time (OPTIONAL, default: 3600)</li>
     *   <li><b>state:</b> CSRF protection state parameter (OPTIONAL)</li>
     * </ul>
     *
     * @param request the authorization URL request containing all necessary parameters
     * @return the authorization response containing redirect URL, request URI, state, and workload context
     */
    RequestAuthUrlResponse requestAuthUrl(RequestAuthUrlRequest request);

    /**
     * Exchanges the authorization code for an Agent Operation Authorization Token (AOAT).
     * <p>
     * This method processes the authorization callback, exchanging the authorization code
     * for an Agent Operation Authorization Token (AOAT). This is the final step in the
     * OAuth 2.0 authorization flow with PAR extension.
     * </p>
     *
     * <h4>Token Exchange Flow:</h4>
     * <ol>
     *   <li>Validate the authorization response</li>
     *   <li>Exchange authorization code for AOAT</li>
     *   <li>Store AOAT in the executor context</li>
     *   <li>Return updated executor instance for chaining</li>
     * </ol>
     *
     * <h4>Parameters:</h4>
     * <ul>
     *   <li><b>code:</b> The authorization code from the callback</li>
     *   <li><b>state:</b> The state parameter for CSRF validation</li>
     * </ul>
     *
     * @param response the authorization response containing the authorization code
     * @return the updated executor instance with Agent OA Token
     */
    AgentOperationAuthToken exchangeAgentAuthToken(AuthorizationResponse response);

    /**
     * Builds the authorization context for tool execution.
     * <p>
     * This method generates the necessary authorization context (WIT, WPT, AOAT)
     * for tool execution, but does not execute the tool itself. Protocol-specific
     * adapters (MCP, FC, API, etc.) should use this context to inject credentials
     * into their respective transport layers.
     * </p>
     *
     * <h4>Context Components:</h4>
     * <ul>
     *   <li><b>WIT:</b> Workload Identity Token - identifies and authenticates the workload</li>
     *   <li><b>WPT:</b> Workload Proof Token - proves the integrity and authenticity of the request</li>
     *   <li><b>AOAT:</b> Agent Operation Authorization Token - contains user identity and operation authorization</li>
     * </ul>
     *
     * <h4>Usage Example:</h4>
     * <pre>
     * PrepareAuthorizationContextRequest contextRequest = PrepareAuthorizationContextRequest.builder()
     *     .contextId("context-id")
     *     .build();
     * ToolAuthorizationContext authContext = executor.buildAuthContext(contextRequest);
     *
     * // MCP Protocol Adapter
     * McpAsyncHttpClientRequestCustomizer customizer = (builder, method, uri, body, ctx) -> {
     *     builder.header("Authorization", "Bearer " + contextContext.getAoat());
     *     builder.header("X-Workload-Identity", contextContext.getWit());
     *     builder.header("X-Workload-Proof", contextContext.getWpt());
     *     return Mono.just(builder);
     * };
     * </pre>
     *
     * @param contextRequest the prepare authorization context request containing contextId
     * @return the authorization context containing WIT, WPT, and AOAT
     */
    AgentAuthorizationContext buildAuthContext(PrepareAuthorizationContextRequest contextRequest);

    /**
     * Gets the workload context for cleanup.
     * <p>
     * This method returns the workload context that should be used for cleanup
     * after tool execution completes. The workload context contains the workload
     * identity and key pair information that needs to be revoked and cleared.
     * </p>
     *
     * @return the workload context
     */
    WorkloadContext getWorkloadContext();

    /**
     * Cleans up the authorization context after operation completion.
     * <p>
     * This method should be called after an operation completes to clean up
     * the workload, revoke tokens, and clear sensitive data. This is a critical
     * step for maintaining security and preventing resource leaks.
     * </p>
     *
     * <h4>Cleanup Operations:</h4>
     * <ul>
     *   <li>Revoke the workload identity</li>
     *   <li>Clear temporary key pairs</li>
     *   <li>Remove cached tokens</li>
     *   <li>Clear sensitive data from memory</li>
     * </ul>
     *
     * <h4>Best Practices:</h4>
     * <ul>
     *   <li>Always call this method after tool execution completes</li>
     *   <li>Call this method in a finally block to ensure cleanup even on errors</li>
     *   <li>Do not reuse the executor after cleanup</li>
     * </ul>
     *
     * @param workloadContext the workload context to clean up
     */
    void cleanup(WorkloadContext workloadContext);

}