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
package com.alibaba.openagentauth.framework.actor;

import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkAuthorizationContextException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.ParSubmissionRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.role.ApplicationRole;

/**
 * Agent actor interface.
 * <p>
 * This interface defines the contract for AI Agent actor implementations, which represent
 * users and execute operations on their behalf. The Agent actor is an independent entity
 * that manages its own state, behavior, and lifecycle, following the Actor model pattern.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>User Authentication:</b> Authenticate users and obtain ID Tokens</li>
 *   <li><b>Workload Management:</b> Create virtual workloads for each request</li>
 *   <li><b>Authorization Coordination:</b> Manage the authorization flow via AOA Bridge</li>
 *   <li><b>Token Management:</b> Cache and manage WIT and AOAT tokens</li>
 *   <li><b>Authorization Context Preparation:</b> Prepare authorization context for tool execution</li>
 *   <li><b>Prompt Security:</b> Implement prompt encryption and redaction</li>
 * </ul>
 *
 * <h3>Complete Workflow:</h3>
 * <p>
 * The Agent authorization flow consists of six phases:
 * </p>
 * <ol>
 *   <li><b>Phase 1 - User Authentication:</b> OIDC authorization code flow via Agent User IDP</li>
 *   <li><b>Phase 2 - Workload Creation:</b> Create virtual workload and issue WIT via Agent IDP</li>
 *   <li><b>Phase 3 - OAuth Client Registration:</b> DCR using WIT as client_assertion</li>
 *   <li><b>Phase 4 - Authorization Request:</b> PAR flow to submit operation proposal</li>
 *   <li><b>Phase 5 - User Authorization:</b> OAuth 2.0 user consent flow</li>
 *   <li><b>Phase 6 - Token Exchange & Tool Execution:</b> Exchange code for AOAT, prepare context</li>
 * </ol>
 * <p>
 * For detailed sequence diagrams and system interactions for each phase, see
 * {@code docs/architecture/protocol/agent-authorization-flow.md}.
 * </p>
 *
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Step 1: User Authentication
 * AuthenticationResponse authResponse = agentActor.authenticateUser(credentials);
 * String userId = authResponse.getUserId();
 *
 * // Step 2: Create Virtual Workload and Issue WIT
 * AgentRequestContext context = new AgentRequestContext(...);
 * WorkloadContext workloadContext = agentActor.issueWorkloadIdentityToken(IssueWitRequest.builder()
 *     .userIdentityToken(idToken)
 *     .context(context)
 *     .build());
 *
 * // Step 3: Register OAuth Client (DCR)
 * DcrResponse dcrResponse = agentActor.registerOAuthClient(workloadContext);
 *
 * // Step 4: Submit PAR Request
 * String operationProposal = "{\n" +
 *     "  \"action\": \"query_products\",\n" +
 *     "  \"resource\": \"shopping\"\n" +
 *     "}";
 * Object evidence = promptVc; // Prompt VC with user input
 * ParResponse parResponse = agentActor.submitParRequest(workloadContext, operationProposal, evidence);
 *
 * // Step 5: Generate Authorization URL (Frontend Redirect)
 * String authUrl = agentActor.generateAuthorizationUrl(parResponse.getRequestUri());
 * // Frontend: window.location.href = authUrl;
 *
 * // Step 6: Handle Authorization Callback (in callback endpoint)
 * @GetMapping("/callback")
 * public ResponseEntity<?> handleCallback(@RequestParam("code") String code) {
 *     AuthorizationResponse authResponse = new AuthorizationResponse(code);
 *     AgentOperationAuthToken aoat = agentActor.handleAuthorizationCallback(authResponse);
 *
 *     // Step 7: Prepare Authorization Context
 *     ToolAuthorizationContext context = agentActor.prepareAuthorizationContext(workloadContext, aoat);
 *
 *     // Step 8: Execute Tool via Protocol Adapter
 *     // MCP Protocol Adapter
 *     McpAsyncHttpClientRequestCustomizer customizer = (builder, method, uri, body, ctx) -> {
 *         builder.header("Authorization", "Bearer " + context.getAoat());
 *         builder.header("X-Workload-Identity", context.getWit());
 *         builder.header("X-Workload-Proof", context.getWpt());
 *         return Mono.just(builder);
 *     };
 *
 *     // Step 9: Cleanup
 *     agentActor.clearAuthorizationContext(workloadContext);
 *
 *     return ResponseEntity.ok(result);
 * }
 * }</pre>
 *
 * @see ApplicationRole#AGENT
 * @see FrameworkOAuth2TokenClient
 * @since 1.0
 */
public interface Agent extends FrameworkOAuth2TokenClient {
    
    /**
     * Initiates the OIDC authorization flow by generating the authorization URL.
     * <p>
     * This method generates the authorization URL for the OIDC authorization code flow.
     * The frontend should redirect the user to this URL to start the authentication process.
     * </p>
     * 
     * <p>
     * <b>Authorization Flow:</b>
     * <ol>
     *   <li>Frontend calls this method to get the authorization URL</li>
     *   <li>Frontend redirects user to the authorization URL</li>
     *   <li>User authenticates at Agent User IDP</li>
     *   <li>Agent User IDP returns authorization code via callback</li>
     *   <li>Frontend calls {@link #exchangeCodeForToken(ExchangeCodeForTokenRequest)} to exchange code for ID Token</li>
     * </ol>
     * </p>
     *
     * @param request the initiate authorization request containing redirectUri and state
     * @return the authorization URL
     */
    String initiateAuthorization(InitiateAuthorizationRequest request);
    
    /**
     * Issues a Workload Identity Token (WIT) based on the provided request.
     * <p>
     * This method implements the WIMSE protocol for issuing Workload Identity Tokens,
     * which are used to establish the identity of workloads (agents) in the system.
     * The token issuance process validates the agent-user binding proposal and
     * operation context to ensure proper authorization.
     * </p>
     * <p>
     * According to draft-ietf-wimse-workload-creds, this method:
     * </p>
     * <ul>
     *   <li>Validates the agent-user binding proposal (user identity token and agent workload token)</li>
     *   <li>Evaluates the operation request context for policy compliance</li>
     *   <li>Establishes a secure identity binding between user and agent</li>
     *   <li>Returns a workload context containing the issued WIT and associated credentials</li>
     * </ul>
     * <p>
     * <b>Workflow:</b>
     * <ol>
     *   <li>Validate the operation request context and agent-user binding proposal</li>
     *   <li>Extract and validate user identity from the user identity token</li>
     *   <li>Validate the existing agent workload token</li>
     *   <li>Create or update the workload identity binding</li>
     *   <li>Issue a new WIT with the established identity binding</li>
     *   <li>Return the workload context with the issued WIT and credentials</li>
     * </ol>
     * </p>
     *
     * @param request the issue WIT request containing operation context and agent-user binding proposal
     * @return the workload context containing the issued WIT and associated credentials
     * @throws WorkloadCreationException if WIT issuance fails
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
     * @since 1.0
     */
    WorkloadContext issueWorkloadIdentityToken(IssueWitRequest request) throws WorkloadCreationException;
    
    /**
     * Registers an OAuth client with the Authorization Server using Dynamic Client Registration (DCR).
     * <p>
     * This method performs OAuth 2.0 Dynamic Client Registration (RFC 7591) using the workload's
     * WIT as the client assertion. The WIT's subject (WIT.sub) becomes the OAuth client_id, and
     * the authentication method is set to private_key_jwt.
     * </p>
     * 
     * <p>
     * This step establishes the mapping between the workload identity and OAuth client identity,
     * which is required before submitting PAR requests. The Authorization Server validates the
     * WIT signature and returns client registration information.
     * </p>
     *
     * @param workloadContext the workload context containing the WIT for client assertion
     * @return a new WorkloadContext with the DCR-assigned oauthClientId populated
     * @throws FrameworkAuthorizationException if client registration fails
     */
    WorkloadContext registerOAuthClient(WorkloadContext workloadContext) throws FrameworkAuthorizationException;
    
    /**
     * Submits a PAR (Pushed Authorization Request) to the Authorization Server.
     * <p>
     * This method builds the PAR-JWT containing the operation proposal and evidence,
     * signs it with the workload's private key, and submits it to the Authorization Server's
     * PAR endpoint. The Authorization Server validates the request and returns a request_uri
     * that can be used in the authorization redirect.
     * </p>
     * 
     * <p>
     * This is the first step in the OAuth 2.0 authorization flow with PAR extension.
     * After receiving the request_uri, the caller should redirect the user to the
     * authorization endpoint using {@link #generateAuthorizationUrl(String)}.
     * </p>
     *
     * @param request the PAR submission request containing all required parameters
     * @return the PAR response containing the request_uri
     * @throws FrameworkAuthorizationException if PAR submission fails
     */
    ParResponse submitParRequest(ParSubmissionRequest request) throws FrameworkAuthorizationException;
    
    /**
     * Generates the authorization redirect URL.
     * <p>
     * This method constructs the authorization endpoint URL with the request_uri parameter.
     * The caller should redirect the user to this URL to initiate the authorization flow.
     * </p>
     * 
     * <p>
     * This is the second step in the OAuth 2.0 authorization flow. The user will be
     * redirected to the Authorization Server, where they will authenticate and authorize
     * the operation.
     * </p>
     *
     * @param requestUri the request_uri from the PAR response
     * @return the authorization redirect URL
     */
    String generateAuthorizationUrl(String requestUri);
    
    /**
     * Generates the authorization redirect URL with state parameter.
     * <p>
     * This method constructs the authorization endpoint URL with the request_uri and state parameters.
     * The state parameter can be used to maintain session context across the OAuth flow.
     * </p>
     * 
     * <p>
     * This is the second step in the OAuth 2.0 authorization flow with state support.
     * The state parameter is recommended for CSRF protection and session restoration.
     * </p>
     *
     * @param requestUri the request_uri from the PAR response
     * @param state the state parameter for CSRF protection and session restoration
     * @return the authorization redirect URL
     */
    String generateAuthorizationUrl(String requestUri, String state);
    
    /**
     * Handles the authorization callback from the Authorization Server.
     * <p>
     * This method processes the authorization callback, exchanging the authorization code
     * for an Agent Operation Authorization Token (AOAT). This is the final step in the
     * OAuth 2.0 authorization flow.
     * </p>
     * 
     * <p>
     * This method should be called in the callback endpoint that receives the authorization
     * code from the Authorization Server after the user has authorized the operation.
     * </p>
     *
     * @param response the authorization response containing the authorization code
     * @return the Agent Operation Authorization Token
     * @throws FrameworkAuthorizationException if callback processing fails
     */
    AgentOperationAuthToken handleAuthorizationCallback(AuthorizationResponse response) throws FrameworkAuthorizationException;
    
    /**
     * Prepares the authorization context for tool execution.
     * <p>
     * This method generates the necessary authorization context (WIT, WPT, AOAT)
     * for tool execution, but does not execute the tool itself. Protocol-specific
     * adapters (MCP, FC, API, etc.) should use this context to inject credentials
     * into their respective transport layers.
     * </p>
     *
     * <h4>Usage Example:</h4>
     * <pre>
     * // Prepare authorization context
     * PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
     *     .workloadContext(workloadContext)
     *     .aoat(aoat)
     *     .build();
     * ToolAuthorizationContext context = agentActor.prepareAuthorizationContext(request);
     *
     * // MCP Protocol Adapter
     * McpAsyncHttpClientRequestCustomizer customizer = (builder, method, uri, body, ctx) -> {
     *     builder.header("Authorization", "Bearer " + context.getAoat());
     *     builder.header("X-Workload-Identity", context.getWit());
     *     builder.header("X-Workload-Proof", context.getWpt());
     *     return Mono.just(builder);
     * };
     * </pre>
     *
     * @param request the prepare authorization context request containing workloadContext and aoat
     * @return the authorization context containing WIT, WPT, and AOAT
     * @throws FrameworkAuthorizationContextException if context preparation fails
     */
    AgentAuthorizationContext prepareAuthorizationContext(PrepareAuthorizationContextRequest request) throws FrameworkAuthorizationContextException;
    
    /**
     * Clears the authorization context after operation completion.
     * <p>
     * This method should be called after an operation completes to clean up
     * the workload, revoke tokens, and clear sensitive data.
     * </p>
     *
     * @param workloadContext the workload context to clear
     */
    void clearAuthorizationContext(WorkloadContext workloadContext);

}