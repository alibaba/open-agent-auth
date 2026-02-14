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
package com.alibaba.openagentauth.framework.executor.impl;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.vc.VcSigner;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.vc.chain.PromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.ParSubmissionRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.response.RequestAuthUrlResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.UUID;

/**
 * Default implementation of AgentAapExecutor.
 * <p>
 * This class orchestrates the complete authorization flow for agent operations,
 * following the Agent Operation Authorization Protocol (AOAP). It delegates
 * protocol-specific operations to the Agent interface while managing the overall
 * authorization workflow.
 * </p>
 * <p>
 * <b>Authorization Flow:</b></p>
 * <ol>
 *   <li>Create workload context from user identity</li>
 *   <li>Register OAuth client for the workload</li>
 *   <li>Build operation proposal with policy</li>
 *   <li>Submit PAR (Pushed Authorization Request) to authorization server</li>
 *   <li>Generate authorization URL with PAR request URI</li>
 * </ol>
 *
 * @since 1.0
 */
public class DefaultAgentAapExecutor implements AgentAapExecutor {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAgentAapExecutor.class);

    // Core dependencies
    private final Agent agent;
    private final VcSigner vcSigner;
    private final PolicyBuilder policyBuilder;
    private final PromptProtectionChain promptProtectionChain;

    // Configuration
    private final AgentAapExecutorConfig config;

    // Authorization context (managed per request)
    private WorkloadContext currentWorkloadContext;

    /**
     * Constructor with dependency injection.
     *
     * @param agent                    the agent interface for protocol operations
     * @param vcSigner                 the VC signer for evidence signing (optional)
     * @param policyBuilder            the policy builder for operation proposals
     * @param promptProtectionChain    the prompt protection chain for comprehensive protection (optional)
     * @param config                   the executor configuration (optional, uses defaults if null)
     * @throws IllegalArgumentException if required dependencies are null
     */
    public DefaultAgentAapExecutor(
            Agent agent,
            VcSigner vcSigner,
            PolicyBuilder policyBuilder,
            PromptProtectionChain promptProtectionChain,
            AgentAapExecutorConfig config
    ) {

        this.agent = ValidationUtils.validateNotNull(agent, "Agent");
        this.vcSigner = vcSigner;
        this.policyBuilder = ValidationUtils.validateNotNull(policyBuilder, "PolicyBuilder");
        this.promptProtectionChain = promptProtectionChain;
        this.config = ValidationUtils.validateNotNull(config, "AgentAapExecutorConfig");
    }

    /**
     * Requests an authorization URL for agent operation authorization.
     * <p>
     * This method orchestrates the complete authorization flow:
     * </p>
     * <ul>
     *   <li>Validates the request parameters</li>
     *   <li>Creates workload context</li>
     *   <li>Registers OAuth client</li>
     *   <li>Builds operation proposal and evidence</li>
     *   <li>Submits PAR request</li>
     *   <li>Generates authorization URL</li>
     * </ul>
     *
     * @param request the authorization URL request
     * @return the authorization URL response with PAR request URI and state
     * @throws FrameworkAuthorizationException if authorization URL request fails
     */
    @Override
    public RequestAuthUrlResponse requestAuthUrl(RequestAuthUrlRequest request) {
        ValidationUtils.validateNotNull(request, "RequestAuthUrlRequest cannot be null");

        logger.info("Initiating authorization URL request for operation: {}", request.getWorkloadContext() != null ? request.getWorkloadContext().getOperationType() : "unknown");

        try {
            // Step 1: Create workload context
            WorkloadContext workloadContext = createWorkloadContext(request);
            logger.debug("Workload context created: workloadId={}, userId={}",
                    workloadContext.getWorkloadId(), workloadContext.getUserId());

            // Step 2: Register OAuth client
            registerOAuthClient(workloadContext);

            // Step 3: Build authorization components
            AuthorizationComponents components = buildAuthorizationComponents(workloadContext, request);

            // Step 4: Submit PAR request
            ParResponse parResponse = submitParRequest(workloadContext, components, request.getUserIdentityToken());
            logger.debug("PAR request submitted successfully: requestUri={}", parResponse.getRequestUri());

            // Step 5: Generate authorization URL
            String authUrl = agent.generateAuthorizationUrl(parResponse.getRequestUri(), components.getState());
            logger.info("Authorization URL generated successfully");

            // Step 6: Build response
            return buildAuthorizationResponse(authUrl, parResponse, components, workloadContext);

        } catch (FrameworkAuthorizationException e) {
            logger.error("Authorization URL request failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during authorization URL request", e);
            throw new FrameworkAuthorizationException(
                    "Failed to request authorization URL: " + e.getMessage(), e);
        }
    }

    @Override
    public String initiateUserAuth(InitiateAuthorizationRequest request) {
        logger.debug("Initiating user authorization");
        return agent.initiateAuthorization(request);
    }

    @Override
    public AgentAapExecutor exchangeUserIdToken(ExchangeCodeForTokenRequest request) {
        logger.debug("Exchanging user ID token");
        agent.exchangeCodeForToken(request);
        return this;
    }

    @Override
    public AgentOperationAuthToken exchangeAgentAuthToken(AuthorizationResponse response) {
        logger.debug("Exchanging agent authorization token");
        return agent.handleAuthorizationCallback(response);
    }

    @Override
    public AgentAuthorizationContext buildAuthContext(PrepareAuthorizationContextRequest request) {
        logger.debug("Building authorization context");
        return agent.prepareAuthorizationContext(request);
    }

    @Override
    public WorkloadContext getWorkloadContext() {
        return currentWorkloadContext;
    }

    @Override
    public void cleanup(WorkloadContext workloadContext) {
        logger.debug("Cleaning up authorization context");
        agent.clearAuthorizationContext(workloadContext);
    }

    // ===== Helper Methods =====

    /**
     * Resolves the device fingerprint with priority: request > configuration.
     * <p>
     * <b>Priority Order:</b></p>
     * <ol>
     *   <li>Request-level deviceFingerprint (if provided)</li>
     *   <li>Configuration-level defaultDeviceFingerprint (if set)</li>
     *   <li>Legacy strategy-based generation (for backward compatibility)</li>
     * </ol>
     * <p>
     * <b>Standard:</b> draft-liu-agent-operation-authorization-01, Table 1
     * <b>Requirement:</b> OPTIONAL
     * </p>
     *
     * @param request the authorization request
     * @return the resolved device fingerprint, or null if not available
     */
    private String resolveDeviceFingerprint(RequestAuthUrlRequest request) {
        // Priority 1: Request-level deviceFingerprint
        if (request.getDeviceFingerprint() != null) {
            logger.debug("Using deviceFingerprint from request: {}", request.getDeviceFingerprint());
            return request.getDeviceFingerprint();
        }

        // Priority 2: Configuration-level defaultDeviceFingerprint
        if (config.getDeviceFingerprint() != null) {
            logger.debug("Using deviceFingerprint from configuration: {}", config.getDeviceFingerprint());
            return config.getDeviceFingerprint();
        }

        // Priority 3: Legacy strategy-based generation (deprecated)
        logger.warn("deviceFingerprint not provided in request or configuration.");
        return config.getDeviceFingerprintStrategy().generate(request.getSessionId());
    }

    // ===== Workload Management Methods =====

    /**
     * Creates workload context for the authorization request.
     *
     * @param request the authorization request
     * @return the created workload context
     */
    private WorkloadContext createWorkloadContext(RequestAuthUrlRequest request) {

        // Get device fingerprint with priority: request > configuration
        String deviceFingerprint = resolveDeviceFingerprint(request);

        OperationRequestContext operationContext = OperationRequestContext.builder()
                .channel(config.getChannel())
                .language(config.getLanguage())
                .deviceFingerprint(deviceFingerprint)
                .agent(OperationRequestContext.AgentContext.builder()
                        .instance(deviceFingerprint)
                        .platform(config.getPlatform())
                        .client(config.getAgentClient())
                        .build())
                .build();

        // Build agent user binding proposal
        AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                .userIdentityToken(request.getUserIdentityToken())
                .build();

        // Build issue WIT request
        IssueWitRequest witRequest = IssueWitRequest.builder()
                .context(operationContext)
                .proposal(proposal)
                .oauthClientId(config.getClientId())
                .build();

        // Issue workload identity token
        WorkloadContext workloadContext = agent.issueWorkloadIdentityToken(witRequest);
        this.currentWorkloadContext = workloadContext;

        return workloadContext;
    }

    /**
     * Registers OAuth client for the workload.
     *
     * @param workloadContext the workload context
     */
    private void registerOAuthClient(WorkloadContext workloadContext) {
        DcrResponse dcrResponse = agent.registerOAuthClient(workloadContext);
        logger.debug("OAuth client registered: clientId={}", dcrResponse.getClientId());
    }

    // ===== Authorization Component Building Methods =====

    /**
     * Builds all components required for the authorization request.
     * <p>
     * This method encapsulates the creation of operation proposal, evidence,
     * operation context, and other authorization parameters.
     * </p>
     *
     * @param workloadContext the workload context
     * @param request         the authorization request
     * @return the authorization components bundle
     */
    private AuthorizationComponents buildAuthorizationComponents(
            WorkloadContext workloadContext,
            RequestAuthUrlRequest request
    ) {
        AgentOperationProposal operationProposal = buildOperationProposal(request);
        OperationRequestContext opContext = buildOperationContext(workloadContext, request);
        Evidence evidence = buildEvidence(request);
        String state = config.getStateGenerationStrategy().generate(request.getSessionId());
        String redirectUri = config.getRedirectUri();

        return new AuthorizationComponents(operationProposal, evidence, opContext, state, redirectUri);
    }

    /**
     * Builds the operation proposal using the policy builder.
     *
     * @param request the authorization request
     * @return the operation proposal
     */
    private AgentOperationProposal buildOperationProposal(RequestAuthUrlRequest request) {
        String policy = policyBuilder.buildPolicy(request);
        return AgentOperationProposal.builder().policy(policy).build();
    }

    /**
     * Builds the operation request context.
     * <p>
     * This method constructs the complete operation context including user and agent
     * information required for authorization decision-making.
     * </p>
     *
     * @param workloadContext the workload context
     * @param request         the authorization request
     * @return the operation request context
     */
    private OperationRequestContext buildOperationContext(
            WorkloadContext workloadContext,
            RequestAuthUrlRequest request) {

        // Get device fingerprint with priority: request > configuration
        String deviceFingerprint = resolveDeviceFingerprint(request);

        return OperationRequestContext.builder()
                .channel(config.getChannel())
                .language(config.getLanguage())
                .deviceFingerprint(deviceFingerprint)
                .user(buildUserContext(workloadContext))
                .agent(buildAgentContext(deviceFingerprint))
                .build();
    }

    /**
     * Builds the user context from workload information.
     *
     * @param workloadContext the workload context
     * @return the user context
     */
    private OperationRequestContext.UserContext buildUserContext(WorkloadContext workloadContext) {
        return OperationRequestContext.UserContext.builder()
                .id(workloadContext.getUserId())
                .build();
    }

    /**
     * Builds the agent context from request parameters.
     *
     * @param deviceFingerprint the device fingerprint
     * @return the agent context
     */
    private OperationRequestContext.AgentContext buildAgentContext(String deviceFingerprint) {

        return OperationRequestContext.AgentContext.builder()
                .instance(deviceFingerprint)
                .platform(config.getPlatform())
                .client(config.getAgentClient())
                .build();
    }

    /**
     * Builds evidence for the authorization request.
     * <p>
     * This method follows the Strategy pattern by attempting to use VC signing
     * if available, and falling back to raw ID token as a degraded but functional
     * alternative. This ensures the authorization flow remains functional even
     * when VC signing is not configured or fails.
     * </p>
     *
     * @param request the authorization request
     * @return the evidence object
     */
    private Evidence buildEvidence(RequestAuthUrlRequest request) {
        if (vcSigner == null) {
            logger.debug("VC signer not configured, using raw ID token as evidence");
            return buildRawEvidence(request.getUserIdentityToken());
        }

        try {
            return buildSignedEvidence(request);
        } catch (Exception e) {
            logger.warn("Failed to sign evidence VC, falling back to raw ID token: {}", e.getMessage());
            return buildRawEvidence(request.getUserIdentityToken());
        }
    }

    /**
     * Builds raw evidence using the ID token directly.
     *
     * @param idToken the user identity token
     * @return the evidence with raw ID token
     */
    private Evidence buildRawEvidence(String idToken) {
        return Evidence.builder().sourcePromptCredential(idToken).build();
    }

    /**
     * Builds signed evidence using VC signer.
     * <p>
     * This method creates a Verifiable Credential containing the user's original
     * input as evidence, then signs it using the configured VC signer. The signed
     * VC provides cryptographic proof of the user's intent.
     * </p>
     *
     * @param request the authorization request
     * @return the signed evidence
     * @throws RuntimeException if VC signing fails
     */
    private Evidence buildSignedEvidence(RequestAuthUrlRequest request) {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(config.getExpirationSeconds());

        UserInputEvidence userInputEvidence = createUserInputEvidence(now, request);
        VerifiableCredential credential = createVerifiableCredential(userInputEvidence, now, expiration);

        try {
            String signedVcJwt = vcSigner.sign(credential);
            logger.debug("Evidence VC signed successfully");
            return Evidence.builder().sourcePromptCredential(signedVcJwt).build();
        } catch (Exception e) {
            logger.error("Failed to sign VC", e);
            throw new RuntimeException("VC signing failed", e);
        }
    }

    /**
     * Creates user input evidence for VC.
     *
     * @param timestamp the current timestamp
     * @param request   the authorization request
     * @return the user input evidence
     */
    private UserInputEvidence createUserInputEvidence(Instant timestamp, RequestAuthUrlRequest request) {
        // Get device fingerprint with priority: request > configuration
        String deviceFingerprint = resolveDeviceFingerprint(request);

        // Protect the user's original prompt using the three-layer protection mechanism
        String prompt = request.getUserOriginalInput();
        if (promptProtectionChain != null && config.getPromptProtectionEnabled() != null
            && config.getPromptProtectionEnabled()) {

            // Get sanitization level from configuration
            SanitizationLevel sanitizationLevel = parseSanitizationLevel(config.getSanitizationLevel());

            ProtectionContext protectionContext = new ProtectionContext(
                prompt,
                sanitizationLevel,
                config.getEncryptionEnabled(),  // Enable JWE encryption for evidence
                config.getRequireUserInteraction() == null || !config.getRequireUserInteraction()
            );

            var protectionResult = promptProtectionChain.protect(protectionContext);

            if (protectionResult.isSuccess()) {
                prompt = protectionResult.getProtectedPrompt();
                logger.debug("User prompt protected successfully: encrypted={}, hasSensitiveInfo={}, level={}",
                    protectionResult.isEncrypted(), protectionResult.hasSensitiveInfo(), sanitizationLevel);
            } else {
                logger.warn("Prompt protection failed: {}, using original prompt",
                    protectionResult.getErrorMessage());
            }
        }

        return UserInputEvidence.builder()
                .type("UserInputEvidence")
                .prompt(prompt)
                .timestamp(timestamp)
                .channel(config.getChannel())
                .deviceFingerprint(deviceFingerprint)
                .build();
    }

    /**
     * Parses the sanitization level from configuration string.
     *
     * @param level the sanitization level string
     * @return the parsed SanitizationLevel
     */
    private SanitizationLevel parseSanitizationLevel(String level) {
        if (level == null || level.trim().isEmpty()) {
            return SanitizationLevel.MEDIUM;
        }
        
        try {
            return SanitizationLevel.valueOf(level.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid sanitization level: {}, using MEDIUM as default", level);
            return SanitizationLevel.MEDIUM;
        }
    }

    /**
     * Creates a verifiable credential from user input evidence.
     *
     * @param userInputEvidence the user input evidence
     * @param now               the current time
     * @param expiration        the expiration time
     * @return the verifiable credential
     */
    private VerifiableCredential createVerifiableCredential(
            UserInputEvidence userInputEvidence,
            Instant now,
            Instant expiration) {

        return VerifiableCredential.builder()
                .jti("vc-" + UUID.randomUUID())
                .iss(config.getIssuer())
                .sub(currentWorkloadContext.getUserId())
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(userInputEvidence)
                .issuer(config.getIssuer())
                .issuanceDate(now)
                .expirationDate(expiration)
                .build();
    }

    // ===== PAR Request Methods =====

    /**
     * Submits PAR request to authorization server.
     *
     * @param workloadContext the workload context
     * @param components      the authorization components
     * @return the PAR response
     */
    private ParResponse submitParRequest(
            WorkloadContext workloadContext,
            AuthorizationComponents components,
            String userIdentityToken
    ) {

        ParSubmissionRequest parRequest = ParSubmissionRequest.builder()
                .workloadContext(workloadContext)
                .operationProposal(components.getOperationProposal())
                .evidence(components.getEvidence())
                .context(components.getOperationContext())
                .userIdentityToken(userIdentityToken)
                .state(components.getState())
                .expirationSeconds(config.getExpirationSeconds())
                .build();

        return agent.submitParRequest(parRequest);
    }

    /**
     * Builds the authorization URL response.
     *
     * @param authUrl         the authorization URL
     * @param parResponse     the PAR response
     * @param components      the authorization components
     * @param workloadContext the workload context
     * @return the authorization URL response
     */
    private RequestAuthUrlResponse buildAuthorizationResponse(
            String authUrl,
            ParResponse parResponse,
            AuthorizationComponents components,
            WorkloadContext workloadContext) {

        return RequestAuthUrlResponse.builder()
                .authorizationUrl(authUrl)
                .requestUri(parResponse.getRequestUri())
                .state(components.getState())
                .workloadContext(workloadContext)
                .redirectUri(components.getRedirectUri())
                .build();
    }

    // ===== Inner Classes =====

    /**
     * Bundle of authorization components built for a single authorization request.
     * <p>
     * This class encapsulates all the components needed to submit a PAR request
     * and generate an authorization URL, providing better organization and
     * reducing method parameter count.
     * </p>
     */
    private static class AuthorizationComponents {
        private final AgentOperationProposal operationProposal;
        private final Evidence evidence;
        private final OperationRequestContext operationContext;
        private final String state;
        private final String redirectUri;

        public AuthorizationComponents(
                AgentOperationProposal operationProposal,
                Evidence evidence,
                OperationRequestContext operationContext,
                String state,
                String redirectUri) {
            this.operationProposal = operationProposal;
            this.evidence = evidence;
            this.operationContext = operationContext;
            this.state = state;
            this.redirectUri = redirectUri;
        }

        public AgentOperationProposal getOperationProposal() {
            return operationProposal;
        }

        public Evidence getEvidence() {
            return evidence;
        }

        public OperationRequestContext getOperationContext() {
            return operationContext;
        }

        public String getState() {
            return state;
        }

        public String getRedirectUri() {
            return redirectUri;
        }
    }
}