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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import com.alibaba.openagentauth.core.protocol.wimse.workload.model.AgentRequestContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;

import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Default orchestration implementation for Agent IDP.
 * <p>
 * This orchestrator manages agent workload identities and coordinates the creation,
 * issuance, and revocation of Workload Identity Tokens (WIT). It implements
 * the virtual workload pattern for request-level isolation with agent-specific
 * identity claims.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Agent Workload Creation:</b> Creates virtual workloads with temporary key pairs</li>
 *   <li><b>User Binding:</b> Validates ID Token and binds workload identities to user identities</li>
 *   <li><b>WIT Issuance:</b> Generates signed WIT tokens with agent identity claims</li>
 *   <li><b>Workload Lifecycle:</b> Manages workload creation and revocation</li>
 * </ul>
 *
 * @see AgentIdentityProvider
 * @since 1.0
 */
public class DefaultAgentIdentityProvider implements AgentIdentityProvider {

    // Logger
    private static final Logger logger = LoggerFactory.getLogger(DefaultAgentIdentityProvider.class);
    
    // Workload identity constants
    private static final String WORKLOAD_STATUS_ACTIVE = "active";
    private static final long DEFAULT_EXPIRATION_SECONDS = 3600; // 1 hour default expiration

    // Services
    private final TokenService tokenService;
    private final IdTokenValidator idTokenValidator;
    private final String issuer;
    private final String agentUserIdpIssuer;
    private final WorkloadRegistry workloadRegistry;

    /**
     * Creates a new AgentIdpOrchestrator.
     *
     * @param tokenService the token service for WIT generation
     * @param idTokenValidator the ID Token validator for validating user identity tokens
     * @param issuer the issuer URL for agent identity claims (WIT)
     * @param agentUserIdpIssuer the issuer URL for Agent User IDP (ID Token validation)
     * @param workloadRegistry the workload store for persisting workload information
     */
    public DefaultAgentIdentityProvider(TokenService tokenService,
                                        IdTokenValidator idTokenValidator, String issuer,
                                        String agentUserIdpIssuer, WorkloadRegistry workloadRegistry) {
        // Validate input parameters using concise null checks
        this.tokenService = ValidationUtils.validateNotNull(tokenService, "Token service");
        this.idTokenValidator = ValidationUtils.validateNotNull(idTokenValidator, "ID Token validator");
        this.issuer = ValidationUtils.validateNotEmpty(issuer, "Issuer");
        this.agentUserIdpIssuer = ValidationUtils.validateNotEmpty(agentUserIdpIssuer, "Agent User IDP issuer");
        this.workloadRegistry = ValidationUtils.validateNotNull(workloadRegistry, "Workload store");
        
        logger.info("AgentIdpOrchestrator initialized with issuer: {}, agentUserIdpIssuer: {}, expiration: {}s",
                issuer, agentUserIdpIssuer, DEFAULT_EXPIRATION_SECONDS);
    }

    /**
     * Creates a new agent workload identity.
     *
     * @param idToken the ID Token to validate and extract user identity
     * @param context the request context for workload creation
     * @return the created workload identity
     * @throws WorkloadCreationException if workload creation fails
     */
    @Override
    public WorkloadInfo createAgentWorkload(String idToken, AgentRequestContext context) throws WorkloadCreationException {

        // Validate input parameters
        if (ValidationUtils.isNullOrEmpty(idToken)) {
            throw new IllegalArgumentException("ID Token cannot be null or empty");
        }
        ValidationUtils.validateNotNull(context, "Request context");

        logger.debug("Creating agent workload from ID Token");

        try {
            // Validate ID Token and extract user identity
            // Extract client_id from the context
            String clientId = context.getClientId();
            
            String userId = validateAndExtractUserId(idToken, clientId);
            logger.debug("Extracted user ID from ID Token: {}", userId);

            // Create workload identity
            String workloadId = generateWorkloadId();
            Instant now = Instant.now();
            
            // Use the public key provided by Agent (Agent generates key pair)
            String publicKey = context.getPublicKey();
            if (ValidationUtils.isNullOrEmpty(publicKey)) {
                throw new IllegalArgumentException("Public key is required");
            }
            
            // Get trust domain from token service
            String trustDomain = tokenService.getWitGenerator().getTrustDomain().getDomainName();
            
            // Create workload with provided public key (no private key - Agent keeps it)
            WorkloadInfo updatedWorkload = WorkloadInfo.builder()
                    .workloadId(workloadId)
                    .userId(userId)
                    .trustDomain(trustDomain)
                    .issuer(issuer)
                    .publicKey(publicKey)
                    .createdAt(now)
                    .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                    .status(WORKLOAD_STATUS_ACTIVE)
                    .context(OperationRequestContext.builder().build())
                    .build();

            // Store workload
            workloadRegistry.save(updatedWorkload);

            logger.info("Agent workload created: {} for user: {}", workloadId, userId);
            return updatedWorkload;
            
        } catch (Exception e) {
            logger.error("Failed to create workload", e);
            throw new WorkloadCreationException("Failed to create workload", e);
        }
    }

    /**
     * Issues a Workload Identity Token (WIT) using standard request model.
     * <p>
     * This is the standard-compliant implementation that accepts
     * {@link IssueWitRequest} as defined in draft-liu-agent-operation-authorization.
     * </p>
     *
     * <h3>Workflow:</h3>
     * <ul>
     *   <li><b>Step 1:</b> Validate IssueWitRequest</li>
     *   <li><b>Step 2:</b> Validate ID Token and extract user identity</li>
     *   <li><b>Step 3:</b> Find or create workload (independent of WIT expiration)</li>
     *   <li><b>Step 4:</b> Issue WIT with independent expiration time</li>
     * </ul>
     *
     * @param request the standard IssueWitRequest
     * @return the Workload Identity Token (WIT)
     * @throws FrameworkTokenGenerationException if token generation fails
     * @throws WorkloadCreationException if workload creation fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    @Override
    public WorkloadIdentityToken issueWit(IssueWitRequest request)
        throws FrameworkTokenGenerationException, WorkloadCreationException {

        // Step 1: Validate IssueWitRequest
        validateIssueWitRequest(request);

        // Step 2: Extract core fields from standard model
        String idToken = request.getProposal().getUserIdentityToken();
        String clientId = request.getOauthClientId();

        // Step 3: Validate ID Token and extract user identity
        String userId = validateAndExtractUserId(idToken, clientId);

        // Step 4: Find or create workload (using standard model data)
        WorkloadInfo workload = findOrCreateWorkloadByUniqueKey(userId, request);

        // Step 5: Issue WIT
        return doIssueWit(workload);
    }

    /**
     * Revokes an agent workload identity.
     *
     * @param agentWorkloadId the agent workload ID to revoke
     * @throws WorkloadNotFoundException if the workload is not found
     */
    @Override
    public void revokeAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException {
        
        // Validate input parameters
        if (ValidationUtils.isNullOrEmpty(agentWorkloadId)) {
            throw new IllegalArgumentException("Agent workload ID cannot be null or empty");
        }

        logger.debug("Revoking agent workload: {}", agentWorkloadId);
        
        if (!workloadRegistry.exists(agentWorkloadId)) {
            throw new WorkloadNotFoundException("Agent workload not found: " + agentWorkloadId);
        }
        
        workloadRegistry.revoke(agentWorkloadId);

        logger.info("Agent workload revoked: {}", agentWorkloadId);
    }

    /**
     * Gets the agent workload identity.
     *
     * @param agentWorkloadId the agent workload ID to get
     * @return the agent workload identity
     * @throws WorkloadNotFoundException if the workload is not found
     */
    @Override
    public WorkloadInfo getAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException {
        
        // Validate input parameters
        if (ValidationUtils.isNullOrEmpty(agentWorkloadId)) {
            throw new IllegalArgumentException("Agent workload ID cannot be null or empty");
        }

        return workloadRegistry.findById(agentWorkloadId)
                .orElseThrow(() -> new WorkloadNotFoundException("Agent workload not found: " + agentWorkloadId));
    }

    /**
     * Validates the ID Token and extracts the user ID (sub claim).
     * <p>
     * This method uses the IdTokenValidator to perform comprehensive validation
     * according to the OpenID Connect Core 1.0 specification, including:
     * </p>
     * <ul>
     *   <li>Signature verification</li>
     *   <li>Issuer validation</li>
     *   <li>Audience validation</li>
     *   <li>Expiration validation</li>
     *   <li>Issued at validation</li>
     * </ul>
     *
     * @param idToken the ID Token to validate
     * @param clientId the OAuth 2.0 client ID (expected audience in the ID Token)
     * @return the user ID from the ID Token's sub claim
     * @throws WorkloadCreationException if ID Token validation fails
     */
    private String validateAndExtractUserId(String idToken, String clientId) throws WorkloadCreationException {
        
        // Validate input parameters
        if (ValidationUtils.isNullOrEmpty(idToken)) {
            throw new WorkloadCreationException("ID Token cannot be null or empty");
        }
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            throw new WorkloadCreationException("Client ID cannot be null or empty");
        }

        try {
            // Validate ID Token using IdTokenValidator
            // According to OIDC specification, the ID Token's aud claim must contain the client_id
            // The ID Token is issued by Agent User IDP, so we use agentUserIdpIssuer as expected issuer
            // and clientId as expected audience
            IdToken validatedToken = idTokenValidator.validate(idToken, agentUserIdpIssuer, clientId);
            
            String userId = validatedToken.getClaims().getSub();
            if (ValidationUtils.isNullOrEmpty(userId)) {
                throw new WorkloadCreationException("ID Token is missing subject claim");
            }
            
            logger.debug("ID Token validated successfully, extracted user ID: {}", userId);
            return userId;
            
        } catch (IdTokenException e) {
            logger.error("Failed to validate ID Token: {}", e.getMessage(), e);
            throw new WorkloadCreationException("Failed to validate ID Token: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error validating ID Token", e);
            throw new WorkloadCreationException("Unexpected error validating ID Token", e);
        }
    }

    /**
     * Generates a unique workload ID according to WIMSE standard.
     * <p>
     * This method follows the specification defined in 
     * <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-identifier-01">draft-ietf-wimse-identifier-01</a>.
     * The generated identifier follows the format: {@code wimse://<trust-domain>/workload/<uuid>}
     * </p>
     *
     * @return the workload ID in WIMSE standard format
     */
    private String generateWorkloadId() {
        String domainName = tokenService.getWitGenerator().getTrustDomain().getDomainName();
        String uniqueId = UUID.randomUUID().toString();
        
        // Build the identifier: wimse://trust-domain/workload/unique-id
        // getDomainName() handles both "wimse://example.com" and "example.com" formats
        return "wimse://" + domainName + "/workload/" + uniqueId;
    }

    /**
     * Gets the ID Token validator.
     *
     * @return the IdTokenValidator instance
     */
    public IdTokenValidator getIdTokenValidator() {
        return idTokenValidator;
    }

    /**
     * Finds an existing workload for the workload unique key, or creates a new one.
     * <p>
     * This method works with the standard request model and extracts required fields
     * from the request internally, following good encapsulation principles.
     * </p>
     * 
     * <p>
     * Workload expiration is independent of WIT expiration. This method only checks
     * if the workload itself is expired, not the WIT.
     * </p>
     * 
     * @param userId the user ID extracted from ID Token
     * @param request the original IssueWitRequest containing all required fields
     * @return existing or newly created workload
     * @throws WorkloadCreationException if workload creation fails
     */
    private WorkloadInfo findOrCreateWorkloadByUniqueKey(String userId, IssueWitRequest request) 
            throws WorkloadCreationException {
        
        // Extract fields from request internally
        OperationRequestContext.AgentContext agentContext = request.getContext().getAgent();
        String workloadUniqueKey = generateWorkloadUniqueKey(userId, agentContext);
        
        logger.debug("Looking for workload with workloadUniqueKey: {}", workloadUniqueKey);
        
        // Try to find existing workload by workloadUniqueKey
        Optional<WorkloadInfo> existingWorkload = workloadRegistry.findByWorkloadUniqueKey(workloadUniqueKey);
        
        if (existingWorkload.isPresent()) {
            WorkloadInfo workload = existingWorkload.get();
            
            // Check if workload is active (not expired)
            if (workload.isActive()) {
                // Update the workload's public key to match the new key pair generated
                // by the Agent. Each issueWit call from the Agent generates a fresh key
                // pair, so the IDP must bind the latest public key into the WIT's cnf.jwk.
                String newPublicKey = request.getPublicKey();
                if (newPublicKey != null && !newPublicKey.equals(workload.getPublicKey())) {
                    logger.info("Updating public key for existing workload: {}", workload.getWorkloadId());
                    workload = workload.toBuilder()
                            .publicKey(newPublicKey)
                            .build();
                    workloadRegistry.save(workload);
                }
                logger.debug("Reusing existing workload: {} for userId: {}, agentContext: {}", 
                        workload.getWorkloadId(), userId, agentContext);
                return workload;
            } else {
                // Workload is expired, delete it
                logger.info("Existing workload {} is expired (expiresAt: {}), deleting", 
                        workload.getWorkloadId(), workload.getExpiresAt());
                workloadRegistry.delete(workload.getWorkloadId());
            }
        }
        
        // No valid workload found, create a new one
        logger.info("Creating new workload for userId: {}, agentContext: {}", userId, agentContext);
        return createNewWorkload(userId, workloadUniqueKey, request);
    }

    /**
     * Creates a new workload for the workload unique key.
     * <p>
     * This method extracts required fields from the request internally, following
     * good encapsulation principles. It stores the original request in metadata
     * for audit purposes.
     * </p>
     *
     * @param userId the user ID
     * @param workloadUniqueKey the workload unique key
     * @param request the original IssueWitRequest for audit purposes
     * @return the newly created workload
     * @throws WorkloadCreationException if workload creation fails
     */
    private WorkloadInfo createNewWorkload(String userId, String workloadUniqueKey, IssueWitRequest request)
        throws WorkloadCreationException {

        try {
            // Generate workload ID
            String workloadId = generateWorkloadId();
            Instant now = Instant.now();

            // Build metadata with audit information
            // Store the context for audit purposes
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("workloadUniqueKey", workloadUniqueKey);

            // Get trust domain from token service
            String trustDomain = tokenService.getWitGenerator().getTrustDomain().getDomainName();

            // Create workload with independent expiration time
            WorkloadInfo workload = WorkloadInfo.builder()
                    .workloadId(workloadId)
                    .userId(userId)
                    .trustDomain(trustDomain)
                    .issuer(issuer)
                    .publicKey(request.getPublicKey())
                    .createdAt(now)
                    .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                    .status(WORKLOAD_STATUS_ACTIVE)
                    .context(request.getContext())
                    .metadata(metadata)
                    .build();

            // Store workload
            workloadRegistry.save(workload);

            logger.info("New workload created: {} for user: {}, agentContext: {}, expires at: {}",
                workloadId, userId, request.getContext(), workload.getExpiresAt());

            return workload;

        } catch (Exception e) {
            logger.error("Failed to create new workload for user: {}, agentContext: {}",
                userId, request.getContext(), e);
            throw new WorkloadCreationException("Failed to create workload", e);
        }
    }

    /**
     * Issues a WIT for the given workload.
     * <p>
     * This is the core WIT issuance logic that generates WIT.
     * </p>
     * 
     * @param workload the workload to issue WIT for
     * @return the issued WIT
     * @throws FrameworkTokenGenerationException if token generation fails
     */
    private WorkloadIdentityToken doIssueWit(WorkloadInfo workload) 
            throws FrameworkTokenGenerationException {
        
        try {
            Instant now = Instant.now();
            
            // WIT expiration time is independent of workload expiration
            // Use fixed DEFAULT_EXPIRATION_SECONDS (1 hour)
            Instant witExpiresAt = now.plusSeconds(DEFAULT_EXPIRATION_SECONDS);
            
            // Generate WIT with independent expiration time
            WorkloadIdentityToken wit = tokenService.generateWit(
                    workload.getWorkloadId(),
                    workload.getPublicKey(),
                    DEFAULT_EXPIRATION_SECONDS
            );
            
            logger.info("WIT issued for workload: {}, WIT expires at: {}, Workload expires at: {}",
                    workload.getWorkloadId(), witExpiresAt, workload.getExpiresAt());
            
            return wit;
            
        } catch (JOSEException e) {
            logger.error("Failed to generate WIT for workload: {}", workload.getWorkloadId(), e);
            throw new FrameworkTokenGenerationException("Failed to generate WIT", e);
        }
    }

    /**
     * Generates a unique workload key for workload lookup.
     * <p>
     * The workload unique key is used to identify and reuse workloads across
     * multiple requests. The key uses the complete agent context information
     * (instance, platform, client) to ensure unique identification of an agent
     * at the finest granularity.
     * </p>
     * <p>
     * This provides instance-level isolation where different agent instances,
     * even on the same platform and client, will have separate workloads.
     * </p>
     *
     * @param userId the user ID
     * @param agentContext the agent context containing instance, platform, and client
     * @return the workload unique key in format "userId:platform:client:instance"
     */
    private String generateWorkloadUniqueKey(String userId, OperationRequestContext.AgentContext agentContext) {
        String platform = agentContext.getPlatform() != null ? agentContext.getPlatform() : "default";
        String client = agentContext.getClient() != null ? agentContext.getClient() : "default";
        String instance = agentContext.getInstance() != null ? agentContext.getInstance() : "default";
        
        return userId + ":" + platform + ":" + client + ":" + instance;
    }

    /**
     * Validates the IssueWitRequest according to standard requirements.
     * <p>
     * This method validates core fields required for workload creation and token issuance.
     * </p>
     *
     * @param request the IssueWitRequest to validate
     * @throws IllegalArgumentException if request is null or required fields are missing
     */
    private void validateIssueWitRequest(IssueWitRequest request) {
        ValidationUtils.validateNotNull(request, "IssueWitRequest");
        ValidationUtils.validateNotNull(request.getContext(), "Operation request context");
        ValidationUtils.validateNotNull(request.getProposal(), "Agent user binding proposal");
        
        // Validate required nested fields
        ValidationUtils.validateNotEmpty(request.getProposal().getUserIdentityToken(), 
                "User identity token");
        ValidationUtils.validateNotNull(request.getContext().getAgent(), "Agent context");
        ValidationUtils.validateNotEmpty(request.getContext().getAgent().getClient(), "Client ID");
        ValidationUtils.validateNotEmpty(request.getPublicKey(), "Public key");
    }

}