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
package com.alibaba.openagentauth.core.protocol.oauth2.token.aoat;

import com.alibaba.openagentauth.core.binding.BindingInstance;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.exception.workload.VcVerificationException;
import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.context.References;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.vc.VcVerifier;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.UUID;

/**
 * Default implementation of {@link AoatTokenGenerator}.
 * <p>
 * This implementation generates Agent Operation Authorization Tokens (AOAT)
 * by extracting claims from PAR requests and building the required AOAT structure.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public class DefaultAoatTokenGenerator implements AoatTokenGenerator {

    /**
     * Logger for the default AOAT token generator.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultAoatTokenGenerator.class);

    /**
     * AOAT generator for signing and serializing tokens.
     */
    private final AoatGenerator aoatGenerator;

    /**
     * VC verifier for verifying evidence credentials.
     */
    private final VcVerifier vcVerifier;

    /**
     * Policy registry for registering OPA policies.
     */
    private final PolicyRegistry policyRegistry;

    /**
     * Binding instance store for storing binding instances.
     */
    private final BindingInstanceStore bindingInstanceStore;

    /**
     * Prompt decryption service for JWE protection.
     */
    private final PromptDecryptionService promptDecryptionService;

    /**
     * Default token expiration time in seconds.
     */
    private final long defaultTokenExpirationSeconds;

    /**
     * Creates a new DefaultAoatTokenGenerator.
     *
     * @param aoatGenerator the AOAT generator
     * @param vcVerifier the VC verifier
     * @param policyRegistry the policy registry
     * @param defaultTokenExpirationSeconds the default expiration time in seconds
     */
    public DefaultAoatTokenGenerator(
            AoatGenerator aoatGenerator,
            VcVerifier vcVerifier,
            PolicyRegistry policyRegistry,
            long defaultTokenExpirationSeconds
    ) {
        this.aoatGenerator = Objects.requireNonNull(aoatGenerator, "AOAT generator cannot be null");
        this.vcVerifier = Objects.requireNonNull(vcVerifier, "VC verifier cannot be null");
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "Policy registry cannot be null");
        this.bindingInstanceStore = null;
        this.promptDecryptionService = null;
        this.defaultTokenExpirationSeconds = defaultTokenExpirationSeconds;
        logger.info("DefaultAoatTokenGenerator initialized with expiration: {} seconds", defaultTokenExpirationSeconds);
    }

    /**
     * Creates a new DefaultAoatTokenGenerator with binding instance store.
     *
     * @param aoatGenerator the AOAT generator
     * @param vcVerifier the VC verifier
     * @param policyRegistry the policy registry
     * @param bindingInstanceStore the binding instance store
     * @param defaultTokenExpirationSeconds the default expiration time in seconds
     */
    /**
     * Constructs a new DefaultAoatTokenGenerator.
     *
     * @param aoatGenerator              the AOAT generator
     * @param vcVerifier                 the VC verifier
     * @param policyRegistry             the policy registry
     * @param bindingInstanceStore       the binding instance store
     * @param promptDecryptionService    the prompt decryption service for JWE protection (optional)
     * @param defaultTokenExpirationSeconds the default token expiration time in seconds
     * @throws NullPointerException if any required parameter is null
     */
    public DefaultAoatTokenGenerator(
            AoatGenerator aoatGenerator,
            VcVerifier vcVerifier,
            PolicyRegistry policyRegistry,
            BindingInstanceStore bindingInstanceStore,
            PromptDecryptionService promptDecryptionService,
            long defaultTokenExpirationSeconds
    ) {
        this.aoatGenerator = ValidationUtils.validateNotNull(aoatGenerator, "aoatGenerator");
        this.vcVerifier = ValidationUtils.validateNotNull(vcVerifier, "vcVerifier");
        this.policyRegistry = ValidationUtils.validateNotNull(policyRegistry, "policyRegistry");
        this.bindingInstanceStore = ValidationUtils.validateNotNull(bindingInstanceStore, "bindingInstanceStore");
        this.promptDecryptionService = promptDecryptionService;
        this.defaultTokenExpirationSeconds = defaultTokenExpirationSeconds;
    }

    @Override
    public AgentOperationAuthToken generateAoat(String subject, ParJwtClaims parClaims) throws JOSEException {
        logger.info("Generating AOAT for subject: {}", subject);

        // Validate PAR claims
        if (parClaims == null) {
            logger.error("PAR claims cannot be null");
            throw OAuth2TokenException.invalidGrant("Missing authorization request claims");
        }

        // Step 1: Build AgentIdentity
        AgentIdentity agentIdentity = buildAgentIdentity(parClaims);

        // Step 2: Build AgentOperationAuthorization
        AgentOperationAuthorization authorization = buildAuthorization(parClaims);

        // Step 3: Verify Evidence VC
        Evidence evidence = parClaims.getEvidence();
        VerifiableCredential verifiedVc = verifyEvidenceVc(evidence);

        // Step 4: Build TokenAuthorizationContext
        TokenAuthorizationContext context = buildAuthorizationContext(parClaims, verifiedVc);

        // Step 5: Build AuditTrail
        AuditTrail auditTrail = buildAuditTrail(parClaims, verifiedVc);

        // Step 6: Build References (NEW - according to draft-liu-agent-operation-authorization Section 4)
        References references = buildReferences(parClaims);

        // Step 7: Generate AOAT
        logger.info("Generating AOAT for subject: {}, agent: {}", subject, agentIdentity.getId());

        return aoatGenerator.newBuilder(subject, agentIdentity, authorization, defaultTokenExpirationSeconds)
                .evidence(evidence)
                .context(context)
                .auditTrail(auditTrail)
                .references(references)
                .build();
    }

    /**
     * Builds AgentIdentity from PAR claims.
     * <p>
     * According to draft-liu-agent-operation-authorization-01, the agent_identity.issuedTo
     * field must be derived from the user identity token in the binding proposal, which represents
     * the authenticated user from the Agent User IDP (not the AS User IDP).
     * </p>
     *
     * @param parClaims the PAR claims
     * @return the built AgentIdentity
     */
    private AgentIdentity buildAgentIdentity(ParJwtClaims parClaims) {

        // Extract binding proposal
        AgentUserBindingProposal bindingProposal = parClaims.getAgentUserBindingProposal();
        if (bindingProposal == null) {
            logger.warn("No agent user binding proposal found, creating minimal agent identity");
        }

        String agentId = generateBindingInstanceId();
        String issuer = aoatGenerator.getIssuer();
        Instant now = Instant.now();
        Instant expires = now.plusSeconds(defaultTokenExpirationSeconds);

        // Build issuedFor - REQUIRED field according to draft-liu-agent-operation-authorization-01
        // Extract real values from context, WIT (Workload Identity Token) and binding proposal
        AgentIdentity.IssuedFor issuedFor = buildIssuedFor(bindingProposal, agentId, parClaims.getContext());

        // Extract the actual user identifier from the Agent User IDP's ID Token
        // This is the correct user for agent_identity.issuedTo (e.g., alice)
        String agentUserId = extractUserIdFromIdToken(bindingProposal);
        String agentUserIdpIssuer = extractUserIdpIssuer(bindingProposal);

        // Extract workload identity from WIT (Workload Identity Token)
        // According to the protocol, this is the actual workload identifier from the WIT
        String workloadIdentity = extractWorkloadIdentityFromWit(bindingProposal);

        // Build agent identity
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(agentId)
                .issuer(issuer)
                .issuedTo(agentUserIdpIssuer + "|" + agentUserId)
                .issuedFor(issuedFor)
                .issuanceDate(now)
                .validFrom(now)
                .expires(expires)
                .build();

        // Create and store binding instance if binding instance store is available
        if (bindingInstanceStore != null) {
            createAndStoreBindingInstance(agentIdentity, now, expires, workloadIdentity);
        } else {
            logger.info("BindingInstanceStore not configured, skipping binding instance storage");
        }

        return agentIdentity;
    }

    /**
     * Builds the IssuedFor field from context, WIT and binding proposal.
     * <p>
     * According to draft-liu-agent-operation-authorization-01, issuedFor is a REQUIRED field
     * that must contain:
     * - platform: Logical service namespace
     * - client: Software client identifier (e.g., mobile app ID)
     * - clientInstance: Unique fingerprint of the client instance (e.g., device+app hash)
     * </p>
     * <p>
     * Data source priority:
     * 1. From OperationRequestContext.agent (preferred - contains real platform/client info)
     * 2. From WIT claims (if context is not available)
     * 3. From binding proposal device_fingerprint (for clientInstance)
     * 4. Generate fallback values (if nothing is available)
     * </p>
     *
     * @param bindingProposal the agent user binding proposal
     * @param agentId the agent ID (workload identifier)
     * @param context the operation request context
     * @return the built IssuedFor object
     */
    private AgentIdentity.IssuedFor buildIssuedFor(AgentUserBindingProposal bindingProposal, String agentId, OperationRequestContext context) {
        String platform = null;
        String client = null;
        String clientInstance = null;

        logger.info("buildIssuedFor called - context: {}, agentId: {}", 
                   context != null ? context.toString() : "null", agentId);

        // Priority 1: Extract from OperationRequestContext.agent (preferred)
        if (context != null && context.getAgent() != null) {
            OperationRequestContext.AgentContext agentContext = context.getAgent();
            platform = agentContext.getPlatform();
            client = agentContext.getClient();
            clientInstance = agentContext.getInstance();
            
            logger.info("Extracted from context.agent - platform: {}, client: {}, clientInstance: {}", 
                       platform, client, clientInstance);
        } else {
            logger.warn("context or context.agent is null - context: {}, context.agent: {}", 
                       context != null ? "not null" : "null",
                       context != null && context.getAgent() != null ? "not null" : "null");
        }

        // Priority 2: Extract from WIT if available (for platform and client)
        if ((ValidationUtils.isNullOrEmpty(platform) || ValidationUtils.isNullOrEmpty(client))
                && bindingProposal != null && bindingProposal.getAgentWorkloadToken() != null) {
            try {
                String witJwt = bindingProposal.getAgentWorkloadToken();
                SignedJWT signedJwt = SignedJWT.parse(witJwt);
                String witIssuer = signedJwt.getJWTClaimsSet().getIssuer();
                String witSubject = signedJwt.getJWTClaimsSet().getSubject();

                if (ValidationUtils.isNullOrEmpty(platform)) {
                    platform = witIssuer;
                }
                if (ValidationUtils.isNullOrEmpty(client)) {
                    client = witSubject;
                }
                
                logger.info("Extracted from WIT - platform: {}, client: {}", platform, client);
            } catch (Exception e) {
                logger.error("Failed to extract claims from WIT", e);
            }
        }

        // Priority 3: Extract clientInstance from device_fingerprint in binding proposal
        if (ValidationUtils.isNullOrEmpty(clientInstance)) {
            if (bindingProposal != null && bindingProposal.getDeviceFingerprint() != null) {
                clientInstance = bindingProposal.getDeviceFingerprint();
                logger.info("Extracted clientInstance from device_fingerprint: {}", clientInstance);
            }
        }

        // Priority 4: Generate fallback values
        if (ValidationUtils.isNullOrEmpty(platform)) {
            platform = aoatGenerator.getIssuer();
            logger.info("Using AS issuer as platform fallback: {}", platform);
        }
        
        if (ValidationUtils.isNullOrEmpty(client)) {
            client = agentId;
            logger.info("Using agentId as client fallback: {}", client);
        }
        
        if (ValidationUtils.isNullOrEmpty(clientInstance)) {
            clientInstance = UUID.randomUUID().toString();
            logger.info("Generated UUID as clientInstance fallback: {}", clientInstance);
        }

        logger.info("Built issuedFor - platform: {}, client: {}, clientInstance: {}", 
                   platform, client, clientInstance);

        return AgentIdentity.IssuedFor.builder()
                .platform(platform)
                .client(client)
                .clientInstance(clientInstance)
                .build();
    }

    /**
     * Generates a unique identifier for the agent-user binding instance.
     * <p>
     * According to draft-liu-agent-operation-authorization-01, the agent_identity.id
     * MUST be a UUID-based URI that uniquely identifies this binding instance.
     * The ID is generated by the Authorization Server (AS) and represents the
     * specific agent-to-user binding, not the workload identity itself.
     * </p>
     * <p>
     * The Workload Identity Token (WIT) is validated separately to ensure the
     * workload's legitimacy and trustworthiness, but its subject claim (sub)
     * is not used as the binding instance ID.
     * </p>
     * <p>
     * Note: This method currently generates a new UUID for each binding instance.
     * Future implementations may store and reuse binding IDs for the same
     * agent-user pair to enable persistent binding lifecycle management.
     * </p>
     *
     * @return a UUID-based URI for this binding instance (format: urn:uuid:...)
     */
    private String generateBindingInstanceId() {
        // Always generate a new UUID-based URI for this binding instance
        String bindingId = "urn:uuid:" + UUID.randomUUID();
        logger.info("Generated binding instance ID: {}", bindingId);
        return bindingId;
    }

    /**
     * Extracts the user IDP issuer from the ID Token in the binding proposal.
     * <p>
     * According to draft-liu-agent-operation-authorization-01, the agent_identity.issuedTo
     * field must be in the format "issuer|userId", where issuer is the IDP issuer URI
     * from the user identity token.
     * </p>
     *
     * @param bindingProposal the agent user binding proposal
     * @return the IDP issuer URI from the ID Token's iss claim, or a default if not available
     */
    private String extractUserIdpIssuer(AgentUserBindingProposal bindingProposal) {

        // If no binding proposal, return default issuer
        if (bindingProposal == null || bindingProposal.getUserIdentityToken() == null) {
            logger.warn("No ID Token in binding proposal, using default issuer");
            return aoatGenerator.getIssuer();
        }

        try {
            // Parse the ID Token JWT
            String idTokenJwt = bindingProposal.getUserIdentityToken();
            SignedJWT signedJwt = SignedJWT.parse(idTokenJwt);
            String idpIssuer = signedJwt.getJWTClaimsSet().getIssuer();

            // If IDP issuer is available, return it
            if (!ValidationUtils.isNullOrEmpty(idpIssuer)) {
                logger.info("Extracted IDP issuer from ID Token: {}", idpIssuer);
                return idpIssuer;
            }
        } catch (Exception e) {
            logger.error("Failed to extract IDP issuer from ID Token, using default issuer", e);
        }

        // If IDP issuer is not available, return default issuer
        return aoatGenerator.getIssuer();
    }

    /**
     * Extracts the user identifier (sub claim) from the ID Token in the binding proposal.
     * <p>
     * According to draft-liu-agent-operation-authorization-01, the agent_identity.issuedTo
     * field must be derived from the user identity token's sub claim, which represents
     * the authenticated user from the Agent User IDP (e.g., alice).
     * </p>
     *
     * @param bindingProposal the agent user binding proposal
     * @return the user identifier from the ID Token's sub claim, or a default if not available
     */
    private String extractUserIdFromIdToken(AgentUserBindingProposal bindingProposal) {

        // If no binding proposal, return default subject
        if (bindingProposal == null || bindingProposal.getUserIdentityToken() == null) {
            logger.warn("No ID Token in binding proposal, using default user identifier");
            return "unknown_user";
        }

        try {
            // Parse the ID Token JWT
            String idTokenJwt = bindingProposal.getUserIdentityToken();
            SignedJWT signedJwt = SignedJWT.parse(idTokenJwt);
            String userId = signedJwt.getJWTClaimsSet().getSubject();

            // If user ID is available, return it
            if (!ValidationUtils.isNullOrEmpty(userId)) {
                logger.info("Extracted user ID from ID Token: {}", userId);
                return userId;
            }
        } catch (Exception e) {
            logger.error("Failed to extract user ID from ID Token, using default user identifier", e);
        }

        // If user ID is not available, return default
        return "unknown_user";
    }

    /**
     * Builds AgentOperationAuthorization from PAR claims.
     * <p>
     * This method registers the operation proposal as a policy in the PolicyRegistry
     * and returns the authorization with the assigned policy ID.
     * </p>
     *
     * @param parClaims the PAR claims
     * @return the built AgentOperationAuthorization
     */
    private AgentOperationAuthorization buildAuthorization(ParJwtClaims parClaims) {
        String operationProposal = parClaims.getOperationProposal();
        if (ValidationUtils.isNullOrEmpty(operationProposal)) {
            logger.error("Operation proposal is required");
            throw OAuth2TokenException.invalidGrant("Missing operation proposal");
        }

        try {
            // Register the operation proposal as a policy
            PolicyRegistration registration = policyRegistry.register(
                    operationProposal,
                    "Agent operation proposal",
                    "authorization-server",
                    null
            );

            // Extract the policy ID
            String policyId = registration.getPolicy().getPolicyId();
            logger.info("Successfully registered operation proposal with policy ID: {}", policyId);

            // Return the policy ID
            return AgentOperationAuthorization.builder()
                    .policyId(policyId)
                    .build();

        } catch (PolicyRegistrationException e) {
            logger.error("Failed to register operation proposal as policy", e);
            throw OAuth2TokenException.invalidGrant("Failed to register operation proposal: " + e.getMessage());
        }
    }

    /**
     * Builds TokenAuthorizationContext from PAR claims.
     *
     * @param parClaims the PAR claims
     * @param verifiedVc the verified (and possibly decrypted) evidence VC
     * @return the built TokenAuthorizationContext, or null if not available
     */
    private TokenAuthorizationContext buildAuthorizationContext(ParJwtClaims parClaims, VerifiableCredential verifiedVc) {
        OperationRequestContext requestContext = parClaims.getContext();
        if (requestContext == null) {
            return null;
        }

        String renderedText = buildRenderedText(parClaims, verifiedVc);
        return TokenAuthorizationContext.builder()
                .renderedText(renderedText)
                .build();
    }

    /**
     * Builds rendered text for the authorization context.
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 4, the renderedText
     * should provide a human-readable description of the authorized operation that users
     * can easily understand. The protocol example shows:
     * "Purchase items under $50 during the Nov 11 promotion (valid until 23:59)"
     * </p>
     * <p>
     * This method generates user-friendly rendered text by:
     * </p>
     * <ul>
     *   <li>Extracting the original user prompt from the evidence VC (if available)</li>
     *   <li>Creating a clear, readable description of the authorized operation</li>
     *   <li>Using a user-friendly time format for expiration</li>
     * </ul>
     *
     * @param parClaims the PAR claims
     * @param verifiedVc the verified (and possibly decrypted) evidence VC
     * @return the rendered text
     */
    private String buildRenderedText(ParJwtClaims parClaims, VerifiableCredential verifiedVc) {

        // Extract operation proposal and context
        String operationProposal = parClaims.getOperationProposal();
        OperationRequestContext context = parClaims.getContext();

        // Extract original user prompt from verified (and decrypted) VC for better readability
        String originalPrompt = null;
        if (verifiedVc != null && verifiedVc.getCredentialSubject() != null) {
            originalPrompt = verifiedVc.getCredentialSubject().getPrompt();
        }

        StringBuilder rendered = new StringBuilder();

        // Build user-friendly description based on available context
        if (originalPrompt != null && !originalPrompt.isEmpty()) {
            // Use original prompt as base for better readability
            rendered.append("Authorized: ").append(originalPrompt);
        } else if (!ValidationUtils.isNullOrEmpty(operationProposal)) {
            // Fallback to generic description if no original prompt available
            rendered.append("Authorized agent operation per policy: ").append(operationProposal.length() > 50
                ? operationProposal.substring(0, 50) + "..."
                : operationProposal);
        } else {
            rendered.append("Authorized agent operation");
        }

        // Add context information if available
        if (context != null) {
            if (context.getChannel() != null && !context.getChannel().isEmpty()) {
                rendered.append(" via ").append(context.getChannel());
            }
            if (context.getAgent() != null && context.getAgent().getPlatform() != null) {
                rendered.append(" on ").append(context.getAgent().getPlatform());
            }
        }

        // Add expiration time in user-friendly format
        Instant expires = Instant.now().plusSeconds(defaultTokenExpirationSeconds);
        String expiresTime = expires.atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("HH:mm"));
        rendered.append(" (valid until ").append(expiresTime).append(")");

        return rendered.toString();
    }

    /**
     * Verifies the Verifiable Credential in the evidence claim.
     *
     * @param evidence the evidence claim containing the VC
     * @return the verified VerifiableCredential, or null if no evidence is present
     * @throws OAuth2TokenException if VC verification fails
     */
    private VerifiableCredential verifyEvidenceVc(Evidence evidence) {
        if (evidence == null || evidence.getSourcePromptCredential() == null) {
            logger.debug("No evidence VC present, skipping verification");
            return null;
        }

        String vcJwt = evidence.getSourcePromptCredential();
        logger.info("Verifying evidence VC before issuing AOAT");

        try {
            VerifiableCredential vc = vcVerifier.verify(vcJwt);
            logger.info("Evidence VC verified successfully: {}", vc.getJti());
            
            // Decrypt the prompt if decryption service is available
            if (vc != null && vc.getCredentialSubject() != null && promptDecryptionService != null) {
                try {
                    String encryptedPrompt = vc.getCredentialSubject().getPrompt();
                    String decryptedPrompt = promptDecryptionService.decryptPrompt(encryptedPrompt);
                    
                    // Create a new VC with decrypted prompt
                    VerifiableCredential decryptedVc = VerifiableCredential.builder()
                            .jti(vc.getJti())
                            .iss(vc.getIss())
                            .sub(vc.getSub())
                            .iat(vc.getIat())
                            .exp(vc.getExp())
                            .type(vc.getType())
                            .credentialSubject(UserInputEvidence.builder()
                                    .type(vc.getCredentialSubject().getType())
                                    .prompt(decryptedPrompt)
                                    .timestamp(vc.getCredentialSubject().getTimestamp())
                                    .channel(vc.getCredentialSubject().getChannel())
                                    .deviceFingerprint(vc.getCredentialSubject().getDeviceFingerprint())
                                    .build())
                            .issuer(vc.getIssuer())
                            .issuanceDate(vc.getIssuanceDate())
                            .expirationDate(vc.getExpirationDate())
                            .proof(vc.getProof())
                            .build();
                    
                    logger.debug("Prompt decrypted successfully");
                    return decryptedVc;
                } catch (Exception e) {
                    logger.warn("Failed to decrypt prompt, using encrypted value: {}", e.getMessage());
                }
            }
            
            return vc;
        } catch (java.text.ParseException e) {
            logger.error("Failed to parse evidence VC JWT", e);
            throw OAuth2TokenException.invalidGrant("Invalid evidence VC format: " + e.getMessage());
        } catch (VcVerificationException e) {
            logger.error("Evidence VC verification failed: {}", e.getMessage());
            throw OAuth2TokenException.invalidGrant("Evidence VC verification failed: " + e.getMessage());
        }
    }

    /**
     * Builds AuditTrail from PAR claims and verified VC.
     *
     * @param parClaims the PAR claims
     * @param verifiedVc the verified VerifiableCredential (may be null)
     * @return the built AuditTrail
     */
    private AuditTrail buildAuditTrail(ParJwtClaims parClaims, VerifiableCredential verifiedVc) {

        String originalPromptText = null;
        if (verifiedVc != null && verifiedVc.getCredentialSubject() != null) {
            originalPromptText = verifiedVc.getCredentialSubject().getPrompt();
        }

        String renderedOperationText = buildRenderedText(parClaims, verifiedVc);
        String semanticExpansionLevel = "low";
        String userAcknowledgeTimestamp = Instant.now().toString();
        String consentInterfaceVersion = "1.0";

        return AuditTrail.builder()
                .originalPromptText(originalPromptText)
                .renderedOperationText(renderedOperationText)
                .semanticExpansionLevel(semanticExpansionLevel)
                .userAcknowledgeTimestamp(userAcknowledgeTimestamp)
                .consentInterfaceVersion(consentInterfaceVersion)
                .build();
    }

    /**
     * Gets the default token expiration time.
     *
     * @return the expiration time in seconds
     */
    public long getDefaultTokenExpirationSeconds() {
        return defaultTokenExpirationSeconds;
    }

    /**
     * Creates and stores a binding instance.
     * <p>
     * This method creates a BindingInstance from the agent identity and binding proposal,
     * then stores it in the BindingInstanceStore. This enables two-layer identity verification
     * by maintaining a persistent record of the user-workload binding relationship.
     * </p>
     *
     * @param agentIdentity the agent identity
     * @param createdAt the creation timestamp
     * @param expiresAt the expiration timestamp
     * @param workloadIdentity the workload identity
     */
    private void createAndStoreBindingInstance(
            AgentIdentity agentIdentity,
            Instant createdAt,
            Instant expiresAt,
            String workloadIdentity
    ) {
        
        // Extract user identity from agent_identity.issuedTo field
        // Format: "issuer|userId", we need only the userId part
        String issuedTo = agentIdentity.getIssuedTo();
        String userIdentity = extractUserIdFromIssuedTo(issuedTo);

        // Build binding instance
        BindingInstance bindingInstance = BindingInstance.builder()
                .bindingInstanceId(agentIdentity.getId())
                .userIdentity(userIdentity)
                .workloadIdentity(workloadIdentity)
                .agentIdentity(agentIdentity)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .build();

        // Store binding instance
        try {
            bindingInstanceStore.store(bindingInstance);
            logger.info("Successfully stored binding instance: {} for user: {} and workload: {}",
                    bindingInstance.getBindingInstanceId(),
                    userIdentity,
                    workloadIdentity);
        } catch (Exception e) {
            logger.error("Failed to store binding instance: {}", bindingInstance.getBindingInstanceId(), e);
            // Log error but don't throw exception to avoid breaking token generation
        }
    }

    /**
     * Extracts user ID from the issuedTo field.
     * <p>
     * The issuedTo field format is "issuer|userId". This method extracts the userId part.
     * </p>
     *
     * @param issuedTo the issuedTo field value
     * @return the user ID
     */
    private String extractUserIdFromIssuedTo(String issuedTo) {
        // Check if issuedTo is null or empty
        if (ValidationUtils.isNullOrEmpty(issuedTo)) {
            return "";
        }
        
        // Split by "|" and return the second part (userId)
        String[] parts = issuedTo.split("\\|");
        if (parts.length >= 2) {
            return parts[1];
        }
        
        // If no "|" found, return the entire string as user ID (fallback)
        return issuedTo;
    }

    /**
     * Extracts workload identity from the Workload Identity Token (WIT).
     * <p>
     * According to draft-liu-agent-operation-authorization, the workload identity
     * is the subject claim (sub) from the WIT, which identifies the actual workload.
     * This is different from the agent_identity.id, which is the binding instance ID.
     * </p>
     *
     * @param bindingProposal the agent user binding proposal containing the WIT
     * @return the workload identity from the WIT's sub claim, or null if not available
     */
    private String extractWorkloadIdentityFromWit(AgentUserBindingProposal bindingProposal) {
        if (bindingProposal == null || bindingProposal.getAgentWorkloadToken() == null) {
            logger.warn("No WIT available in binding proposal");
            return null;
        }

        try {
            String witJwt = bindingProposal.getAgentWorkloadToken();
            SignedJWT signedJwt = SignedJWT.parse(witJwt);
            String workloadIdentity = signedJwt.getJWTClaimsSet().getSubject();

            if (!ValidationUtils.isNullOrEmpty(workloadIdentity)) {
                logger.info("Extracted workload identity from WIT: {}", workloadIdentity);
                return workloadIdentity;
            } else {
                logger.warn("WIT sub claim is empty");
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to extract workload identity from WIT", e);
            return null;
        }
    }

    /**
     * Builds References from PAR claims.
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 4, the references claim
     * contains optional references to related proposals or other resources. The relatedProposalId
     * field references the original PAR-JWT's JTI (JWT ID), establishing a traceable link
     * between the authorization request and the issued access token.
     * </p>
     * <p>
     * <b>Format Conversion:</b> The PAR-JWT's jti may be in plain UUID format (e.g., "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
     * but the relatedProposalId in the AOAT MUST be in URN UUID format (e.g., "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890")
     * as specified in the protocol. This method automatically converts the format if needed.
     * </p>
     * <p>
     * This linkage enables:
     * </p>
     * <ul>
     *   <li>End-to-end auditability from authorization request to token issuance</li>
     *   <li>Verification that the token corresponds to a specific approved proposal</li>
     *   <li>Support for compliance and regulatory requirements</li>
     * </ul>
     *
     * @param parClaims the PAR claims
     * @return the built References, or null if no proposal ID is available
     */
    private References buildReferences(ParJwtClaims parClaims) {
        if (parClaims == null) {
            return null;
        }

        String proposalId = parClaims.getJwtId();
        if (proposalId == null || proposalId.isEmpty()) {
            logger.debug("No proposal ID (jti) found in PAR claims, skipping references claim");
            return null;
        }

        // Convert to URN UUID format if not already in that format
        // The protocol requires relatedProposalId to be in URN UUID format (urn:uuid:...)
        String relatedProposalId = proposalId;
        if (!proposalId.startsWith("urn:uuid:")) {
            relatedProposalId = "urn:uuid:" + proposalId;
            logger.debug("Converting proposal ID from plain UUID to URN UUID format: {} -> {}", proposalId, relatedProposalId);
        }

        logger.info("Building references with proposal ID: {}", relatedProposalId);
        return References.builder()
                .relatedProposalId(relatedProposalId)
                .build();
    }
}
