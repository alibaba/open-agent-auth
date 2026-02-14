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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;

/**
 * Adapter that bridges {@link TokenGenerator} and {@link AoatTokenGenerator}.
 * <p>
 * This class adapts the AOAT token generation logic to work with the standard
 * OAuth 2.0 token generation interface, allowing the OAuth2TokenServer to
 * delegate token generation without knowing about AOAT-specific details.
 * </p>
 *
 * @since 1.0
 */
public class AoatTokenGeneratorAdapter implements TokenGenerator {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AoatTokenGeneratorAdapter.class);

    /**
     * The AOAT token generator.
     */
    private final AoatTokenGenerator aoatTokenGenerator;

    /**
     * The PAR server for retrieving authorization requests.
     */
    private final OAuth2ParServer OAuth2ParServer;

    /**
     * Creates a new AoatTokenGeneratorAdapter.
     *
     * @param aoatTokenGenerator the AOAT token generator
     * @param OAuth2ParServer the PAR server
     */
    public AoatTokenGeneratorAdapter(AoatTokenGenerator aoatTokenGenerator, OAuth2ParServer OAuth2ParServer) {
        this.aoatTokenGenerator = aoatTokenGenerator;
        this.OAuth2ParServer = OAuth2ParServer;
        logger.info("AoatTokenGeneratorAdapter initialized");
    }

    @Override
    public String generateToken(AuthorizationCode authCode, TokenRequest request) {
        logger.info("Generating AOAT token for code: {}", authCode.getCode());

        try {
            // Step 1: Retrieve PAR request
            ParRequest parRequest = OAuth2ParServer.retrieveRequest(authCode.getRequestUri());
            if (parRequest == null) {
                logger.error("PAR request not found for request_uri: {}", authCode.getRequestUri());
                throw OAuth2TokenException.invalidGrant("Original authorization request not found");
            }

            // Step 2: Extract PAR claims
            ParJwtClaims parClaims = extractParClaims(parRequest);

            // Step 3: Generate AOAT
            AgentOperationAuthToken aoat = aoatTokenGenerator.generateAoat(authCode.getSubject(), parClaims);

            logger.info("AOAT token generated successfully: {}", aoat.getJwtId());
            return aoat.getJwtString();

        } catch (JOSEException e) {
            logger.error("Failed to generate AOAT token", e);
            throw OAuth2TokenException.serverError("Failed to generate access token: " + e.getMessage(), e);
        }
    }

    @Override
    public long getExpirationSeconds() {
        // Delegate to the AOAT token generator
        if (aoatTokenGenerator instanceof DefaultAoatTokenGenerator) {
            return ((DefaultAoatTokenGenerator) aoatTokenGenerator).getDefaultTokenExpirationSeconds();
        }
        return 3600; // Default expiration
    }

    /**
     * Extracts PAR claims from the PAR request.
     *
     * @param parRequest the PAR request
     * @return the extracted PAR claims
     * @throws OAuth2TokenException if extraction fails
     */
    private ParJwtClaims extractParClaims(ParRequest parRequest) {
        String requestJwt = parRequest.getRequestJwt();
        if (ValidationUtils.isNullOrEmpty(requestJwt)) {
            logger.error("PAR request does not contain JWT");
            throw OAuth2TokenException.invalidGrant("Missing authorization request JWT");
        }

        try {
            SignedJWT signedJwt = SignedJWT.parse(requestJwt);
            JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();

            // Extract standard JWT claims
            String issuer = claimsSet.getIssuer();
            String subject = claimsSet.getSubject();
            java.util.List<String> audience = claimsSet.getAudience();
            java.util.Date issueTime = claimsSet.getIssueTime();
            java.util.Date expirationTime = claimsSet.getExpirationTime();
            String jwtId = claimsSet.getJWTID();

            // Extract custom claims
            Evidence evidence = extractEvidenceClaim(claimsSet);
            AgentUserBindingProposal bindingProposal = extractBindingProposalClaim(claimsSet);
            String operationProposal = extractOperationProposalClaim(claimsSet);
            OperationRequestContext context = extractContextClaim(claimsSet);

            return ParJwtClaims.builder()
                    .issuer(issuer)
                    .subject(subject)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(jwtId)
                    .evidence(evidence)
                    .agentUserBindingProposal(bindingProposal)
                    .operationProposal(operationProposal)
                    .context(context)
                    .build();

        } catch (ParseException e) {
            logger.error("Failed to parse PAR JWT", e);
            throw OAuth2TokenException.invalidGrant("Invalid authorization request JWT format");
        }
    }

    /**
     * Extracts the evidence claim from JWT claims set.
     */
    private Evidence extractEvidenceClaim(JWTClaimsSet claimsSet) {
        try {
            Object evidenceObj = claimsSet.getClaim("evidence");
            if (evidenceObj == null) {
                return null;
            }

            // Use JwtClaimConverter for proper conversion
            return JwtClaimConverter.convertMapToEvidence(evidenceObj);

        } catch (Exception e) {
            logger.error("Failed to extract evidence claim", e);
            return null;
        }
    }

    /**
     * Extracts the agent user binding proposal claim from JWT claims set.
     */
    private AgentUserBindingProposal extractBindingProposalClaim(JWTClaimsSet claimsSet) {
        try {
            Object bindingObj = claimsSet.getClaim("agent_user_binding_proposal");
            if (bindingObj == null) {
                return null;
            }

            // Use JwtClaimConverter for proper conversion
            return JwtClaimConverter.convertMapToAgentUserBindingProposal(bindingObj);

        } catch (Exception e) {
            logger.error("Failed to extract agent user binding proposal claim", e);
            return null;
        }
    }

    /**
     * Extracts the agent operation proposal claim from JWT claims set.
     */
    private String extractOperationProposalClaim(JWTClaimsSet claimsSet) {
        try {
            Object proposalObj = claimsSet.getClaim("agent_operation_proposal");
            if (proposalObj == null) {
                return null;
            }
            return proposalObj.toString();
        } catch (Exception e) {
            logger.error("Failed to extract agent operation proposal claim", e);
            return null;
        }
    }

    /**
     * Extracts the context claim from JWT claims set.
     */
    private OperationRequestContext extractContextClaim(JWTClaimsSet claimsSet) {
        try {
            Object contextObj = claimsSet.getClaim("context");
            logger.info("extractContextClaim called - contextObj: {}, type: {}", 
                       contextObj != null ? contextObj.toString() : "null",
                       contextObj != null ? contextObj.getClass().getName() : "null");
            
            if (contextObj == null) {
                logger.warn("Context claim is null in JWT claims set");
                return null;
            }

            // Use JwtClaimConverter for proper conversion
            OperationRequestContext context = JwtClaimConverter.convertMapToOperationRequestContext(contextObj);
            logger.info("Extracted context - agent: {}", 
                       context.getAgent() != null ? context.getAgent().toString() : "null");
            return context;

        } catch (Exception e) {
            logger.error("Failed to extract context claim", e);
            return null;
        }
    }
}