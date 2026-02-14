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
package com.alibaba.openagentauth.core.protocol.oauth2.par.jwt;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Map;

/**
 * Parser for PAR-JWT claims without validation.
 * <p>
 * This class provides a lightweight way to parse PAR-JWT and extract claims
 * without performing signature verification or other validation checks.
 * It is intended for display purposes when the PAR-JWT has already been
 * validated during the PAR submission phase.
 * </p>
 */
public class AapParJwtParser {

    private static final Logger logger = LoggerFactory.getLogger(AapParJwtParser.class);

    /**
     * Parses a PAR-JWT and extracts claims without validation.
     *
     * @param parJwt the JWT string representing the PAR-JWT
     * @return a ParJwtClaims containing the extracted claims, or null if parsing fails
     */
    public ParJwtClaims parse(String parJwt) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(parJwt);
            return extractClaims(signedJwt);
        } catch (ParseException e) {
            logger.error("Error parsing PAR-JWT for claims extraction", e);
            return null;
        }
    }

    /**
     * Extracts the claims from a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ParJwtClaims containing the extracted claims
     */
    private ParJwtClaims extractClaims(SignedJWT signedJwt) throws ParseException {
        var claimsSet = signedJwt.getJWTClaimsSet();

        return ParJwtClaims.builder()
                .issuer(claimsSet.getIssuer())
                .subject(claimsSet.getSubject())
                .audience(claimsSet.getAudience())
                .issueTime(claimsSet.getIssueTime())
                .expirationTime(claimsSet.getExpirationTime())
                .jwtId(claimsSet.getJWTID())
                .evidence(extractEvidence(claimsSet))
                .agentUserBindingProposal(extractAgentUserBindingProposal(claimsSet))
                .operationProposal(extractOperationProposal(claimsSet))
                .context(extractContext(claimsSet))
                .build();
    }

    /**
     * Extracts the evidence from a PAR-JWT.
     *
     * @param claimsSet the JWT claims set
     * @return an Evidence containing the extracted evidence
     */
    private Evidence extractEvidence(JWTClaimsSet claimsSet) {
        Object evidenceClaim = claimsSet.getClaim("evidence");
        if (evidenceClaim instanceof Map) {
            try {
                return JwtClaimConverter.convertMapToEvidence(evidenceClaim);
            } catch (Exception e) {
                logger.warn("Failed to convert evidence claim to Evidence object", e);
            }
        }
        return null;
    }

    /**
     * Extracts the agent user binding proposal from a PAR-JWT.
     *
     * @param claimsSet the JWT claims set
     * @return an AgentUserBindingProposal containing the extracted agent user binding proposal
     */
    private AgentUserBindingProposal extractAgentUserBindingProposal(JWTClaimsSet claimsSet) {
        Object proposalClaim = claimsSet.getClaim("agent_user_binding_proposal");
        if (proposalClaim instanceof Map) {
            try {
                return JwtClaimConverter.convertMapToAgentUserBindingProposal(proposalClaim);
            } catch (Exception e) {
                logger.warn("Failed to convert agent_user_binding_proposal claim to AgentUserBindingProposal object", e);
            }
        }
        return null;
    }

    /**
     * Extracts the agent operation proposal from a PAR-JWT.
     *
     * @param claimsSet the JWT claims set
     * @return an AgentOperationProposal containing the extracted agent operation proposal
     */
    private String extractOperationProposal(JWTClaimsSet claimsSet) {
        Object proposalClaim = claimsSet.getClaim("agent_operation_proposal");
        if (proposalClaim instanceof String) {
            return (String) proposalClaim;
        }
        return null;
    }

    /**
     * Extracts the operation request context from a PAR-JWT.
     *
     * @param claimsSet the JWT claims set
     * @return an OperationRequestContext containing the extracted operation request context
     */
    private OperationRequestContext extractContext(JWTClaimsSet claimsSet) {
        Object contextClaim = claimsSet.getClaim("context");
        if (contextClaim instanceof Map) {
            try {
                return JwtClaimConverter.convertMapToOperationRequestContext(contextClaim);
            } catch (Exception e) {
                logger.warn("Failed to convert context claim to OperationRequestContext object", e);
            }
        }
        return null;
    }
}
