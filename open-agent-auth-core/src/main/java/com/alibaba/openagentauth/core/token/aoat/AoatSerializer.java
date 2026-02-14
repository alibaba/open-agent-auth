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
package com.alibaba.openagentauth.core.token.aoat;

import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

/**
 * Serializer for Agent Operation Authorization Tokens (AOAT).
 * <p>
 * This class provides methods to convert structured {@link AgentOperationAuthToken} objects
 * into their JWT string representations. This is useful for computing hashes, storing tokens,
 * or transmitting them over the network.
 * </p>
 * <p>
 * The serialization process reconstructs the JWT from the structured object's header and claims,
 * ensuring that the resulting JWT string matches the original format used when the token was created.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
public class AoatSerializer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AoatSerializer.class);

    /**
     * Serializes and signs an AgentOperationAuthToken object to a JWT string.
     * <p>
     * This method builds a JWSObject from the structured AgentOperationAuthToken,
     * signs it using the provided signer, and returns the serialized JWT string.
     * This approach follows the natural JWT flow of "build → sign → serialize"
     * and eliminates the need for manual string concatenation.
     * </p>
     *
     * @param token the AgentOperationAuthToken object to serialize and sign
     * @param signer the JWSSigner to use for signing
     * @param algorithm the JWS algorithm to use (e.g., RS256)
     * @param signingKey the RSA signing key to extract kid from
     * @return the signed JWT string representation
     * @throws JOSEException if serialization or signing fails
     */
    public static String serialize(AgentOperationAuthToken token, JWSSigner signer, JWSAlgorithm algorithm, RSAKey signingKey) throws JOSEException {

        // Validate arguments
        ValidationUtils.validateNotNull(token, "AgentOperationAuthToken");
        ValidationUtils.validateNotNull(signer, "JWSSigner");
        ValidationUtils.validateNotNull(algorithm, "JWSAlgorithm");

        try {
            // Build JWSObject from the structured token
            JWSObject jwsObject = buildJWSObject(token, algorithm, signingKey);

            // Sign the JWSObject
            jwsObject.sign(signer);

            // Serialize and return the signed JWT string
            return jwsObject.serialize();

        } catch (Exception e) {
            logger.error("Failed to serialize and sign AgentOperationAuthToken to JWT string", e);
            throw new JOSEException("Failed to serialize and sign AgentOperationAuthToken to JWT string", e);
        }
    }

    /**
     * Builds a JWSObject from the structured AgentOperationAuthToken.
     *
     * @param token the AgentOperationAuthToken object
     * @param algorithm the JWS algorithm to use
     * @param signingKey the RSA signing key to extract kid from
     * @return the JWSObject ready for signing
     * @throws JOSEException if building fails
     */
    private static JWSObject buildJWSObject(AgentOperationAuthToken token, JWSAlgorithm algorithm, RSAKey signingKey) throws JOSEException {
        try {
            // Build JWSHeader with the provided algorithm and kid from the signing key
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm)
                    .type(new JOSEObjectType("JWT"));
            
            // Set key ID from the signing key if available
            if (signingKey != null && signingKey.getKeyID() != null) {
                headerBuilder.keyID(signingKey.getKeyID());
                logger.debug("Set kid from signing key: {}", signingKey.getKeyID());
            }
            
            JWSHeader header = headerBuilder.build();

            // Build JWTClaimsSet from token claims
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(token.getIssuer())
                    .subject(token.getSubject())
                    .audience(token.getAudience())
                    .issueTime(token.getIssuedAt() != null ? Date.from(token.getIssuedAt()) : null)
                    .expirationTime(token.getExpirationTime() != null ? Date.from(token.getExpirationTime()) : null)
                    .jwtID(token.getJwtId());

            // Add agent_identity claim (REQUIRED)
            if (token.getAgentIdentity() != null) {
                claimsBuilder.claim("agent_identity", JwtClaimConverter.convertAgentIdentityToMap(token.getAgentIdentity()));
            }

            // Add agent_operation_authorization claim (REQUIRED)
            if (token.getAuthorization() != null) {
                claimsBuilder.claim("agent_operation_authorization", JwtClaimConverter.convertAuthorizationToMap(token.getAuthorization()));
            }

            // Add optional claims if present
            if (token.getEvidence() != null) {
                claimsBuilder.claim("evidence", JwtClaimConverter.convertEvidenceToMap(token.getEvidence()));
            }

            if (token.getContext() != null) {
                claimsBuilder.claim("context", JwtClaimConverter.convertAuthorizationContextToMap(token.getContext()));
            }

            if (token.getAuditTrail() != null) {
                claimsBuilder.claim("audit_trail", JwtClaimConverter.convertAuditTrailToMap(token.getAuditTrail()));
            }

            if (token.getReferences() != null) {
                claimsBuilder.claim("references", JwtClaimConverter.convertReferencesToMap(token.getReferences()));
            }

            List<DelegationChain> delegationChain = token.getDelegationChain();
            if (delegationChain != null && !delegationChain.isEmpty()) {
                claimsBuilder.claim("delegation_chain", JwtClaimConverter.convertDelegationChainListToMap(delegationChain));
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create JWSObject with header and payload
            return new JWSObject(header, new Payload(claimsSet.toJSONObject()));

        } catch (Exception e) {
            logger.error("Failed to build JWSObject from AgentOperationAuthToken", e);
            throw new JOSEException("Failed to build JWSObject from AgentOperationAuthToken", e);
        }
    }

}