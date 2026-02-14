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
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serializer for Workload Proof Tokens (WPT).
 * <p>
 * This class provides methods to convert structured {@link WorkloadProofToken} objects
 * into their JWT string representations. This is useful for transmission or storage.
 * </p>
 * <p>
 * The serialization process reconstructs the JWT from the structured object's header and claims,
 * ensuring that the resulting JWT string matches the original format used when the token was created.
 * </p>
 * <p>
 * According to draft-ietf-wimse-wpt, the WPT claims include:
 * </p>
 * <ul>
 *   <li><b>exp</b>: Expiration time (REQUIRED)</li>
 *   <li><b>jti</b>: JWT ID (REQUIRED)</li>
 *   <li><b>wth</b>: Workload Identity Token hash (REQUIRED)</li>
 *   <li><b>ath</b>: Access Token hash (OPTIONAL)</li>
 *   <li><b>tth</b>: Transaction Token hash (OPTIONAL)</li>
 *   <li><b>oth</b>: Other Tokens hashes (OPTIONAL)</li>
 * </ul>
 * <p>
 * Note that WPT does NOT include iss (issuer) or sub (subject) claims.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a>
 */
public class WptSerializer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WptSerializer.class);

    /**
     * Serializes and signs a WorkloadProofToken object to a JWT string.
     * <p>
     * This method builds a JWSObject from the structured WorkloadProofToken,
     * signs it using the provided signer, and returns the serialized JWT string.
     * This approach follows the natural JWT flow of "build → sign → serialize"
     * and eliminates the need for manual string concatenation.
     * </p>
     *
     * @param wpt the WorkloadProofToken object to serialize and sign
     * @param signer the JWSSigner to use for signing
     * @return the signed JWT string representation
     * @throws JOSEException if serialization or signing fails
     */
    public static String serialize(WorkloadProofToken wpt, JWSSigner signer) throws JOSEException {

        // Validate arguments
        ValidationUtils.validateNotNull(wpt, "WorkloadProofToken");
        ValidationUtils.validateNotNull(signer, "JWSSigner");

        try {
            // Build JWSObject from the structured WPT
            JWSObject jwsObject = buildJWSObject(wpt);

            // Sign the JWSObject
            jwsObject.sign(signer);

            // Serialize and return the signed JWT string
            return jwsObject.serialize();

        } catch (Exception e) {
            logger.error("Failed to serialize and sign WorkloadProofToken to JWT string", e);
            throw new JOSEException("Failed to serialize and sign WorkloadProofToken to JWT string", e);
        }
    }

    /**
     * Builds a JWSObject from the structured WorkloadProofToken.
     *
     * @param wpt the WorkloadProofToken object
     * @return the JWSObject ready for signing
     * @throws JOSEException if building fails
     */
    private static JWSObject buildJWSObject(WorkloadProofToken wpt) throws JOSEException {
        try {
            // Build JWSHeader from WPT header
            JWSHeader header = new JWSHeader.Builder(
                    new JWSAlgorithm(wpt.getHeader().getAlgorithm()))
                    .type(new JOSEObjectType(wpt.getHeader().getType()))
                    .build();

            // Build JWTClaimsSet from WPT claims
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .expirationTime(wpt.getClaims().getExpirationTime())
                    .jwtID(wpt.getClaims().getJwtId())
                    .claim("wth", wpt.getClaims().getWorkloadTokenHash());

            // Add optional claims
            if (wpt.getClaims().getAudience() != null) {
                claimsBuilder.audience(wpt.getClaims().getAudience());
            }
            if (wpt.getClaims().getAccessTokenHash() != null) {
                claimsBuilder.claim("ath", wpt.getClaims().getAccessTokenHash());
            }
            if (wpt.getClaims().getTransactionTokenHash() != null) {
                claimsBuilder.claim("tth", wpt.getClaims().getTransactionTokenHash());
            }
            if (wpt.getClaims().getOtherTokenHashes() != null) {
                claimsBuilder.claim("oth", wpt.getClaims().getOtherTokenHashes());
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create JWSObject with header and payload
            return new JWSObject(header, new Payload(claimsSet.toJSONObject()));

        } catch (Exception e) {
            logger.error("Failed to build JWSObject from WPT", e);
            throw new JOSEException("Failed to build JWSObject from WPT", e);
        }
    }
}