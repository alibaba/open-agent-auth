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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.JwkConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Map;

/**
 * Parser for Workload Identity Tokens (WIT) following the WIMSE protocol.
 * <p>
 * This class is responsible for converting signed JWT strings into structured
 * {@link WorkloadIdentityToken} objects. It handles the extraction and conversion
 * of all WIT claims including standard JWT claims (iss, sub, exp, jti), the
 * confirmation claim (cnf) containing the public key, and custom claims such
 * as agent_identity.
 * </p>
 * <p>
 * The parsing process follows these steps:
 * </p>
 * <ol>
 *   <li>Extract JWT claims from the signed JWT</li>
 *   <li>Parse the confirmation (cnf) claim to extract the public key</li>
 *   <li>Parse the agent_identity claim if present</li>
 *   <li>Build the structured WorkloadIdentityToken object</li>
 * </ol>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol-07.html">draft-ietf-wimse-s2s-protocol-07</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 */
public class WitParser {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WitParser.class);

    /**
     * Parses a WIT from a signed JWT.
     * <p>
     * This method extracts all claims from the JWT and constructs a structured
     * {@link WorkloadIdentityToken} object. It validates the input and provides
     * detailed error messages if parsing fails.
     * </p>
     *
     * @param signedJwt the signed JWT to parse
     * @return a WorkloadIdentityToken object
     * @throws ParseException if parsing fails due to invalid JWT structure or claims
     * @throws IllegalArgumentException if signedJwt is null
     */
    public WorkloadIdentityToken parse(SignedJWT signedJwt) throws ParseException {

        // Validate input
        // Validate input
        ValidationUtils.validateNotNull(signedJwt, "Signed JWT");

        logger.debug("Parsing Workload Identity Token");

        // Extract JWT claims
        var claims = signedJwt.getJWTClaimsSet();

        // Parse confirmation claim (cnf) - contains the public key for WPT verification
        WorkloadIdentityToken.Claims.Confirmation confirmation = parseConfirmationClaim(claims);

        // Build structured WIT object
        WorkloadIdentityToken wit = buildWorkloadIdentityToken(signedJwt, claims, confirmation);

        logger.debug("Successfully parsed WIT with subject: {}", wit.getSubject());
        return wit;
    }

    /**
     * Parses the confirmation (cnf) claim from the JWT claims set.
     * <p>
     * The confirmation claim contains the public key (JWK) that will be used
     * to verify Workload Proof Tokens (WPTs). This claim is REQUIRED according
     * to the WIMSE specification.
     * </p>
     *
     * @param claims the JWT claims set
     * @return the confirmation object, or null if not present
     * @throws ParseException if the cnf claim is malformed
     */
    private WorkloadIdentityToken.Claims.Confirmation parseConfirmationClaim(JWTClaimsSet claims) throws ParseException {

        // Extract cnf claim
        Map<String, Object> cnfClaim = claims.getJSONObjectClaim("cnf");

        // cnf claim is optional in the parser, but required for WPT verification
        if (cnfClaim == null) {
            logger.debug("WIT does not contain cnf claim");
            return null;
        }

        // Validate cnf.jwk
        if (!cnfClaim.containsKey("jwk")) {
            throw new ParseException("cnf claim missing required 'jwk' field", 0);
        }

        try {
            // Extract JWK map
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnfClaim.get("jwk");

            // Validate JWK structure
            JWK.parse(jwkMap);

            // Convert to our Jwk model
            Jwk jwkModel = JwkConverter.convertMapToJwk(jwkMap);

            // Build confirmation object
            return WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(jwkModel)
                    .build();

        } catch (Exception e) {
            throw new ParseException("Failed to parse cnf.jwk claim: " + e.getMessage(), 0);
        }
    }

    /**
     * Builds a structured WorkloadIdentityToken object from parsed components.
     *
     * @param signedJwt the signed JWT
     * @param claims the JWT claims set
     * @param confirmation the parsed confirmation claim
     * @return a WorkloadIdentityToken object
     */
    private WorkloadIdentityToken buildWorkloadIdentityToken(
            SignedJWT signedJwt,
            JWTClaimsSet claims,
            WorkloadIdentityToken.Claims.Confirmation confirmation
    ) {

        // Build claims
        WorkloadIdentityToken.Claims.ClaimsBuilder claimsBuilder = WorkloadIdentityToken.Claims.builder()
                .issuer(claims.getIssuer())
                .subject(claims.getSubject())
                .expirationTime(claims.getExpirationTime())
                .jwtId(claims.getJWTID())
                .confirmation(confirmation);

        // Build header
        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm(signedJwt.getHeader().getAlgorithm().getName())
                .build();

        // Serialize the JWT to preserve the original JWT string
        String jwtString;
        try {
            jwtString = signedJwt.serialize();
        } catch (Exception e) {
            logger.error("Failed to serialize WIT JWT", e);
            jwtString = null;
        }

        // Build WIT
        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claimsBuilder.build())
                .jwtString(jwtString)
                .build();
    }

}