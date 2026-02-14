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

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;

/**
 * Parser for Agent Operation Authorization Tokens (AOAT) following the draft-liu-agent-operation-authorization specification.
 * <p>
 * This class is responsible for converting signed JWT strings into structured
 * {@link AgentOperationAuthToken} objects. It handles the extraction and conversion
 * of all AOAT claims including standard JWT claims (iss, sub, aud, iat, exp, jti),
 * required claims (agent_identity, agent_operation_authorization), and optional claims
 * (evidence, context, auditTrail, references, delegation_chain).
 * </p>
 * <p>
 * The parsing process follows these steps:
 * </p>
 * <ol>
 *   <li>Extract JWT claims from the signed JWT</li>
 *   <li>Parse standard JWT claims (iss, sub, aud, iat, exp, jti)</li>
 *   <li>Parse required claims (agent_identity, agent_operation_authorization)</li>
 *   <li>Parse optional claims (evidence, context, auditTrail, references, delegation_chain)</li>
 *   <li>Build the structured AgentOperationAuthToken object with header</li>
 * </ol>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
public class AoatParser {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AoatParser.class);

    /**
     * Parses an AOAT from a signed JWT.
     * <p>
     * This method extracts all claims from the JWT and constructs a structured
     * {@link AgentOperationAuthToken} object. It validates the input and provides
     * detailed error messages if parsing fails.
     * </p>
     *
     * @param signedJwt the signed JWT to parse
     * @return an AgentOperationAuthToken object
     * @throws ParseException if parsing fails due to invalid JWT structure or claims
     * @throws IllegalArgumentException if signedJwt is null
     */
    public AgentOperationAuthToken parse(SignedJWT signedJwt) throws ParseException {

        // Validate input
        // Validate input
        ValidationUtils.validateNotNull(signedJwt, "Signed JWT");

        logger.debug("Parsing Agent Operation Authorization Token");

        // Extract JWT claims
        JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();

        // Build structured AOAT object using JwtClaimConverter
        AgentOperationAuthToken.Claims claims = JwtClaimConverter.convertJwtClaimsSetToAoatClaims(claimsSet);

        // Build header from signed JWT
        AgentOperationAuthToken.Header header = AgentOperationAuthToken.Header.builder()
                .type("JWT")
                .algorithm(signedJwt.getHeader().getAlgorithm().getName())
                .build();

        // Build AOAT with header and claims
        AgentOperationAuthToken aoat = AgentOperationAuthToken.builder()
                .header(header)
                .claims(claims)
                .jwtString(signedJwt.serialize())
                .build();

        logger.debug("Successfully parsed AOAT with subject: {}", aoat.getSubject());
        return aoat;
    }

}