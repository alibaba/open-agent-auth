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

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AapParJwtParser Tests")
class AapParJwtParserTest {

    private static final String HMAC_SECRET = "super-secret-key-that-is-at-least-256-bits-long!!";

    private AapParJwtParser parser;

    @BeforeEach
    void setUp() {
        parser = new AapParJwtParser();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create parser instance")
        void shouldCreateParserInstance() {
            // Act
            AapParJwtParser newParser = new AapParJwtParser();

            // Assert
            assertThat(newParser).isNotNull();
        }
    }

    @Nested
    @DisplayName("Parse Tests")
    class ParseTests {

        @Test
        @DisplayName("Should parse valid JWT successfully")
        void shouldParseValidJwtSuccessfully() throws JOSEException {
            // Arrange
            Date now = new Date();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .audience("client123")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600000))
                .jwtID("jwt-id-123")
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getIssuer()).isEqualTo("https://example.com");
            assertThat(result.getSubject()).isEqualTo("user123");
            assertThat(result.getJwtId()).isEqualTo("jwt-id-123");
        }

        @Test
        @DisplayName("Should throw NullPointerException when JWT string is null")
        void shouldThrowNullPointerExceptionWhenJwtStringIsNull() {
            // Act & Assert - SignedJWT.parse(null) throws NPE which is not caught
            // by the ParseException catch block in the source code
            org.junit.jupiter.api.Assertions.assertThrows(
                    NullPointerException.class,
                    () -> parser.parse(null)
            );
        }

        @Test
        @DisplayName("Should return null when JWT string is empty")
        void shouldReturnNullWhenJwtStringIsEmpty() {
            // Act
            ParJwtClaims result = parser.parse("");

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return null when JWT is invalid")
        void shouldReturnNullWhenJwtIsInvalid() {
            // Arrange
            String invalidJwt = "invalid.jwt.string";

            // Act
            ParJwtClaims result = parser.parse(invalidJwt);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should parse JWT with evidence claim")
        void shouldParseJwtWithEvidenceClaim() throws JOSEException {
            // Arrange
            Map<String, Object> evidenceMap = new HashMap<>();
            evidenceMap.put("type", "user_input");
            evidenceMap.put("data", "test data");

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .claim("evidence", evidenceMap)
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should parse JWT with agent_user_binding_proposal claim")
        void shouldParseJwtWithAgentUserBindingProposalClaim() throws JOSEException {
            // Arrange
            Map<String, Object> proposalMap = new HashMap<>();
            proposalMap.put("binding_type", "delegation");

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .claim("agent_user_binding_proposal", proposalMap)
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should parse JWT with agent_operation_proposal claim")
        void shouldParseJwtWithAgentOperationProposalClaim() throws JOSEException {
            // Arrange
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .claim("agent_operation_proposal", "allow if user.is_admin")
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getOperationProposal()).isEqualTo("allow if user.is_admin");
        }

        @Test
        @DisplayName("Should parse JWT with context claim")
        void shouldParseJwtWithContextClaim() throws JOSEException {
            // Arrange
            Map<String, Object> contextMap = new HashMap<>();
            contextMap.put("request_id", "req-123");

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .claim("context", contextMap)
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle null optional claims gracefully")
        void shouldHandleNullOptionalClaimsGracefully() throws JOSEException {
            // Arrange
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("user123")
                .build();

            String jwtString = createSignedJwtString(claimsSet);

            // Act
            ParJwtClaims result = parser.parse(jwtString);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getEvidence()).isNull();
            assertThat(result.getAgentUserBindingProposal()).isNull();
            assertThat(result.getOperationProposal()).isNull();
            assertThat(result.getContext()).isNull();
        }
    }

    /**
     * Creates a properly signed JWT string using HMAC-SHA256.
     * The parser uses SignedJWT.parse() which requires a valid signed JWT format.
     */
    private String createSignedJwtString(JWTClaimsSet claimsSet) throws JOSEException {
        JWSSigner signer = new MACSigner(HMAC_SECRET);
        SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJwt.sign(signer);
        return signedJwt.serialize();
    }
}