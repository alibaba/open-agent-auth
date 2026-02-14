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

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AoatParser}.
 * <p>
 * Tests cover:
 * <ul>
 *   <li>Happy path scenarios with valid tokens</li>
 *   <li>Parameter validation (null checks)</li>
 *   <li>Parsing of standard JWT claims</li>
 *   <li>Parsing of required AOAT claims</li>
 *   <li>Parsing of optional AOAT claims</li>
 *   <li>Error handling and edge cases</li>
 * </ul>
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AoatParser Tests")
class AoatParserTest {

    private AoatParser parser;
    private AoatGenerator generator;
    private RSAKey signingKey;

    @BeforeEach
    void setUp() throws JOSEException {
        parser = new AoatParser();
        
        // Generate test key
        signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        
        // Create generator for test tokens
        generator = new AoatGenerator(
                signingKey,
                JWSAlgorithm.RS256,
                "https://issuer.example.com",
                "https://audience.example.com"
        );
    }

    @Nested
    @DisplayName("Successful Parsing Tests")
    class SuccessfulParsingTests {

        @Test
        @DisplayName("Should parse valid AOAT with required claims")
        void shouldParseValidAoatWithRequiredClaims() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getSubject()).isEqualTo("user123");
            assertThat(parsedToken.getIssuer()).isEqualTo("https://issuer.example.com");
            assertThat(parsedToken.getAudience()).isEqualTo("https://audience.example.com");
            assertThat(parsedToken.getAgentIdentity()).isNotNull();
            assertThat(parsedToken.getAuthorization()).isNotNull();
            assertThat(parsedToken.getHeader()).isNotNull();
            assertThat(parsedToken.getHeader().getType()).isEqualTo("JWT");
            assertThat(parsedToken.getHeader().getAlgorithm()).isEqualTo("RS256");
            assertThat(parsedToken.getJwtString()).isNotNull();
        }

        @Test
        @DisplayName("Should parse AOAT with optional claims")
        void shouldParseAoatWithOptionalClaims() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .evidence(Evidence.builder()
                            .sourcePromptCredential("test-credential")
                            .build())
                    .context(TokenAuthorizationContext.builder()
                            .renderedText("Test operation")
                            .build())
                    .build();

            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getEvidence()).isNotNull();
            assertThat(parsedToken.getContext()).isNotNull();
            assertThat(parsedToken.getEvidence().getSourcePromptCredential()).isEqualTo("test-credential");
            assertThat(parsedToken.getContext().getRenderedText()).isEqualTo("Test operation");
        }

        @Test
        @DisplayName("Should parse AOAT with delegation chain")
        void shouldParseAoatWithDelegationChain() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .delegationChain(java.util.List.of(
                            DelegationChain.builder()
                                    .delegatorJti("delegator-jti-001")
                                    .delegatorAgentIdentity(agentIdentity)
                                    .delegationTimestamp(java.time.Instant.now())
                                    .operationSummary("Test delegation")
                                    .asSignature("test-signature")
                                    .build()
                    ))
                    .build();

            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getDelegationChain()).isNotNull();
            assertThat(parsedToken.getDelegationChain()).hasSize(1);
            assertThat(parsedToken.getDelegationChain().get(0).getDelegatorJti()).isEqualTo("delegator-jti-001");
        }

        @Test
        @DisplayName("Should preserve JWT string in parsed token")
        void shouldPreserveJwtStringInParsedToken() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String originalJwtString = token.getJwtString();
            SignedJWT signedJwt = SignedJWT.parse(originalJwtString);

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getJwtString()).isEqualTo(originalJwtString);
        }
    }

    @Nested
    @DisplayName("Standard JWT Claims Parsing Tests")
    class StandardJwtClaimsParsingTests {

        @Test
        @DisplayName("Should parse issuer claim correctly")
        void shouldParseIssuerClaimCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getIssuer()).isEqualTo("https://issuer.example.com");
        }

        @Test
        @DisplayName("Should parse subject claim correctly")
        void shouldParseSubjectClaimCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getSubject()).isEqualTo("user123");
        }

        @Test
        @DisplayName("Should parse audience claim correctly")
        void shouldParseAudienceClaimCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getAudience()).isEqualTo("https://audience.example.com");
        }

        @Test
        @DisplayName("Should parse issued at time correctly")
        void shouldParseIssuedAtTimeCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getIssuedAt()).isNotNull();
            assertThat(parsedToken.getIssuedAt()).isAfter(java.time.Instant.now().minusSeconds(10));
            assertThat(parsedToken.getIssuedAt()).isBefore(java.time.Instant.now().plusSeconds(10));
        }

        @Test
        @DisplayName("Should parse expiration time correctly")
        void shouldParseExpirationTimeCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getExpirationTime()).isNotNull();
            assertThat(parsedToken.getExpirationTime()).isAfter(java.time.Instant.now());
        }

        @Test
        @DisplayName("Should parse JWT ID correctly")
        void shouldParseJwtIdCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getJwtId()).isNotNull();
            assertThat(parsedToken.getJwtId()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Header Parsing Tests")
    class HeaderParsingTests {

        @Test
        @DisplayName("Should parse header type correctly")
        void shouldParseHeaderTypeCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getHeader()).isNotNull();
            assertThat(parsedToken.getHeader().getType()).isEqualTo("JWT");
        }

        @Test
        @DisplayName("Should parse header algorithm correctly")
        void shouldParseHeaderAlgorithmCorrectly() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken.getHeader()).isNotNull();
            assertThat(parsedToken.getHeader().getAlgorithm()).isEqualTo("RS256");
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when signed JWT is null")
        void shouldThrowExceptionWhenSignedJwtIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> parser.parse(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signed JWT");
        }

        @Test
        @DisplayName("Should throw ParseException for JWT with invalid claims")
        void shouldThrowParseExceptionForJwtWithInvalidClaims() throws JOSEException {
            // Arrange
            // Create a JWT with missing required claims (agent_identity and agent_operation_authorization)
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .build();
            
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject("test-user")
                    .issuer("https://issuer.example.com")
                    .audience("https://audience.example.com")
                    .issueTime(java.util.Date.from(java.time.Instant.now()))
                    .expirationTime(java.util.Date.from(java.time.Instant.now().plusSeconds(3600)))
                    .jwtID("test-jti")
                    .build();
            
            SignedJWT jwtWithoutRequiredClaims = new SignedJWT(header, claimsSet);
            
            // Sign the JWT
            jwtWithoutRequiredClaims.sign(new RSASSASigner(signingKey));

            // Act & Assert
            // The parser should throw IllegalArgumentException because required claims are missing
            assertThatThrownBy(() -> parser.parse(jwtWithoutRequiredClaims))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("agent_identity");
        }

        @Test
        @DisplayName("Should parse token with missing optional claims")
        void shouldParseTokenWithMissingOptionalClaims() throws JOSEException, ParseException {
            // Arrange
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            SignedJWT signedJwt = SignedJWT.parse(token.getJwtString());

            // Act
            AgentOperationAuthToken parsedToken = parser.parse(signedJwt);

            // Assert
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getEvidence()).isNull();
            assertThat(parsedToken.getContext()).isNull();
            assertThat(parsedToken.getAuditTrail()).isNull();
            assertThat(parsedToken.getReferences()).isNull();
        }
    }

    // Helper methods

    private AgentIdentity createAgentIdentity() {
        return AgentIdentity.builder()
                .version("1.0")
                .id("agent-001")
                .issuer("https://issuer.example.com")
                .issuedTo("user123")
                .issuedFor(AgentIdentity.IssuedFor.builder()
                        .platform("test-platform")
                        .client("test-client")
                        .clientInstance("test-instance")
                        .build())
                .issuanceDate(java.time.Instant.now())
                .validFrom(java.time.Instant.now())
                .expires(java.time.Instant.now().plusSeconds(86400))
                .build();
    }
}