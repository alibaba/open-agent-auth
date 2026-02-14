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
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AoatTokenGeneratorAdapter}.
 * <p>
 * This test class validates the adapter that bridges TokenGenerator and AoatTokenGenerator.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AoatTokenGeneratorAdapter Tests")
class AoatTokenGeneratorAdapterTest {

    @Mock
    private AoatTokenGenerator aoatTokenGenerator;

    @Mock
    private OAuth2ParServer OAuth2ParServer;

    private AoatTokenGeneratorAdapter adapter;

    private static final String TEST_CODE = "auth_code_xyz";
    private static final String TEST_REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";
    private static final String TEST_JWT_ID = "jwt_id_123";
    private static final String TEST_ACCESS_TOKEN = "access_token_abc123";
    private static final long DEFAULT_EXPIRATION_SECONDS = 3600L;

    @BeforeEach
    void setUp() {
        adapter = new AoatTokenGeneratorAdapter(aoatTokenGenerator, OAuth2ParServer);
    }

    @Nested
    @DisplayName("generateToken() - Happy Path")
    class GenerateTokenHappyPath {

        @Test
        @DisplayName("Should successfully generate AOAT token")
        void shouldSuccessfullyGenerateAoatToken() throws Exception {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            ParRequest parRequest = createValidParRequest();
            AgentOperationAuthToken aoat = createValidAgentOperationAuthToken();

            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class))).thenReturn(aoat);

            // Act
            String token = adapter.generateToken(authCode, request);

            // Assert
            assertThat(token).isEqualTo(TEST_ACCESS_TOKEN);

            // Verify interactions
            verify(OAuth2ParServer).retrieveRequest(TEST_REQUEST_URI);
            verify(aoatTokenGenerator).generateAoat(eq(authCode.getSubject()), any(ParJwtClaims.class));
        }

        @Test
        @DisplayName("Should extract and pass PAR claims to AOAT generator")
        void shouldExtractAndPassParClaimsToAoatGenerator() throws Exception {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            ParRequest parRequest = createValidParRequest();
            AgentOperationAuthToken aoat = createValidAgentOperationAuthToken();

            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class))).thenReturn(aoat);

            // Act
            adapter.generateToken(authCode, request);

            // Assert
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                assertThat(claims.getJwtId()).isEqualTo(TEST_JWT_ID);
                assertThat(claims.getSubject()).isEqualTo(TEST_SUBJECT);
                assertThat(claims.getOperationProposal()).isEqualTo("allow { input.amount <= 100 }");
                // Note: evidence and context may be null when parsed from JWT string
                // because complex objects in JWT payload are not automatically deserialized
                return true;
            }));
        }
    }

    @Nested
    @DisplayName("generateToken() - Error Handling")
    class GenerateTokenErrorHandling {

        @Test
        @DisplayName("Should throw invalid_grant exception when PAR request not found")
        void shouldThrowInvalidGrantExceptionWhenParRequestNotFound() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(authCode, request))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Original authorization request not found");
        }

        @Test
        @DisplayName("Should throw invalid_grant exception when PAR request JWT is missing")
        void shouldThrowInvalidGrantExceptionWhenParRequestJwtIsMissing() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            ParRequest parRequest = ParRequest.builder()
                    .responseType("code")
                    .clientId("test-client")
                    .redirectUri("https://example.com/callback")
                    .requestJwt(null)
                    .build();
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(authCode, request))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Missing authorization request JWT");
        }

        @Test
        @DisplayName("Should throw server_error exception when token generation fails")
        void shouldThrowServerErrorExceptionWhenTokenGenerationFails() throws Exception {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            ParRequest parRequest = createValidParRequest();
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(new com.nimbusds.jose.JOSEException("Token generation failed"));

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(authCode, request))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "server_error")
                    .hasMessageContaining("Failed to generate access token");
        }
    }

    @Nested
    @DisplayName("getExpirationSeconds()")
    class GetExpirationSeconds {

        @Test
        @DisplayName("Should return default expiration when generator is not DefaultAoatTokenGenerator")
        void shouldReturnDefaultExpirationWhenGeneratorIsNotDefaultAoatTokenGenerator() {
            // Act
            long expiration = adapter.getExpirationSeconds();

            // Assert
            assertThat(expiration).isEqualTo(3600L); // Default expiration
        }
    }

    @Nested
    @DisplayName("PAR Claims Extraction")
    class ParClaimsExtraction {

        @Test
        @DisplayName("Should extract operation proposal from PAR JWT")
        void shouldExtractOperationProposalFromParJwt() throws Exception {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://example.com/callback")
                    .build();

            ParRequest parRequest = createValidParRequest();
            AgentOperationAuthToken aoat = createValidAgentOperationAuthToken();

            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class))).thenReturn(aoat);

            // Act
            String token = adapter.generateToken(authCode, request);

            // Assert
            assertThat(token).isEqualTo(TEST_ACCESS_TOKEN);
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                String operationProposal = claims.getOperationProposal();
                assertThat(operationProposal).isNotNull();
                assertThat(operationProposal).isEqualTo("allow { input.amount <= 100 }");
                return true;
            }));
        }
    }

    // Helper methods

    private static final String TEST_SUBJECT = "user_123";
    private static final String TEST_ISSUER = "https://client.example.com";

    private AuthorizationCode createValidAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId("test-client")
                .redirectUri("https://example.com/callback")
                .requestUri(TEST_REQUEST_URI)
                .subject(TEST_SUBJECT)
                .scope("read write")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600L))
                .used(false)
                .build();
    }

    private ParRequest createValidParRequest() {
        String jwt = createValidParJwt();
        return ParRequest.builder()
                .responseType("code")
                .clientId("test-client")
                .redirectUri("https://example.com/callback")
                .requestJwt(jwt)
                .build();
    }

    private String createValidParJwt() {
        // This is a simplified JWT structure for testing
        // In real scenarios, this would be a properly signed JWT
        String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0wMSJ9";
        String payload = createParJwtPayload();
        String signature = "signature_placeholder";
        return header + "." + payload + "." + signature;
    }

    private String createParJwtPayload() {
        // Create a base64url-encoded payload with all required claims
        // This is a simplified version for testing
        // JWT ID changed to match the expected value in tests
        return "eyJpc3MiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXJfMTIzIiwiYXVkIjpbImh0dHBzOi8vYXMub25saW5lLXNob3AuZXhhbXBsZSJdLCJleHAiOjE3MzE2NjgxMDAsImlhdCI6MTczMTY2NDUwMCwianRpIjoiand0X2lkXzEyMyIsImV2aWRlbmNlIjp7InNvdXJjZVByb21wdENyZWRlbnRpYWwiOiJ2Y19qd3RfYWJjMTIzIn0sImFnZW50X3VzZXJfYmluZGluZ19wcm9wb3NhbCI6eyJ1c2VyX2lkZW50aXR5X3Rva2VuIjoiaWRfdG9rZW5feHl6IiwiYWdlbnRfd29ya2xvYWRfdG9rZW4iOiJ3aXRfdG9rZW5feHl6IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiZGZwX2FiYzEyMyJ9LCJhZ2VudF9vcGVyYXRpb25fcHJvcG9zYWwiOiJhbGxvdyB7IGlucHV0LmFtb3VudCA8PSAxMDAgfSIsImNvbnRleHQiOnsiY2hhbm5lbCI6Im1vYmlsZS1hcHAiLCJ1c2VyIjp7ImlkIjoidXNlcl8xMjMifSwiYWdlbnQiOnsiaW5zdGFuY2UiOiJkZnBfYWJjMTIzIiwicGxhdGZvcm0iOiJwZXJzb25hbC1hZ2VudC5leGFtcGxlLmNvbSIsImNsaWVudCI6Im1vYmlsZS1hcHAtdjEuZXhhbXBsZS5jb20ifX19";
    }

    private ParJwtClaims createValidParJwtClaims() {
        Instant now = Instant.now();
        Evidence evidence = Evidence.builder()
                .sourcePromptCredential("vc_jwt_abc123")
                .build();

        AgentUserBindingProposal binding = AgentUserBindingProposal.builder()
                .userIdentityToken("id_token_xyz")
                .agentWorkloadToken("wit_token_xyz")
                .deviceFingerprint("dfp_abc123")
                .build();

        OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                .instance("dfp_abc123")
                .platform("personal-agent.example.com")
                .client("mobile-app-v1.example.com")
                .build();

        OperationRequestContext.UserContext userContext = OperationRequestContext.UserContext.builder()
                .id("user_123")
                .build();

        OperationRequestContext context = OperationRequestContext.builder()
                .channel("mobile-app")
                .user(userContext)
                .agent(agentContext)
                .build();

        return ParJwtClaims.builder()
                .issuer(TEST_ISSUER)
                .subject(TEST_SUBJECT)
                .audience(List.of("https://as.online-shop.example"))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .jwtId(TEST_JWT_ID)
                .evidence(evidence)
                .agentUserBindingProposal(binding)
                .operationProposal("allow { input.amount <= 100 }")
                .context(context)
                .build();
    }

    private AgentOperationAuthToken createValidAgentOperationAuthToken() {
        Instant now = Instant.now();

        AgentOperationAuthToken.Header header = AgentOperationAuthToken.Header.builder()
                .type("JWT")
                .algorithm("RS256")
                .build();

        AgentOperationAuthToken.Claims claims = AgentOperationAuthToken.Claims.builder()
                .issuer("https://as.example.com")
                .subject(TEST_SUBJECT)
                .audience("https://api.example.com")
                .issuedAt(now)
                .expirationTime(now.plusSeconds(3600))
                .jwtId(TEST_JWT_ID)
                .agentIdentity(AgentIdentity.builder()
                        .version("1.0")
                        .id("urn:uuid:agent-identity-123")
                        .issuer("https://as.example.com")
                        .issuedTo("https://as.example.com|" + TEST_SUBJECT)
                        .issuedFor(AgentIdentity.IssuedFor.builder()
                                .platform("personal-agent.example.com")
                                .client("mobile-app-v1.example.com")
                                .clientInstance("dfp_abc123")
                                .build())
                        .issuanceDate(now)
                        .validFrom(now)
                        .expires(now.plusSeconds(3600))
                        .build())
                .authorization(AgentOperationAuthorization.builder()
                        .policyId("opa-policy-789")
                        .build())
                .build();

        return AgentOperationAuthToken.builder()
                .header(header)
                .claims(claims)
                .jwtString(TEST_ACCESS_TOKEN)
                .signature("signature_placeholder")
                .build();
    }
}
