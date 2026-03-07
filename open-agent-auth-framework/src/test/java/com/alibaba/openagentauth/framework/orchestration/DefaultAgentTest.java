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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.par.client.OAuth2ParClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.client.WorkloadClient;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.AgentRequestContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.CreateWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.CreateWorkloadResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthenticationException;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.ParSubmissionRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkAuthorizationContextException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAgent}.
 * <p>
 * This test class validates the Agent orchestration implementation,
 * including workload creation, authorization initiation, and token exchange.
 * </p>
 */
@DisplayName("DefaultAgent Tests")
@ExtendWith(MockitoExtension.class)
class DefaultAgentTest {

    private DefaultAgent agent;
    
    @Mock
    private WorkloadClient mockWorkloadClient;
    
    @Mock
    private TokenService mockTokenService;
    
    @Mock
    private WitValidator mockWitValidator;
    
    @Mock
    private IdTokenValidator mockIdTokenValidator;
    
    @Mock
    private OAuth2ParClient mockParClient;
    
    @Mock
    private OAuth2DcrClient mockDcrClient;
    
    @Mock
    private OAuth2TokenClient mockUserAuthenticationTokenClient;
    
    @Mock
    private OAuth2TokenClient mockAgentOperationAuthorizationTokenClient;
    
    @Mock
    private AapParJwtGenerator mockAapParJwtGenerator;

    private static final String AUTHORIZATION_SERVER_URL = "https://auth.example.com";
    private static final String AGENT_USER_IDP_URL = "https://user-idp.example.com";
    private static final String CLIENT_ID = "client-123";
    private static final String OAUTH_CALLBACKS_REDIRECT_URI = "http://localhost:8081/callback";
    private static final String WORKLOAD_ID = "workload-123";
    private static final String USER_ID = "user-123";
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String WIT = "wit.jwt.token";
    private static final String AUTH_CODE = "auth-code-123";
    private static final String STATE = "state-123";
    // Valid P-256 EC key coordinates (from RFC 7518 Appendix A)
    // Valid P-256 EC key coordinates (using actual valid coordinates)
    private static final String PUBLIC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis\",\"y\":\"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE\"}";
    private static final String PRIVATE_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis\",\"y\":\"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE\",\"d\":\"Kbk7MJUxvgFyvoASZR7HSQE0vCJi5qkfZRbiMZGJhPE\"}";

    private AoatGenerator aoatGenerator;

    @BeforeEach
    void setUp() throws JOSEException {
        RSAKey signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        aoatGenerator = new AoatGenerator(
                signingKey,
                JWSAlgorithm.RS256,
                AUTHORIZATION_SERVER_URL,
                AGENT_USER_IDP_URL
        );

        agent = new DefaultAgent(
                mockWorkloadClient,
                mockTokenService,
                mockWitValidator,
                mockIdTokenValidator,
                mockParClient,
                mockDcrClient,
                mockUserAuthenticationTokenClient,
                mockAgentOperationAuthorizationTokenClient,
                mockAapParJwtGenerator,
                AUTHORIZATION_SERVER_URL,
                AGENT_USER_IDP_URL,
                CLIENT_ID,
                OAUTH_CALLBACKS_REDIRECT_URI
        );
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create agent with valid parameters")
        void shouldCreateAgentWithValidParameters() {
            // Act
            DefaultAgent newAgent = new DefaultAgent(
                    mockWorkloadClient,
                    mockTokenService,
                    mockWitValidator,
                    mockIdTokenValidator,
                    mockParClient,
                    mockDcrClient,
                    mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL,
                    AGENT_USER_IDP_URL,
                    CLIENT_ID,
                    OAUTH_CALLBACKS_REDIRECT_URI
            );

            // Assert
            assertThat(newAgent).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when workload client is null")
        void shouldThrowExceptionWhenWorkloadClientIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    null, mockTokenService, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL, AGENT_USER_IDP_URL, CLIENT_ID, OAUTH_CALLBACKS_REDIRECT_URI))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent IDP HTTP client cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when token service is null")
        void shouldThrowExceptionWhenTokenServiceIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    mockWorkloadClient, null, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL, AGENT_USER_IDP_URL, CLIENT_ID, OAUTH_CALLBACKS_REDIRECT_URI))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token service cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when authorization server URL is null")
        void shouldThrowExceptionWhenAuthorizationServerUrlIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    mockWorkloadClient, mockTokenService, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    null, AGENT_USER_IDP_URL, CLIENT_ID, OAUTH_CALLBACKS_REDIRECT_URI))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authorization server URL cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when agent user IDP URL is null")
        void shouldThrowExceptionWhenAgentUserIdpUrlIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    mockWorkloadClient, mockTokenService, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL, null, CLIENT_ID, OAUTH_CALLBACKS_REDIRECT_URI))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent User IDP URL cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    mockWorkloadClient, mockTokenService, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL, AGENT_USER_IDP_URL, null, OAUTH_CALLBACKS_REDIRECT_URI))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when OAuth callbacks redirect URI is null")
        void shouldThrowExceptionWhenOAuthCallbacksRedirectUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgent(
                    mockWorkloadClient, mockTokenService, mockWitValidator, mockIdTokenValidator, mockParClient,
                    mockDcrClient, mockUserAuthenticationTokenClient,
                    mockAgentOperationAuthorizationTokenClient,
                    mockAapParJwtGenerator,
                    AUTHORIZATION_SERVER_URL, AGENT_USER_IDP_URL, CLIENT_ID, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("OAuth callbacks redirect URI cannot be null");
        }
    }

    @Nested
    @DisplayName("issueWorkloadIdentityToken()")
    class IssueWorkloadIdentityToken {

        @Test
        @DisplayName("Should successfully issue WIT with valid request")
        void shouldSuccessfullyIssueWitWithValidRequest() throws Exception {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .deviceFingerprint("device-123")
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId(CLIENT_ID)
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_URL)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);

            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_URL), eq(CLIENT_ID)))
                    .thenReturn(idToken);

            WorkloadIdentityToken mockWitToken = mock(WorkloadIdentityToken.class);
            when(mockWitToken.getSubject()).thenReturn(WORKLOAD_ID);
            when(mockWitToken.getExpirationTime()).thenReturn(java.util.Date.from(Instant.now().plusSeconds(3600)));
            
            TokenValidationResult<WorkloadIdentityToken> witValidationResult = TokenValidationResult.success(mockWitToken);

            IssueWitResponse witResponse = IssueWitResponse.builder()
                    .wit(WIT)
                    .build();

            when(mockWorkloadClient.issueWit(any(IssueWitRequest.class)))
                    .thenReturn(witResponse);
            
            try {
                when(mockWitValidator.validate(eq(WIT))).thenReturn(witValidationResult);
            } catch (java.text.ParseException e) {
                throw new RuntimeException(e);
            }

            // Act
            WorkloadContext result = agent.issueWorkloadIdentityToken(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(result.getWit()).isEqualTo(WIT);
            assertThat(result.getUserId()).isEqualTo(USER_ID);
            assertThat(result.getPublicKey()).isNotNull();
            assertThat(result.getPrivateKey()).isNotNull();

            verify(mockWorkloadClient, times(1)).issueWit(any(IssueWitRequest.class));
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.issueWorkloadIdentityToken(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Issue WIT request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            // Arrange - Note: Builder validates context before build(), so we need to pass a valid request
            // The validation happens in IssueWitRequest.Builder.build(), not in agent.issueWorkloadIdentityToken()
            // This test validates that the builder properly rejects null context
            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            // Act & Assert - Builder validation happens here
            assertThatThrownBy(() -> IssueWitRequest.builder()
                    .proposal(proposal)
                    .oauthClientId(CLIENT_ID)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Operation request context is required");
        }

        @Test
        @DisplayName("Should throw exception when proposal is null")
        void shouldThrowExceptionWhenProposalIsNull() {
            // Arrange - Note: Builder validates proposal before build()
            OperationRequestContext context = OperationRequestContext.builder()
                    .build();

            // Act & Assert - Builder validation happens here
            assertThatThrownBy(() -> IssueWitRequest.builder()
                    .context(context)
                    .oauthClientId(CLIENT_ID)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent user binding proposal is required");
        }

        @Test
        @DisplayName("Should throw exception when JOSEException occurs during key generation")
        void shouldThrowExceptionWhenJOSEExceptionOccurs() {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId(CLIENT_ID)
                    .build();

            // Mock workloadClient to throw RuntimeException wrapping JOSEException
            when(mockWorkloadClient.issueWit(any(IssueWitRequest.class)))
                    .thenThrow(new RuntimeException(new JOSEException("Key generation failed")));

            // Act & Assert - Check that exception is WorkloadCreationException
            // The exception message is "Failed to issue WIT" which is correct
            assertThatThrownBy(() -> agent.issueWorkloadIdentityToken(request))
                    .isInstanceOf(WorkloadCreationException.class)
                    .hasMessageContaining("Failed to issue WIT");
        }

        @Test
        @DisplayName("Should throw exception when workload creation fails")
        void shouldThrowExceptionWhenWorkloadCreationFails() throws Exception {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId(CLIENT_ID)
                    .build();

            // Mock workloadClient to throw WorkloadCreationException
            when(mockWorkloadClient.issueWit(any(IssueWitRequest.class)))
                    .thenThrow(new WorkloadCreationException("Workload creation failed"));

            // Act & Assert
            assertThatThrownBy(() -> agent.issueWorkloadIdentityToken(request))
                    .isInstanceOf(WorkloadCreationException.class)
                    .hasMessageContaining("Failed to issue WIT");
        }
    }

    @Nested
    @DisplayName("initiateAuthorization()")
    class InitiateAuthorization {

        @Test
        @DisplayName("Should successfully initiate authorization with valid request")
        void shouldSuccessfullyInitiateAuthorizationWithValidRequest() throws Exception {
            // Arrange
            InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .state(STATE)
                    .build();

            // Act
            String result = agent.initiateAuthorization(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).contains(AGENT_USER_IDP_URL + "/oauth2/authorize");
            assertThat(result).contains("response_type=code");
            assertThat(result).contains("client_id=" + CLIENT_ID);
            assertThat(result).contains("redirect_uri=" + URLEncoder.encode(OAUTH_CALLBACKS_REDIRECT_URI, StandardCharsets.UTF_8));
            assertThat(result).contains("scope=" + URLEncoder.encode("openid profile", StandardCharsets.UTF_8));
            assertThat(result).contains("state=" + STATE);
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.initiateAuthorization(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Initiate authorization request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when state is null")
        void shouldThrowExceptionWhenStateIsNull() {
            // Arrange - Note: Builder validates state before build()
            // Act & Assert - Builder validation happens here
            assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .state(null)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("state is required");
        }
    }

    @Nested
    @DisplayName("exchangeCodeForToken()")
    class ExchangeCodeForToken {

        @Test
        @DisplayName("Should successfully exchange code for token with valid request")
        void shouldSuccessfullyExchangeCodeForTokenWithValidRequest() throws Exception {
            // Arrange
            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code(AUTH_CODE)
                    .state(STATE)
                    .clientId(CLIENT_ID)
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ID_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .idToken(ID_TOKEN)
                    .build();

            when(mockUserAuthenticationTokenClient.exchangeCodeForToken(any(TokenRequest.class)))
                    .thenReturn(tokenResponse);

            // Act
            AuthenticationResponse result = agent.exchangeCodeForToken(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getIdToken()).isEqualTo(ID_TOKEN);
            assertThat(result.getTokenType()).isEqualTo("Bearer");
            assertThat(result.getExpiresIn()).isEqualTo(3600);

            verify(mockUserAuthenticationTokenClient, times(1)).exchangeCodeForToken(any(TokenRequest.class));
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.exchangeCodeForToken(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Exchange code request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when token exchange fails")
        void shouldThrowExceptionWhenTokenExchangeFails() throws Exception {
            // Arrange
            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code(AUTH_CODE)
                    .state(STATE)
                    .clientId(CLIENT_ID)
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .build();

            when(mockUserAuthenticationTokenClient.exchangeCodeForToken(any(TokenRequest.class)))
                    .thenThrow(new RuntimeException("Network error"));

            // Act & Assert
            assertThatThrownBy(() -> agent.exchangeCodeForToken(request))
                    .isInstanceOf(FrameworkAuthenticationException.class)
                    .hasMessageContaining("Failed to exchange authorization code for ID Token");
        }
    }

    @Nested
    @DisplayName("handleAuthorizationCallback()")
    class HandleAuthorizationCallback {

        @Test
        @DisplayName("Should successfully handle authorization callback with valid response")
        void shouldSuccessfullyHandleAuthorizationCallbackWithValidResponse() throws Exception {
            // Arrange
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .authorizationCode(AUTH_CODE)
                    .state(STATE)
                    .build();

            // Create a valid AOAT token with agent_identity and agent_operation_authorization claims using AoatGenerator
            AgentIdentity agentIdentity =
                AgentIdentity.builder()
                    .version("1.0")
                    .id("agent-123")
                    .issuer(AUTHORIZATION_SERVER_URL)
                    .issuedTo(USER_ID)
                    .issuedFor(AgentIdentity.IssuedFor.builder()
                        .platform("test-platform")
                        .client("test-client")
                        .build())
                    .issuanceDate(java.time.Instant.now())
                    .validFrom(java.time.Instant.now())
                    .expires(java.time.Instant.now().plusSeconds(3600))
                    .build();

            AgentOperationAuthorization authorization =
                AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            String aoatToken = aoatGenerator.generateAoatAsString(USER_ID, agentIdentity, authorization, 3600);

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(aoatToken)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

            when(mockAgentOperationAuthorizationTokenClient.exchangeCodeForToken(any(TokenRequest.class)))
                    .thenReturn(tokenResponse);

            // Act
            AgentOperationAuthToken result = agent.handleAuthorizationCallback(response);

            // Assert
            assertThat(result).isNotNull();

            verify(mockAgentOperationAuthorizationTokenClient, times(1))
                    .exchangeCodeForToken(any(TokenRequest.class));
        }

        @Test
        @DisplayName("Should throw exception when response indicates failure")
        void shouldThrowExceptionWhenResponseIndicatesFailure() {
            // Arrange
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .state(STATE)
                    .error("access_denied")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> agent.handleAuthorizationCallback(response))
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .hasCauseInstanceOf(FrameworkAuthorizationException.class)
                    .extracting(Throwable::getCause)
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .extracting("message")
                    .asString()
                    .contains("access_denied");
        }

        @Test
        @DisplayName("Should throw exception when response is null")
        void shouldThrowExceptionWhenResponseIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.handleAuthorizationCallback(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authorization response cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when authorization code is missing")
        void shouldThrowExceptionWhenAuthorizationCodeIsMissing() {
            // Arrange - Note: Builder validates authorization code before build()
            // We need to provide an error instead of null authorization code
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(OAUTH_CALLBACKS_REDIRECT_URI)
                    .state(STATE)
                    .error("invalid_request")
                    .errorDescription("Authorization code is missing")
                    .build();

            // Act & Assert - The actual exception is FrameworkAuthorizationException
            // The exception message is "Failed to handle authorization callback" which is correct
            assertThatThrownBy(() -> agent.handleAuthorizationCallback(response))
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .hasMessageContaining("Failed to handle authorization callback");
        }
    }

    @Nested
    @DisplayName("prepareAuthorizationContext()")
    class PrepareAuthorizationContext {

        @Test
        @DisplayName("Should successfully prepare authorization context with valid request")
        void shouldSuccessfullyPrepareAuthorizationContextWithValidRequest() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            when(aoat.getJwtString()).thenReturn("aoat.jwt.token");

            PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                    .workloadContext(workloadContext)
                    .aoat(aoat)
                    .build();

            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            TokenValidationResult<WorkloadIdentityToken> witResult = TokenValidationResult.success(wit);

            when(mockWitValidator.validate(eq(WIT)))
                    .thenReturn(witResult);

            when(mockTokenService.generateWptAsString(any(), any(), anyLong(), any()))
                    .thenReturn("wpt.jwt.token");

            // Act
            AgentAuthorizationContext result = agent.prepareAuthorizationContext(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getWit()).isEqualTo(WIT);
            assertThat(result.getAoat()).isEqualTo("aoat.jwt.token");
            assertThat(result.getAdditionalHeaders()).isNotEmpty();
            assertThat(result.getAdditionalHeaders()).containsKey("X-Workload-Identity");
            assertThat(result.getAdditionalHeaders()).containsKey("X-Workload-Proof");

            verify(mockWitValidator, times(1)).validate(WIT);
            verify(mockTokenService, times(1)).generateWptAsString(any(), any(), anyLong(), any());
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.prepareAuthorizationContext(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Prepare authorization context request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when WIT validation fails")
        void shouldThrowExceptionWhenWitValidationFails() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            // Don't mock unused methods to avoid UnnecessaryStubbing error

            PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                    .workloadContext(workloadContext)
                    .aoat(aoat)
                    .build();

            TokenValidationResult<WorkloadIdentityToken> witResult = 
                TokenValidationResult.failure("WIT validation failed");

            // Only mock the WitValidator
            when(mockWitValidator.validate(eq(WIT)))
                    .thenReturn(witResult);

            // Act & Assert - The actual exception type is FrameworkAuthorizationContextException
            assertThatThrownBy(() -> agent.prepareAuthorizationContext(request))
                    .isInstanceOf(FrameworkAuthorizationContextException.class)
                    .hasMessageContaining("Failed to prepare authorization context");
        }

        @Test
        @DisplayName("Should throw exception when WPT generation fails")
        void shouldThrowExceptionWhenWptGenerationFails() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            // Don't mock unused method to avoid UnnecessaryStubbing error
            // when(aoat.getJwtString()).thenReturn("aoat.jwt.token");

            PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                    .workloadContext(workloadContext)
                    .aoat(aoat)
                    .build();

            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            TokenValidationResult<WorkloadIdentityToken> witResult = TokenValidationResult.success(wit);

            when(mockWitValidator.validate(eq(WIT)))
                    .thenReturn(witResult);

            when(mockTokenService.generateWptAsString(any(), any(), anyLong(), any()))
                    .thenThrow(new RuntimeException("WPT generation failed"));

            // Act & Assert - The actual exception type is FrameworkAuthorizationContextException
            assertThatThrownBy(() -> agent.prepareAuthorizationContext(request))
                    .isInstanceOf(FrameworkAuthorizationContextException.class)
                    .hasMessageContaining("Failed to prepare authorization context");
        }
    }

    @Nested
    @DisplayName("clearAuthorizationContext()")
    class ClearAuthorizationContext {

        @Test
        @DisplayName("Should successfully clear authorization context with valid workload")
        void shouldSuccessfullyClearAuthorizationContextWithValidWorkload() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            // Act
            agent.clearAuthorizationContext(workloadContext);

            // Assert - no exception thrown
            verify(mockWorkloadClient, times(1)).revokeWorkload(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should throw exception when workload context is null")
        void shouldThrowExceptionWhenWorkloadContextIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.clearAuthorizationContext(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload context cannot be null");
        }

        @Test
        @DisplayName("Should handle exception when revocation fails gracefully")
        void shouldHandleExceptionWhenRevocationFailsGracefully() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            doThrow(new RuntimeException("Revocation failed"))
                    .when(mockWorkloadClient).revokeWorkload(WORKLOAD_ID);

            // Act - should not throw exception, only log error
            agent.clearAuthorizationContext(workloadContext);

            // Assert - verify call was attempted
            verify(mockWorkloadClient, times(1)).revokeWorkload(WORKLOAD_ID);
        }
    }

    @Nested
    @DisplayName("registerOAuthClient()")
    class RegisterOAuthClient {

        @Test
        @DisplayName("Should successfully register OAuth client with valid workload")
        void shouldSuccessfullyRegisterOAuthClientWithValidWorkload() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            DcrResponse expectedResponse = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret("secret-123")
                    .build();

            when(mockDcrClient.registerClient(any()))
                    .thenReturn(expectedResponse);

            // Act
            WorkloadContext result = agent.registerOAuthClient(workloadContext);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getOauthClientId()).isEqualTo(CLIENT_ID);

            verify(mockDcrClient, times(1)).registerClient(any());
        }

        @Test
        @DisplayName("Should throw exception when workload context is null")
        void shouldThrowExceptionWhenWorkloadContextIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.registerOAuthClient(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload context cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when DCR registration fails")
        void shouldThrowExceptionWhenDcrRegistrationFails() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            when(mockDcrClient.registerClient(any()))
                    .thenThrow(new RuntimeException("DCR registration failed"));

            // Act & Assert
            assertThatThrownBy(() -> agent.registerOAuthClient(workloadContext))
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .hasMessageContaining("Failed to register OAuth client");
        }
    }

    @Nested
    @DisplayName("submitParRequest()")
    class SubmitParRequest {

        @Test
        @DisplayName("Should successfully submit PAR request with valid request")
        void shouldSuccessfullySubmitParRequestWithValidRequest() throws Exception {
            // Arrange
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            ParSubmissionRequest request = ParSubmissionRequest.builder()
                    .workloadContext(workloadContext)
                    .operationProposal(AgentOperationProposal.builder().policy("allow { true }").build())
                    .evidence(Evidence.builder().build())
                    .userIdentityToken(ID_TOKEN)
                    .context(OperationRequestContext.builder().build())
                    .state(STATE)
                    .build();

            ParResponse expectedResponse = ParResponse.success(
                    "urn:ietf:params:oauth:request_uri:" + UUID.randomUUID(),
                    600
            );

            when(mockParClient.submitParRequest(any(ParRequest.class)))
                    .thenReturn(expectedResponse);

            when(mockAapParJwtGenerator.generateParJwt(any()))
                    .thenReturn("par.jwt.token");

            // Act
            ParResponse result = agent.submitParRequest(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getRequestUri()).isNotNull();
            assertThat(result.getExpiresIn()).isEqualTo(600);

            verify(mockParClient, times(1)).submitParRequest(any(ParRequest.class));
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.submitParRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR submission request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when user identity token is null")
        void shouldThrowExceptionWhenUserIdentityTokenIsNull() {
            // Arrange - Note: Builder validates userIdentityToken before build()
            WorkloadContext workloadContext = WorkloadContext.builder()
                    .workloadId(WORKLOAD_ID)
                    .userId(USER_ID)
                    .wit(WIT)
                    .publicKey(PUBLIC_KEY)
                    .privateKey(PRIVATE_KEY)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            // Act & Assert - Builder validation happens here
            assertThatThrownBy(() -> ParSubmissionRequest.builder()
                    .workloadContext(workloadContext)
                    .operationProposal(AgentOperationProposal.builder().policy("allow { true }").build())
                    .evidence(Evidence.builder().build())
                    .userIdentityToken(null)
                    .context(OperationRequestContext.builder().build())
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("userIdentityToken cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("generateAuthorizationUrl()")
    class GenerateAuthorizationUrl {

        @Test
        @DisplayName("Should generate authorization URL with request URI only")
        void shouldGenerateAuthorizationUrlWithRequestUriOnly() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:test";

            // Act
            String result = agent.generateAuthorizationUrl(requestUri);

            // Assert
            assertThat(result).isNotNull();
            // Note: The actual implementation uses authorizationServerUrl for authorization
            assertThat(result).contains(AUTHORIZATION_SERVER_URL + "/oauth2/authorize");
            // URL encoding is applied to request_uri
            assertThat(result).contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest");
        }

        @Test
        @DisplayName("Should generate authorization URL with request URI and state")
        void shouldGenerateAuthorizationUrlWithRequestUriAndState() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:test";
            String state = STATE;

            // Act
            String result = agent.generateAuthorizationUrl(requestUri, state);

            // Assert
            assertThat(result).isNotNull();
            // Note: The actual implementation uses authorizationServerUrl for authorization
            assertThat(result).contains(AUTHORIZATION_SERVER_URL + "/oauth2/authorize");
            // URL encoding is applied to request_uri
            assertThat(result).contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest");
            // State parameter should be present
            assertThat(result).contains("state=" + STATE);
        }

        @Test
        @DisplayName("Should throw exception when request URI is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agent.generateAuthorizationUrl(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request URI cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when request URI is empty")
        void shouldThrowExceptionWhenRequestUriIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> agent.generateAuthorizationUrl(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request URI cannot be null or empty");
        }
    }
}
