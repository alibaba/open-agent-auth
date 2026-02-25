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

import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkParProcessingException;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.model.request.AoatIssuanceRequest;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAuthorizationServer}.
 * <p>
 * This test class validates the Authorization Server orchestration implementation,
 * including PAR processing, AOAT issuance, and OAuth client registration.
 * </p>
 */
@DisplayName("DefaultAuthorizationServer Tests")
@ExtendWith(MockitoExtension.class)
class DefaultAuthorizationServerTest {

    private DefaultAuthorizationServer authorizationServer;
    
    @Mock
    private OAuth2ParServer mockParServer;
    
    @Mock
    private OAuth2DcrClientStore mockDcrClientStore;
    
    @Mock
    private OAuth2TokenClient mockOAuth2TokenClient;
    
    @Mock
    private OAuth2TokenServer mockOAuth2TokenServer;


    private static final String CLIENT_ID = "client-123";
    private static final String REDIRECT_URI = "http://localhost:8081/callback";
    private static final String AUTH_CODE = "auth-code-123";
    private static final String STATE = "state-123";
    private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiaHR0cHM6Ly9hdXRob3JpemF0aW9uLXNlcnZlci5leGFtcGxlLmNvbSIsImF1ZCI6ImNsaWVudC0xMjMiLCJleHAiOjE1MTYyNDI2MjIsImp0aSI6ImFvYXQtMTIzLTQ1NiIsImFnZW50X2lkZW50aXR5Ijp7ImFnZW50X2lkIjoiYWdlbnQtMTIzIiwiYWdlbnRfbmFtZSI6InRlc3QtYWdlbnQiLCJhZ2VudF90eXBlIjoiU0VSVklDRSJ9LCJhZ2VudF9vcGVyYXRpb25fYXV0aG9yaXphdGlvbiI6eyJwZXJtaXNzaW9ucyI6WyJyZWFkOnJlc291cmNlIiwid3JpdGU6cmVzb3VyY2UiXX19.invalid_signature";
    private static final String WIT = "wit.jwt.token";
    private static final String WORKLOAD_ID = "workload-123";

    @BeforeEach
    void setUp() {
        authorizationServer = new DefaultAuthorizationServer(
                mockParServer,
                mockDcrClientStore,
                mockOAuth2TokenClient,
                mockOAuth2TokenServer,
                null,
                null,
                null
        );
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create authorization server with valid parameters")
        void shouldCreateAuthorizationServerWithValidParameters() {
            // Act
            DefaultAuthorizationServer server = new DefaultAuthorizationServer(
                    mockParServer, mockDcrClientStore, mockOAuth2TokenClient, mockOAuth2TokenServer, null, null, null);

            // Assert
            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when PAR server is null")
        void shouldThrowExceptionWhenParServerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAuthorizationServer(
                    null, mockDcrClientStore, mockOAuth2TokenClient, mockOAuth2TokenServer, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR server cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when OAuth2TokenClient is null")
        void shouldThrowExceptionWhenOAuth2TokenClientIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAuthorizationServer(
                    mockParServer, mockDcrClientStore, null, mockOAuth2TokenServer, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("OAuth2TokenClient cannot be null");
        }
    }

    @Nested
    @DisplayName("processParRequest()")
    class ProcessParRequest {

        @Test
        @DisplayName("Should successfully process PAR request")
        void shouldSuccessfullyProcessParRequest() throws FrameworkParProcessingException {
            // Arrange
            ParRequest parRequest = ParRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid profile")
                    .responseType("code")
                    .build();

            ParResponse expectedResponse = ParResponse.success(
                    "urn:ietf:params:oauth:request_uri:" + UUID.randomUUID(), 
                    600
            );

            when(mockParServer.processParRequest(any(ParRequest.class), anyString()))
                    .thenReturn(expectedResponse);

            // Act
            ParResponse response = authorizationServer.processParRequest(parRequest);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo(600);

            verify(mockParServer, times(1)).processParRequest(parRequest, CLIENT_ID);
        }

        @Test
        @DisplayName("Should throw exception when PAR request is null")
        void shouldThrowExceptionWhenParRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.processParRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR request cannot be null");
        }
    }

    @Nested
    @DisplayName("issueAoat()")
    class IssueAoat {

        @Test
        @DisplayName("Should successfully issue AOAT")
        void shouldSuccessfullyIssueAoat() throws Exception {
            // Arrange
            AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                    .authorizationCode(AUTH_CODE)
                    .redirectUri(REDIRECT_URI)
                    .workloadId(WORKLOAD_ID)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

            when(mockOAuth2TokenServer.issueToken(any(TokenRequest.class), anyString()))
                    .thenReturn(tokenResponse);

            // Act
            AgentOperationAuthToken aoat = authorizationServer.issueAoat(request);

            // Assert
            assertThat(aoat).isNotNull();

            verify(mockOAuth2TokenServer, times(1)).issueToken(any(TokenRequest.class), eq(WORKLOAD_ID));
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueAoat(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AOAT issuance request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when authorization code is null")
        void shouldThrowExceptionWhenAuthorizationCodeIsNull() {
            // Arrange
            AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                    .authorizationCode(null)
                    .redirectUri(REDIRECT_URI)
                    .workloadId(WORKLOAD_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueAoat(request))
                    .isInstanceOf(FrameworkTokenGenerationException.class)
                    .hasMessageContaining("Authorization code is required for AOAT issuance");
        }

        @Test
        @DisplayName("Should throw exception when authorization code is empty")
        void shouldThrowExceptionWhenAuthorizationCodeIsEmpty() {
            // Arrange
            AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                    .authorizationCode("   ")
                    .redirectUri(REDIRECT_URI)
                    .workloadId(WORKLOAD_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueAoat(request))
                    .isInstanceOf(FrameworkTokenGenerationException.class)
                    .hasMessageContaining("Authorization code is required for AOAT issuance");
        }

        @Test
        @DisplayName("Should throw exception when redirect URI is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            // Arrange
            AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                    .authorizationCode(AUTH_CODE)
                    .redirectUri(null)
                    .workloadId(WORKLOAD_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueAoat(request))
                    .isInstanceOf(FrameworkTokenGenerationException.class)
                    .hasMessageContaining("Redirect URI is required for AOAT issuance");
        }

        @Test
        @DisplayName("Should throw exception when redirect URI is empty")
        void shouldThrowExceptionWhenRedirectUriIsEmpty() {
            // Arrange
            AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                    .authorizationCode(AUTH_CODE)
                    .redirectUri("   ")
                    .workloadId(WORKLOAD_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueAoat(request))
                    .isInstanceOf(FrameworkTokenGenerationException.class)
                    .hasMessageContaining("Redirect URI is required for AOAT issuance");
        }
    }

    @Nested
    @DisplayName("registerOAuthClient()")
    class RegisterOAuthClient {

        @Test
        @DisplayName("Should successfully register OAuth client")
        void shouldSuccessfullyRegisterOAuthClient() throws FrameworkAuthorizationException {
            // Arrange
            List<String> redirectUris = Arrays.asList(REDIRECT_URI);

            DcrResponse expectedResponse = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret("secret-123")
                    .clientSecretExpiresAt(0L)
                    .build();

            // We need to create a new instance with WIT validator for this test
            DefaultAuthorizationServer serverWithWitValidator = new DefaultAuthorizationServer(
                    mockParServer,
                    mockDcrClientStore,
                    mockOAuth2TokenClient,
                    mockOAuth2TokenServer,
                    null,
                    null,
                    null
            );

            // Act
            DcrResponse response = serverWithWitValidator.registerOAuthClient(WIT, redirectUris);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when client assertion is null")
        void shouldThrowExceptionWhenClientAssertionIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.registerOAuthClient(null, Arrays.asList(REDIRECT_URI)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client assertion cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when client assertion is empty")
        void shouldThrowExceptionWhenClientAssertionIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.registerOAuthClient("   ", Arrays.asList(REDIRECT_URI)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client assertion cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when redirect URIs is null")
        void shouldThrowExceptionWhenRedirectUrisIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.registerOAuthClient(WIT, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Redirect URIs cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when redirect URIs is empty")
        void shouldThrowExceptionWhenRedirectUrisIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.registerOAuthClient(WIT, Arrays.asList()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Redirect URIs cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("issueToken()")
    class IssueToken {

        @Test
        @DisplayName("Should successfully issue token")
        void shouldSuccessfullyIssueToken() throws Exception {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code(AUTH_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            TokenResponse expectedResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .scope("openid profile")
                    .build();

            when(mockOAuth2TokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(expectedResponse);

            // Act
            TokenResponse response = authorizationServer.issueToken(request, CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600L);
            assertThat(response.getScope()).isEqualTo("openid profile");

            verify(mockOAuth2TokenServer, times(1)).issueToken(request, CLIENT_ID);
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when core token server throws exception")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenCoreTokenServerThrowsException() throws Exception {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code(AUTH_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            when(mockOAuth2TokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new RuntimeException("Invalid authorization code"));

            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.issueToken(request, CLIENT_ID))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Failed to issue token");
        }

        @Test
        @DisplayName("Should delegate to core OAuth2TokenServer with correct parameters")
        void shouldDelegateToCoreOAuth2TokenServerWithCorrectParameters() throws Exception {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code(AUTH_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            TokenResponse expectedResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

            when(mockOAuth2TokenServer.issueToken(any(TokenRequest.class), anyString()))
                    .thenReturn(expectedResponse);

            // Act
            authorizationServer.issueToken(request, CLIENT_ID);

            // Assert
            verify(mockOAuth2TokenServer, times(1)).issueToken(request, CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("exchangeCodeForToken()")
    class ExchangeCodeForToken {

        @Test
        @DisplayName("Should successfully exchange code for token")
        void shouldSuccessfullyExchangeCodeForToken() throws Exception {
            // Arrange
            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code(AUTH_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .state(STATE)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

            when(mockOAuth2TokenClient.exchangeCodeForToken(any(TokenRequest.class)))
                    .thenReturn(tokenResponse);

            // Act
            AuthenticationResponse response = authorizationServer.exchangeCodeForToken(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getIdToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600);

            verify(mockOAuth2TokenClient, times(1)).exchangeCodeForToken(any(TokenRequest.class));
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> authorizationServer.exchangeCodeForToken(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
