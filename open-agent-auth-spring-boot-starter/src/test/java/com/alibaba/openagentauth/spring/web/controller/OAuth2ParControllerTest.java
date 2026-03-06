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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2ParController}.
 * <p>
 * Tests the OAuth 2.0 Pushed Authorization Request controller's behavior including:
 * <ul>
 *   <li>Successful PAR request processing</li>
 *   <li>PAR request with JWT form</li>
 *   <li>PAR request with hybrid form</li>
 *   <li>Error handling for invalid requests</li>
 *   <li>Exception handling</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2ParController Tests")
class OAuth2ParControllerTest {

    @Mock
    private OAuth2ParServer parServer;

    @Mock
    private OAuth2ClientStore clientStore;

    private OAuth2ParController controller;

    private static final String CLIENT_ID = "client-123";
    private static final String CLIENT_SECRET = "secret-456";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String RESPONSE_TYPE = "code";
    private static final String STATE = "state-456";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";
    private static final int EXPIRES_IN = 600;

    /**
     * Creates a valid JWT with all required claims for testing.
     * Format: header.payload.signature (all base64url encoded)
     */
    private static String createTestJwt(String clientId, String redirectUri, String responseType, String state) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append("{\"client_id\":\"").append(clientId).append("\",");
        payloadBuilder.append("\"redirect_uri\":\"").append(redirectUri).append("\",");
        payloadBuilder.append("\"response_type\":\"").append(responseType).append("\"");
        if (state != null) {
            payloadBuilder.append(",\"state\":\"").append(state).append("\"");
        }
        payloadBuilder.append("}");
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBuilder.toString().getBytes());
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString("test-signature".getBytes());
        return header + "." + payload + "." + signature;
    }

    private static final String REQUEST_JWT = createTestJwt(CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, STATE);

    @BeforeEach
    void setUp() {
        controller = new OAuth2ParController(parServer, clientStore);
        
        // Mock client store to return a valid client
        OAuth2RegisteredClient mockClient = OAuth2RegisteredClient.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .tokenEndpointAuthMethod("client_secret_basic")
                .build();
        Mockito.lenient().when(clientStore.retrieve(CLIENT_ID)).thenReturn(mockClient);
        
        // Mock client store for unknown client
        Mockito.lenient().when(clientStore.retrieve("unknown-client")).thenReturn(null);
    }

    /**
     * Creates a valid Basic Auth header for testing.
     */
    private String createBasicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        return "Basic " + encodedCredentials;
    }

    @Nested
    @DisplayName("PAR Endpoint Tests")
    class ParEndpointTests {

        @Test
        @DisplayName("Should process PAR request successfully with hybrid form")
        void shouldProcessParRequestSuccessfullyWithHybridForm() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);
            requestBody.add("response_type", RESPONSE_TYPE);
            requestBody.add("state", STATE);

            ParResponse parResponse = ParResponse.success(REQUEST_URI, EXPIRES_IN);
            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenReturn(parResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.par(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("request_uri")).isEqualTo(REQUEST_URI);
            assertThat(response.getBody().get("expires_in")).isEqualTo(EXPIRES_IN);
            
            verify(parServer).processParRequest(any(ParRequest.class), eq(CLIENT_ID));
        }

        @Test
        @DisplayName("Should process PAR request successfully with pure JWT form")
        void shouldProcessParRequestSuccessfullyWithPureJwtForm() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            String validJwt = createTestJwt(CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, STATE);
            
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", validJwt);

            ParResponse parResponse = ParResponse.success(REQUEST_URI, EXPIRES_IN);
            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenReturn(parResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.par(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("request_uri")).isEqualTo(REQUEST_URI);
            assertThat(response.getBody().get("expires_in")).isEqualTo(EXPIRES_IN);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when request parameter is missing")
        void shouldThrowIllegalArgumentExceptionWhenRequestParameterIsMissing() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("request");
        }

        @Test
        @DisplayName("Should throw ParException without RFC error code")
        void shouldThrowParExceptionWithoutRfcErrorCode() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new ParException("Invalid redirect URI", new RuntimeException("Invalid redirect URI")));

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid redirect URI");
        }

        @Test
        @DisplayName("Should throw ParException with RFC error code")
        void shouldThrowParExceptionWithRfcErrorCode() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenThrow(ParException.invalidRedirectUri("Redirect URI is not registered"));

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Redirect URI is not registered");
        }

        @Test
        @DisplayName("Should throw RuntimeException during PAR server processing")
        void shouldThrowRuntimeExceptionDuringParServerProcessing() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new RuntimeException("Unexpected error"));

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Unexpected error");
        }
    }

    @Nested
    @DisplayName("Client Authentication Tests")
    class ClientAuthenticationTests {

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when Authorization header is missing")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenAuthorizationHeaderIsMissing() {
            // Given
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, null))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Authorization header");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when Authorization header has invalid format")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenAuthorizationHeaderHasInvalidFormat() {
            // Given
            String invalidAuthHeader = "Bearer invalid-token";
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, invalidAuthHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Basic authentication");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client credentials are invalid")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenClientCredentialsAreInvalid() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, "wrong-secret");
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Invalid client secret");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client is not registered")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenClientIsNotRegistered() {
            // Given
            String authHeader = createBasicAuthHeader("unknown-client", "secret");
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", "unknown-client");
            requestBody.add("redirect_uri", REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controller.par(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client not registered");
        }
    }

    @Nested
    @DisplayName("Request Parsing Tests")
    class RequestParsingTests {

        @Test
        @DisplayName("Should parse PAR request with all parameters in body")
        void shouldParseParRequestWithAllParametersInBody() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", REQUEST_JWT);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);
            requestBody.add("response_type", RESPONSE_TYPE);
            requestBody.add("state", STATE);

            ParResponse parResponse = ParResponse.success(REQUEST_URI, EXPIRES_IN);
            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenReturn(parResponse);

            // When
            controller.par(requestBody, authHeader);

            // Then
            verify(parServer).processParRequest(any(ParRequest.class), eq(CLIENT_ID));
        }

        @Test
        @DisplayName("Should parse PAR request with default response_type")
        void shouldParseParRequestWithDefaultResponseType() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            String jwtWithoutResponseType = createTestJwt(CLIENT_ID, REDIRECT_URI, null, null);
            
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", jwtWithoutResponseType);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            ParResponse parResponse = ParResponse.success(REQUEST_URI, EXPIRES_IN);
            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenReturn(parResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.par(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        @Test
        @DisplayName("Should parse PAR request without state")
        void shouldParseParRequestWithoutState() {
            // Given
            String authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            String jwtWithoutState = createTestJwt(CLIENT_ID, REDIRECT_URI, RESPONSE_TYPE, null);
            
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("request", jwtWithoutState);
            requestBody.add("client_id", CLIENT_ID);
            requestBody.add("redirect_uri", REDIRECT_URI);

            ParResponse parResponse = ParResponse.success(REQUEST_URI, EXPIRES_IN);
            when(parServer.processParRequest(any(ParRequest.class), eq(CLIENT_ID)))
                    .thenReturn(parResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.par(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }
}