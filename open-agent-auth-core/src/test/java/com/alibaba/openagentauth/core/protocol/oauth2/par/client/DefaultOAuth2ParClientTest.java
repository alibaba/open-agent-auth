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
package com.alibaba.openagentauth.core.protocol.oauth2.par.client;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.BasicAuthAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.client.OAuth2ClientAuthentication;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentCaptor.forClass;

/**
 * Unit tests for {@link DefaultOAuth2ParClient}.
 * <p>
 * This test class validates the PAR client implementation
 * following the RFC 9126 specification for Pushed Authorization Requests.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 */
@DisplayName("DefaultOAuth2ParClient Tests")
class DefaultOAuth2ParClientTest {

    private static final String PAR_ENDPOINT = "https://as.example.com/par";
    private static final String CLIENT_ID = "client_12345";
    private static final String CLIENT_SECRET = "secret_67890";
    private static final String REQUEST_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6ImNsaWVudF8xMjM0NSIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJzY29wZSI6Im9wZW5pZCJ9.test";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";
    private static final int EXPIRES_IN = 90;

    private HttpClient mockHttpClient;
    private HttpResponse<String> mockHttpResponse;
    private OAuth2ClientAuthentication mockAuthentication;
    private DefaultOAuth2ParClient client;
    
    private ServiceEndpointResolver mockServiceEndpointResolver;

    @BeforeEach
    void setUp() {
        mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
        when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                .thenReturn(PAR_ENDPOINT);
    }

    @Nested
    @DisplayName("Constructor with OAuth2ClientAuthentication")
    class ConstructorWithOAuth2ClientAuthentication {

        @Test
        @DisplayName("Should create client with valid parameters")
        void shouldCreateClientWithValidParameters() {
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.getAuthenticationMethod()).thenReturn("client_secret_basic");
            client = new DefaultOAuth2ParClient(mockServiceEndpointResolver, mockAuthentication);
            assertThat(client).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            assertThatThrownBy(() -> new DefaultOAuth2ParClient(null, mockAuthentication))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }

        @Test
        @DisplayName("Should throw exception when authentication is null")
        void shouldThrowExceptionWhenAuthenticationIsNull() {
            assertThatThrownBy(() -> new DefaultOAuth2ParClient(mockServiceEndpointResolver, (OAuth2ClientAuthentication) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authentication strategy");
        }
    }

    @Nested
    @DisplayName("Constructor with custom HttpClient and OAuth2ClientAuthentication")
    class ConstructorWithHttpClientAndOAuth2ClientAuthentication {

        @Test
        @DisplayName("Should create client with valid parameters")
        void shouldCreateClientWithValidParameters() {
            mockHttpClient = HttpClient.newHttpClient();
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);
            assertThat(client).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when httpClient is null")
        void shouldThrowExceptionWhenHttpClientIsNull() {
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            assertThatThrownBy(() -> new DefaultOAuth2ParClient(null, mockServiceEndpointResolver, mockAuthentication))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("HTTP client");
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            mockHttpClient = HttpClient.newHttpClient();
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            assertThatThrownBy(() -> new DefaultOAuth2ParClient(mockHttpClient, null, mockAuthentication))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }

        @Test
        @DisplayName("Should throw exception when authentication is null")
        void shouldThrowExceptionWhenAuthenticationIsNull() {
            mockHttpClient = HttpClient.newHttpClient();
            assertThatThrownBy(() -> new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, (OAuth2ClientAuthentication) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authentication strategy");
        }
    }

    @Nested
    @DisplayName("submitParRequest")
    class SubmitParRequest {

        @Test
        @DisplayName("Should submit request successfully and return response")
        void shouldSubmitRequestSuccessfullyAndReturnResponse() throws Exception {
            setupMockHttpClientForSuccess();
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();
            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(response.getExpiresIn()).isEqualTo(EXPIRES_IN);
        }

        @Test
        @DisplayName("Should submit request with state parameter")
        void shouldSubmitRequestWithStateParameter() throws Exception {
            setupMockHttpClientForSuccess();
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .state("test-state")
                    .requestJwt(REQUEST_JWT)
                    .build();

            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            assertThatThrownBy(() -> client.submitParRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR request");
        }

        @Test
        @DisplayName("Should throw ParException when HTTP request fails")
        void shouldThrowParExceptionWhenHttpRequestFails() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpClient.send(any(HttpRequest.class), any()))
                    .thenThrow(new RuntimeException("Network error"));

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Failed to submit PAR request")
                    .hasCauseInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should throw ParException when response status is 400")
        void shouldThrowParExceptionWhenResponseStatusIs400() throws Exception {
            setupMockHttpClientForError(400, "invalid_request", "The request is missing a required parameter");
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("invalid_request");
        }

        @Test
        @DisplayName("Should throw ParException when response status is 401")
        void shouldThrowParExceptionWhenResponseStatusIs401() throws Exception {
            setupMockHttpClientForError(401, "invalid_client", "Client authentication failed");
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("invalid_client");
        }

        @Test
        @DisplayName("Should throw ParException when response status is 500")
        void shouldThrowParExceptionWhenResponseStatusIs500() throws Exception {
            setupMockHttpClientForError(500, "server_error", "Internal server error");
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("server_error");
        }

        @Test
        @DisplayName("Should throw ParException when response body is invalid JSON")
        void shouldThrowParExceptionWhenResponseBodyIsInvalidJson() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("invalid json");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(Throwable.class);
        }

        @Test
        @DisplayName("Should throw ParException when request_uri is missing from response")
        void shouldThrowParExceptionWhenRequestUriIsMissingFromResponse() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"expires_in\":90}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Failed to parse PAR response");
        }

        @Test
        @DisplayName("Should throw ParException when expires_in is missing from response")
        void shouldThrowParExceptionWhenExpiresInIsMissingFromResponse() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"request_uri\":\"" + REQUEST_URI + "\"}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(Throwable.class);
        }

        @Test
        @DisplayName("Should apply authentication headers to request")
        void shouldApplyAuthenticationHeadersToRequest() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();
            client.submitParRequest(request);

            // Verify that authentication was applied
            verify(mockAuthentication).applyAuthentication(any(), any());
        }

        @Test
        @DisplayName("Should use BasicAuthAuthentication with OAuth2ClientAuthentication constructor")
        void shouldUseBasicAuthAuthenticationWithOAuth2ClientAuthenticationConstructor() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            BasicAuthAuthentication basicAuth = new BasicAuthAuthentication(CLIENT_ID, CLIENT_SECRET);
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, basicAuth);

            ParRequest request = createParRequest();
            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should propagate client_id from ParRequest to request body")
        void shouldPropagateClientIdFromParRequestToRequestBody() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            
            String dynamicClientId = "dynamic_client_12345";
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(dynamicClientId)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .requestJwt(REQUEST_JWT)
                    .build();

            client.submitParRequest(request);

            ArgumentCaptor<Map> requestBodyCaptor = forClass(Map.class);
            verify(mockAuthentication).applyAuthentication(any(), requestBodyCaptor.capture());
            
            Map<String, String> requestBody = requestBodyCaptor.getValue();
            assertThat(requestBody).containsKey("client_id");
            assertThat(requestBody.get("client_id")).isEqualTo(dynamicClientId);
        }

        @Test
        @DisplayName("Should propagate different client_id than authentication default")
        void shouldPropagateDifferentClientIdThanAuthenticationDefault() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            String authDefaultClientId = "static-default-client";
            String dcrRegisteredClientId = "dcr-registered-uuid-12345";
            
            when(mockAuthentication.getClientId()).thenReturn(authDefaultClientId);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            // Use DCR-registered client_id which differs from the authentication default
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(dcrRegisteredClientId)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .requestJwt(REQUEST_JWT)
                    .build();

            client.submitParRequest(request);

            ArgumentCaptor<Map> requestBodyCaptor = forClass(Map.class);
            verify(mockAuthentication).applyAuthentication(any(), requestBodyCaptor.capture());
            
            Map<String, String> requestBody = requestBodyCaptor.getValue();
            // The DCR-registered client_id should be in the request body, not the auth default
            assertThat(requestBody).containsKey("client_id");
            assertThat(requestBody.get("client_id")).isEqualTo(dcrRegisteredClientId);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should work end-to-end with real BasicAuthAuthentication")
        void shouldWorkEndToEndWithRealBasicAuthAuthentication() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            BasicAuthAuthentication auth = new BasicAuthAuthentication(CLIENT_ID, CLIENT_SECRET);
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, auth);

            ParRequest request = createParRequest();
            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(response.getExpiresIn()).isEqualTo(EXPIRES_IN);
        }

        @Test
        @DisplayName("Should handle empty state parameter correctly")
        void shouldHandleEmptyStateParameterCorrectly() throws Exception {
            setupMockHttpClientForSuccess();
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .state("")
                    .requestJwt(REQUEST_JWT)
                    .build();

            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
        }

        @Test
        @DisplayName("Should handle null state parameter correctly")
        void shouldHandleNullStateParameterCorrectly() throws Exception {
            setupMockHttpClientForSuccess();
            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .state(null)
                    .requestJwt(REQUEST_JWT)
                    .build();

            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle special characters in request JWT")
        void shouldHandleSpecialCharactersInRequestJwt() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            String specialJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIn0.signature";
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .requestJwt(specialJwt)
                    .build();

            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle very long request JWT")
        void shouldHandleVeryLongRequestJwt() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            String longJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + "a".repeat(10000) + ".signature";
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .requestJwt(longJwt)
                    .build();

            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle zero expires_in value")
        void shouldHandleZeroExpiresInValue() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"request_uri\":\"" + REQUEST_URI + "\",\"expires_in\":0}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();
            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should handle large expires_in value")
        void shouldHandleLargeExpiresInValue() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"request_uri\":\"" + REQUEST_URI + "\",\"expires_in\":86400}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();
            ParResponse response = client.submitParRequest(request);

            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo(86400);
        }

        @Test
        @DisplayName("Should handle error response with empty error description")
        void shouldHandleErrorResponseWithEmptyErrorDescription() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(400);
            when(mockHttpResponse.body()).thenReturn("{\"error\":\"invalid_request\"}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class);
        }

        @Test
        @DisplayName("Should handle error response with unknown error code")
        void shouldHandleErrorResponseWithUnknownErrorCode() throws Exception {
            mockHttpClient = mock(HttpClient.class);
            mockHttpResponse = mock(HttpResponse.class);
            mockAuthentication = mock(OAuth2ClientAuthentication.class);
            when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
            when(mockAuthentication.applyAuthentication(any(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(mockHttpResponse.statusCode()).thenReturn(400);
            when(mockHttpResponse.body()).thenReturn("{\"error\":\"unknown_error\",\"error_description\":\"Unknown error occurred\"}");
            when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                    .thenReturn(mockHttpResponse);

            client = new DefaultOAuth2ParClient(mockHttpClient, mockServiceEndpointResolver, mockAuthentication);

            ParRequest request = createParRequest();

            assertThatThrownBy(() -> client.submitParRequest(request))
                    .isInstanceOf(ParException.class);
        }
    }

    // Helper methods

    private void setupMockHttpClientForSuccess() throws Exception {
        mockHttpClient = mock(HttpClient.class);
        mockHttpResponse = mock(HttpResponse.class);
        mockAuthentication = mock(OAuth2ClientAuthentication.class);
        
        when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
        when(mockAuthentication.applyAuthentication(any(), any()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(buildSuccessResponseBody());
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
    }

    private void setupMockHttpClientForError(int statusCode, String error, String description) throws Exception {
        mockHttpClient = mock(HttpClient.class);
        mockHttpResponse = mock(HttpResponse.class);
        mockAuthentication = mock(OAuth2ClientAuthentication.class);
        
        when(mockAuthentication.getClientId()).thenReturn(CLIENT_ID);
        when(mockAuthentication.applyAuthentication(any(), any()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);
        when(mockHttpResponse.body()).thenReturn(buildErrorResponseBody(error, description));
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
    }

    private String buildSuccessResponseBody() {
        return "{\"request_uri\":\"" + REQUEST_URI + "\",\"expires_in\":" + EXPIRES_IN + "}";
    }

    private String buildErrorResponseBody(String error, String description) {
        return "{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}";
    }

    private ParRequest createParRequest() {
        return ParRequest.builder()
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .requestJwt(REQUEST_JWT)
                .build();
    }
}
