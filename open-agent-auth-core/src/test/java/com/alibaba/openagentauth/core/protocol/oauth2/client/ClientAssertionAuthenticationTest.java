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
package com.alibaba.openagentauth.core.protocol.oauth2.client;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for ClientAssertionAuthentication.
 * <p>
 * This test class verifies the functionality of applying WIMSE-based
 * client assertion authentication to HTTP requests.
 * </p>
 */
@DisplayName("ClientAssertionAuthentication Tests")
class ClientAssertionAuthenticationTest {

    private ClientAssertionAuthentication authentication;
    private ClientAssertionAuthentication authenticationWithAuthServerUrl;
    private String sampleWit;

    @BeforeEach
    void setUp() {
        authentication = new ClientAssertionAuthentication();
        authenticationWithAuthServerUrl = new ClientAssertionAuthentication("https://auth-server.example.com/token");
        sampleWit = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJhZ2VudC1pZHAtZXhhbXBsZSIsInN1YiI6Indvcmtsb2FkLXN1YmplY3QiLCJhdWQiOiJodHRwczovL2FzLmV4YW1wbGUuY29tL3Rva2VuIiwiZXhwIjoxNzMxNjY4MTAwLCJpYXQiOjE3MzE2NjQ1MDAsImp0aSI6InVybjp1dWlkOjEyMzQ1Njc4LTkwYWItY2RlZi0xMjM0LTU2Nzg5MGFiY2RlZiJ9.signature";
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create authentication with no-arg constructor")
        void shouldCreateAuthenticationWithNoArgConstructor() {
            assertThat(authentication).isNotNull();
        }

        @Test
        @DisplayName("Should create authentication with authorization server URL")
        void shouldCreateAuthenticationWithAuthorizationServerUrl() {
            assertThat(authenticationWithAuthServerUrl).isNotNull();
        }
    }

    @Nested
    @DisplayName("Apply Authentication Tests")
    class ApplyAuthenticationTests {

        @Test
        @DisplayName("Should apply authentication to request with client assertion in request body")
        void shouldApplyAuthenticationToRequestWithClientAssertion() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, sampleWit);
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isNotNull();
            assertThat(requestBody).containsKey("client_assertion_type");
            assertThat(requestBody).containsKey(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM);
            
            assertThat(requestBody.get("client_assertion_type"))
                    .isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            assertThat(requestBody.get(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM)).isEqualTo(sampleWit);
        }

        @Test
        @DisplayName("Should keep client assertion in request body after authentication")
        void shouldKeepClientAssertionInRequestBodyAfterAuthentication() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, sampleWit);
            
            authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(requestBody).containsKey(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM);
        }

        @Test
        @DisplayName("Should throw IllegalStateException when client assertion is not in request body")
        void shouldThrowIllegalStateExceptionWhenClientAssertionNotInRequestBody() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client_assertion not found in request body");
        }

        @Test
        @DisplayName("Should throw IllegalStateException when client assertion is null")
        void shouldThrowIllegalStateExceptionWhenClientAssertionIsNull() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, null);
            
            assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client_assertion not found in request body");
        }

        @Test
        @DisplayName("Should throw IllegalStateException when client assertion is blank")
        void shouldThrowIllegalStateExceptionWhenClientAssertionIsBlank() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, "   ");
            
            assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client_assertion not found in request body");
        }

        @Test
        @DisplayName("Should preserve existing request body parameters")
        void shouldPreserveExistingRequestBodyParameters() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("existing_param", "existing_value");
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, sampleWit);
            
            authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(requestBody).containsKey("existing_param");
            assertThat(requestBody.get("existing_param")).isEqualTo("existing_value");
        }

        @Test
        @DisplayName("Should not modify request builder")
        void shouldNotModifyRequestBuilder() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM, sampleWit);
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isSameAs(requestBuilder);
        }

        // This test is removed because the new implementation no longer wraps RuntimeException
        // It only throws IllegalStateException directly

        @Nested
        @DisplayName("Apply Authentication Tests - Standard private_key_jwt Mode")
        class StandardPrivateKeyJwtModeTests {

            @Test
            @DisplayName("Should generate client assertion from workload private key")
            void shouldGenerateClientAssertionFromWorkloadPrivateKey() throws JOSEException {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                
                ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
                requestBody.put("client_id", "test-client-id");
                requestBody.put("workload_private_key", ecKey.toJSONString());
                
                // When
                HttpRequest.Builder result = authenticationWithAuthServerUrl.applyAuthentication(requestBuilder, requestBody);
                
                // Then
                assertThat(result).isNotNull();
                assertThat(requestBody).containsKey("client_assertion");
                assertThat(requestBody).containsKey("client_assertion_type");
                assertThat(requestBody.get("client_assertion_type"))
                        .isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                assertThat(requestBody).doesNotContainKey("workload_private_key");
            }

            @Test
            @DisplayName("Should throw exception when workload_private_key is present but client_id is missing")
            void shouldThrowExceptionWhenWorkloadPrivateKeyIsPresentButClientIdIsMissing() throws JOSEException {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                
                ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
                requestBody.put("workload_private_key", ecKey.toJSONString());
                
                // When & Then
                // The IllegalStateException is wrapped in a RuntimeException by the catch block
                assertThatThrownBy(() -> 
                        authenticationWithAuthServerUrl.applyAuthentication(requestBuilder, requestBody))
                        .isInstanceOf(RuntimeException.class)
                        .hasMessageContaining("client_id not found in request body");
            }

            @Test
            @DisplayName("Should not generate assertion when authorizationServerUrl is null")
            void shouldNotGenerateAssertionWhenAuthorizationServerUrlIsNull() throws JOSEException {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                
                ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
                requestBody.put("client_id", "test-client-id");
                requestBody.put("workload_private_key", ecKey.toJSONString());
                requestBody.put("client_assertion", sampleWit);
                
                // When
                HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
                
                // Then - Should use pre-signed assertion instead
                assertThat(result).isNotNull();
                assertThat(requestBody.get("client_assertion")).isEqualTo(sampleWit);
                assertThat(requestBody).containsKey("workload_private_key");
            }

            @Test
            @DisplayName("Should preserve existing request body parameters when generating assertion")
            void shouldPreserveExistingRequestBodyParametersWhenGeneratingAssertion() throws JOSEException {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                
                ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
                requestBody.put("client_id", "test-client-id");
                requestBody.put("workload_private_key", ecKey.toJSONString());
                requestBody.put("scope", "openid profile");
                requestBody.put("grant_type", "client_credentials");
                
                // When
                HttpRequest.Builder result = authenticationWithAuthServerUrl.applyAuthentication(requestBuilder, requestBody);
                
                // Then
                assertThat(result).isNotNull();
                assertThat(requestBody).containsKey("scope");
                assertThat(requestBody).containsKey("grant_type");
                assertThat(requestBody.get("scope")).isEqualTo("openid profile");
                assertThat(requestBody.get("grant_type")).isEqualTo("client_credentials");
            }
        }

        @Nested
        @DisplayName("Apply Authentication Tests - Pre-signed Assertion Mode")
        class PreSignedAssertionModeTests {

            @Test
            @DisplayName("Should apply pre-signed client assertion authentication")
            void shouldApplyPreSignedClientAssertionAuthentication() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_assertion", sampleWit);
                
                // When
                HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
                
                // Then
                assertThat(result).isNotNull();
                assertThat(requestBody).containsKey("client_assertion_type");
                assertThat(requestBody.get("client_assertion_type"))
                        .isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                assertThat(requestBody.get("client_assertion")).isEqualTo(sampleWit);
            }

            @Test
            @DisplayName("Should throw exception when client assertion is not in request body")
            void shouldThrowExceptionWhenClientAssertionNotInRequestBody() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                
                // When & Then
                assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("client_assertion not found in request body");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is null")
            void shouldThrowExceptionWhenClientAssertionIsNull() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_assertion", null);
                
                // When & Then
                assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("client_assertion not found in request body");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is blank")
            void shouldThrowExceptionWhenClientAssertionIsBlank() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_assertion", "   ");
                
                // When & Then
                assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, requestBody))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("client_assertion not found in request body");
            }

            @Test
            @DisplayName("Should preserve existing request body parameters")
            void shouldPreserveExistingRequestBodyParameters() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("existing_param", "existing_value");
                requestBody.put("client_assertion", sampleWit);
                
                // When
                HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
                
                // Then
                assertThat(requestBody).containsKey("existing_param");
                assertThat(requestBody.get("existing_param")).isEqualTo("existing_value");
            }

            @Test
            @DisplayName("Should not modify request builder")
            void shouldNotModifyRequestBuilder() {
                // Given
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://example.com/token"));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_assertion", sampleWit);
                
                // When
                HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
                
                // Then
                assertThat(result).isSameAs(requestBuilder);
            }
        }
    }

    @Nested
    @DisplayName("Get Authentication Method Tests")
    class GetAuthenticationMethodTests {

        @Test
        @DisplayName("Should return private_key_jwt as authentication method")
        void shouldReturnPrivateKeyJwtAsAuthenticationMethod() {
            assertThat(authentication.getAuthenticationMethod()).isEqualTo("private_key_jwt");
        }
    }

    @Nested
    @DisplayName("Get Client ID Tests")
    class GetClientIdTests {

        @Test
        @DisplayName("Should return null as client ID")
        void shouldReturnNullAsClientId() {
            assertThat(authentication.getClientId()).isNull();
        }
    }

    @Nested
    @DisplayName("Client Assertion Parameter Key Tests")
    class ClientAssertionParameterKeyTests {

        @Test
        @DisplayName("Should have CLIENT_ASSERTION_PARAM constant")
        void shouldHaveClientAssertionParamConstant() {
            assertThat(ClientAssertionAuthentication.CLIENT_ASSERTION_PARAM).isEqualTo("client_assertion");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle request body with only client assertion")
        void shouldHandleRequestBodyWithOnlyClientAssertion() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("client_assertion", sampleWit);
            
            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            // Then
            assertThat(result).isNotNull();
            assertThat(requestBody).hasSize(2); // client_assertion_type, client_assertion
        }

        @Test
        @DisplayName("Should handle request body with existing parameters and client assertion")
        void shouldHandleRequestBodyWithExistingParametersAndClientAssertion() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("scope", "openid profile");
            requestBody.put("response_type", "code");
            requestBody.put("client_assertion", sampleWit);
            
            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            // Then
            assertThat(result).isNotNull();
            assertThat(requestBody).hasSize(4);
            assertThat(requestBody).containsKey("scope");
            assertThat(requestBody).containsKey("response_type");
        }

        @Test
        @DisplayName("Should handle client assertion with special characters")
        void shouldHandleClientAssertionWithSpecialCharacters() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            String specialWit = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            requestBody.put("client_assertion", specialWit);
            
            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            // Then
            assertThat(result).isNotNull();
            assertThat(requestBody.get("client_assertion")).isEqualTo(specialWit);
        }

        @Test
        @DisplayName("Should handle blank authorizationServerUrl when workload_private_key is present")
        void shouldHandleBlankAuthorizationServerUrlWhenWorkloadPrivateKeyIsPresent() throws JOSEException {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
            requestBody.put("client_id", "test-client-id");
            requestBody.put("workload_private_key", ecKey.toJSONString());
            requestBody.put("client_assertion", sampleWit);
            
            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            // Then - Should use pre-signed assertion instead
            assertThat(result).isNotNull();
            assertThat(requestBody.get("client_assertion")).isEqualTo(sampleWit);
            assertThat(requestBody).containsKey("workload_private_key");
        }
    }
}