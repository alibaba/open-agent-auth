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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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
 * This test class verifies the functionality of applying client assertion
 * authentication to HTTP requests.
 * </p>
 */
@DisplayName("ClientAssertionAuthentication Tests")
class ClientAssertionAuthenticationTest {

    private ClientAssertionAuthentication authentication;
    private ClientAssertionGenerator generator;
    private String clientId;
    private String tokenEndpoint;

    @BeforeEach
    void setUp() throws JOSEException {
        clientId = "test-client-123";
        tokenEndpoint = "https://example.com/token";
        
        RSAKey signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        
        generator = new ClientAssertionGenerator(clientId, signingKey, JWSAlgorithm.RS256);
        authentication = new ClientAssertionAuthentication(clientId, generator, tokenEndpoint);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create authentication with valid parameters")
        void shouldCreateAuthenticationWithValidParameters() {
            assertThat(authentication).isNotNull();
            assertThat(authentication.getClientId()).isEqualTo(clientId);
            assertThat(authentication.getAuthenticationMethod()).isEqualTo("private_key_jwt");
        }

        @Test
        @DisplayName("Should throw exception when clientId is null")
        void shouldThrowExceptionWhenClientIdIsNull() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            ClientAssertionGenerator gen = new ClientAssertionGenerator("client", key, JWSAlgorithm.RS256);
            
            assertThatThrownBy(() -> new ClientAssertionAuthentication(null, gen, tokenEndpoint))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when clientId is empty")
        void shouldThrowExceptionWhenClientIdIsEmpty() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            ClientAssertionGenerator gen = new ClientAssertionGenerator("client", key, JWSAlgorithm.RS256);
            
            assertThatThrownBy(() -> new ClientAssertionAuthentication("", gen, tokenEndpoint))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when assertionGenerator is null")
        void shouldThrowExceptionWhenAssertionGeneratorIsNull() {
            assertThatThrownBy(() -> new ClientAssertionAuthentication(clientId, null, tokenEndpoint))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Assertion generator");
        }

        @Test
        @DisplayName("Should throw exception when tokenEndpoint is null")
        void shouldThrowExceptionWhenTokenEndpointIsNull() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            ClientAssertionGenerator gen = new ClientAssertionGenerator("client", key, JWSAlgorithm.RS256);
            
            assertThatThrownBy(() -> new ClientAssertionAuthentication(clientId, gen, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token endpoint");
        }

        @Test
        @DisplayName("Should throw exception when tokenEndpoint is empty")
        void shouldThrowExceptionWhenTokenEndpointIsEmpty() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            ClientAssertionGenerator gen = new ClientAssertionGenerator("client", key, JWSAlgorithm.RS256);
            
            assertThatThrownBy(() -> new ClientAssertionAuthentication(clientId, gen, ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token endpoint");
        }
    }

    @Nested
    @DisplayName("Apply Authentication Tests")
    class ApplyAuthenticationTests {

        @Test
        @DisplayName("Should apply authentication to request")
        void shouldApplyAuthenticationToRequest() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isNotNull();
            assertThat(requestBody).containsKey("client_id");
            assertThat(requestBody).containsKey("client_assertion_type");
            assertThat(requestBody).containsKey("client_assertion");
            
            assertThat(requestBody.get("client_id")).isEqualTo(clientId);
            assertThat(requestBody.get("client_assertion_type"))
                    .isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            assertThat(requestBody.get("client_assertion")).isNotEmpty();
        }

        @Test
        @DisplayName("Should generate valid assertion in request body")
        void shouldGenerateValidAssertionInRequestBody() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            authentication.applyAuthentication(requestBuilder, requestBody);
            
            String assertion = requestBody.get("client_assertion");
            assertThat(assertion).isNotEmpty();
            
            // Verify JWT structure
            assertThat(assertion.split("\\.")).hasSize(3); // Header.Payload.Signature
        }

        @Test
        @DisplayName("Should preserve existing request body parameters")
        void shouldPreserveExistingRequestBodyParameters() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("existing_param", "existing_value");
            
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
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isSameAs(requestBuilder);
        }

        @Test
        @DisplayName("Should throw runtime exception when assertion generation fails")
        void shouldThrowRuntimeExceptionWhenAssertionGenerationFails() throws JOSEException {
            // Create a generator that will fail
            RSAKey invalidKey = new RSAKeyGenerator(2048).keyID("key").generate();
            ClientAssertionGenerator failingGenerator = new ClientAssertionGenerator(
                    clientId, invalidKey, JWSAlgorithm.RS256) {
                @Override
                public String generateAssertion(String tokenEndpoint) {
                    throw new RuntimeException("Simulated failure");
                }
            };
            
            ClientAssertionAuthentication failingAuth = new ClientAssertionAuthentication(
                    clientId, failingGenerator, tokenEndpoint);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            assertThatThrownBy(() -> failingAuth.applyAuthentication(requestBuilder, requestBody))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Failed to apply client assertion authentication");
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
        @DisplayName("Should return correct client ID")
        void shouldReturnCorrectClientId() {
            assertThat(authentication.getClientId()).isEqualTo(clientId);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty request body")
        void shouldHandleEmptyRequestBody() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isNotNull();
            assertThat(requestBody).hasSize(3); // client_id, client_assertion_type, client_assertion
        }

        @Test
        @DisplayName("Should handle request body with existing parameters")
        void shouldHandleRequestBodyWithExistingParameters() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("scope", "openid profile");
            requestBody.put("response_type", "code");
            
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(result).isNotNull();
            assertThat(requestBody).hasSize(5);
            assertThat(requestBody).containsKey("scope");
            assertThat(requestBody).containsKey("response_type");
        }

        @Test
        @DisplayName("Should overwrite existing client_id parameter")
        void shouldOverwriteExistingClientIdParameter() {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://example.com/token"));
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("client_id", "old-client-id");
            
            authentication.applyAuthentication(requestBuilder, requestBody);
            
            assertThat(requestBody.get("client_id")).isEqualTo(clientId);
        }
    }
}
