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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksProviderProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link JwksController}.
 * <p>
 * Tests the JWKS endpoint controller that provides public keys in JWKS format.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("JwksController Tests")
class JwksControllerTest {

    private static final String KEY_ID = "test-key-123";
    private static final String KEY_ID_2 = "test-key-456";

    @Mock
    private OpenAgentAuthProperties properties;

    @Mock
    private KeyManager keyManager;

    @InjectMocks
    private JwksController controller;

    private KeyInfo rsaKeyInfo;
    private RSAPublicKey rsaPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RSA key pair for testing
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        // Create KeyInfo for testing
        rsaKeyInfo = KeyInfo.builder()
                .keyId(KEY_ID)
                .algorithm(KeyAlgorithm.RS256)
                .build();

        // Configure mock properties to prevent NullPointerException
        InfrastructureProperties infrastructures = new InfrastructureProperties();
        JwksInfrastructureProperties jwks = new JwksInfrastructureProperties();
        JwksProviderProperties provider = new JwksProviderProperties();
        provider.setCacheHeadersEnabled(true);
        provider.setCacheDurationSeconds(300);
        jwks.setProvider(provider);
        infrastructures.setJwks(jwks);
        
        lenient().when(properties.getInfrastructures()).thenReturn(infrastructures);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create controller with valid parameters")
        void shouldCreateControllerWithValidParameters() {
            // Act
            JwksController controller = new JwksController(properties, keyManager);

            // Assert
            assertThat(controller).isNotNull();
        }
    }

    @Nested
    @DisplayName("jwks() Endpoint Tests")
    class JwksEndpointTests {

        @Test
        @DisplayName("Should return JWKS with keys when active keys exist")
        void shouldReturnJwksWithKeysWhenActiveKeysExist() throws Exception {
            // Arrange
            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);

            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsKey("keys");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            assertThat(keys).hasSize(1);
            assertThat(keys.get(0)).containsEntry("kid", KEY_ID);
            assertThat(keys.get(0)).containsEntry("kty", "RSA");
        }

        @Test
        @DisplayName("Should return empty JWKS when no active keys exist")
        void shouldReturnEmptyJwksWhenNoActiveKeysExist() {
            // Arrange
            when(keyManager.getActiveKeys()).thenReturn(new ArrayList<>());

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsKey("keys");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            assertThat(keys).isEmpty();
        }

        @Test
        @DisplayName("Should include cache headers when cache TTL is configured")
        void shouldIncludeCacheHeadersWhenCacheTtlIsConfigured() {
            // Arrange
            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);

            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getCacheControl()).isNotNull();
            assertThat(response.getHeaders().getCacheControl()).contains("max-age=300");
        }

        @Test
        @DisplayName("Should include cache headers with max-age=0 when cache TTL is zero")
        void shouldNotIncludeCacheHeadersWhenCacheTtlIsZero() {
            // Arrange
            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);

            // Override cache TTL to 0 for this test
            InfrastructureProperties infrastructures = new InfrastructureProperties();
            JwksInfrastructureProperties jwks = new JwksInfrastructureProperties();
            JwksProviderProperties provider = new JwksProviderProperties();
            provider.setCacheHeadersEnabled(true);
            provider.setCacheDurationSeconds(0);
            jwks.setProvider(provider);
            infrastructures.setJwks(jwks);
            
            when(properties.getInfrastructures()).thenReturn(infrastructures);
            
            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getCacheControl()).isNotNull();
            assertThat(response.getHeaders().getCacheControl()).contains("max-age=0");
        }

        @Test
        @DisplayName("Should handle multiple active keys")
        void shouldHandleMultipleActiveKeys() throws Exception {
            // Arrange
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey2 = (RSAPublicKey) keyPair2.getPublic();

            KeyInfo keyInfo2 = KeyInfo.builder()
                    .keyId(KEY_ID_2)
                    .algorithm(KeyAlgorithm.RS256)
                    .build();

            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);
            activeKeys.add(keyInfo2);

            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            lenient().when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);
            when(keyManager.getVerificationKey(KEY_ID_2)).thenReturn(rsaPublicKey2);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            assertThat(keys).hasSize(2);
        }

        @Test
        @DisplayName("Should skip invalid keys and continue with valid ones")
        void shouldSkipInvalidKeysAndContinueWithValidOnes() throws Exception {
            // Arrange
            KeyInfo invalidKeyInfo = KeyInfo.builder()
                    .keyId("invalid-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .build();

            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);
            activeKeys.add(invalidKeyInfo);

            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);
            when(keyManager.getVerificationKey("invalid-key")).thenThrow(new RuntimeException("Key not found"));

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
            assertThat(keys).hasSize(1);
            assertThat(keys.get(0)).containsEntry("kid", KEY_ID);
        }

        @Test
        @DisplayName("Should return JWKS with correct structure")
        void shouldReturnJwksWithCorrectStructure() throws Exception {
            // Arrange
            List<KeyInfo> activeKeys = new ArrayList<>();
            activeKeys.add(rsaKeyInfo);

            when(keyManager.getActiveKeys()).thenReturn(activeKeys);
            when(keyManager.getVerificationKey(KEY_ID)).thenReturn(rsaPublicKey);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.jwks();

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            
            Map<String, Object> body = response.getBody();
            assertThat(body).containsKey("keys");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) body.get("keys");
            Map<String, Object> key = keys.get(0);
            
            // Verify required JWK fields
            assertThat(key).containsKey("kid");
            assertThat(key).containsKey("kty");
            assertThat(key).containsKey("e");
            assertThat(key).containsKey("n");
            assertThat(key).containsKey("alg");
        }
    }
}