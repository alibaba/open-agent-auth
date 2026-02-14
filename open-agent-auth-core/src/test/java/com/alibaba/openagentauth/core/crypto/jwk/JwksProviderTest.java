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
package com.alibaba.openagentauth.core.crypto.jwk;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for JwksProvider interface contract.
 * <p>
 * This test suite verifies the contract of JwksProvider implementations,
 * ensuring they correctly provide JWK sets and handle error conditions.
 * </p>
 *
 * @see JwksProvider
 * @since 1.0
 */
@DisplayName("JwksProvider Contract Tests")
class JwksProviderTest {

    @Nested
    @DisplayName("getJwkSource() method tests")
    class GetJwkSourceTests {

        @Test
        @DisplayName("Should return non-null JWKSource when provider is properly configured")
        void shouldReturnNonNullJwkSourceWhenProviderIsProperlyConfigured() throws IOException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();

            // Act
            JWKSource<SecurityContext> source = provider.getJwkSource();

            // Assert
            assertNotNull(source, "JWKSource should not be null");
        }

        @Test
        @DisplayName("Should return JWKSource that can retrieve keys")
        void shouldReturnJwkSourceThatCanRetrieveKeys() throws IOException, KeySourceException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());

            // Act
            JWKSource<SecurityContext> source = provider.getJwkSource();
            List<JWK> keys = source.get(selector, null);

            // Assert
            assertNotNull(keys, "Retrieved keys should not be null");
            assertFalse(keys.isEmpty(), "JWKSource should be able to retrieve keys");
        }

        @Test
        @DisplayName("Should throw IOException when provider fails to retrieve keys")
        void shouldThrowIOExceptionWhenProviderFailsToRetrieveKeys() {
            // Arrange
            JwksProvider provider = new FailingJwksProvider();

            // Act & Assert
            assertThrows(IOException.class, provider::getJwkSource,
                    "Should throw IOException when retrieval fails");
        }
    }

    @Nested
    @DisplayName("getJwkSet() method tests")
    class GetJwkSetTests {

        @Test
        @DisplayName("Should return non-null JWKSet when provider is properly configured")
        void shouldReturnNonNullJwkSetWhenProviderIsProperlyConfigured() throws IOException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert
            assertNotNull(jwkSet, "JWKSet should not be null");
        }

        @Test
        @DisplayName("Should return JWKSet containing at least one key")
        void shouldReturnJwkSetContainingAtLeastOneKey() throws IOException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();

            // Act
            JWKSet jwkSet = provider.getJwkSet();
            List<JWK> keys = jwkSet.getKeys();

            // Assert
            assertFalse(keys.isEmpty(), "JWKSet should contain at least one key");
        }

        @Test
        @DisplayName("Should return JWKSet with valid RSA keys")
        void shouldReturnJwkSetWithValidRsaKeys() throws IOException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();

            // Act
            JWKSet jwkSet = provider.getJwkSet();
            List<JWK> keys = jwkSet.getKeys();

            // Assert
            assertFalse(keys.isEmpty(), "JWKSet should contain keys");
            assertTrue(keys.get(0) instanceof RSAKey, "Key should be RSA key");
        }

        @Test
        @DisplayName("Should throw IOException when provider fails to retrieve JWKSet")
        void shouldThrowIOExceptionWhenProviderFailsToRetrieveJwkSet() {
            // Arrange
            JwksProvider provider = new FailingJwksProvider();

            // Act & Assert
            assertThrows(IOException.class, provider::getJwkSet,
                    "Should throw IOException when retrieval fails");
        }
    }

    @Nested
    @DisplayName("refresh() method tests")
    class RefreshTests {

        @Test
        @DisplayName("Should successfully refresh cached keys")
        void shouldSuccessfullyRefreshCachedKeys() throws IOException {
            // Arrange
            TestJwksProvider provider = new TestJwksProvider();
            JWKSet initialJwkSet = provider.getJwkSet();

            // Act
            provider.refresh();
            JWKSet refreshedJwkSet = provider.getJwkSet();

            // Assert
            assertNotNull(refreshedJwkSet, "Refreshed JWKSet should not be null");
            assertEquals(initialJwkSet.getKeys().size(), refreshedJwkSet.getKeys().size(),
                    "Refreshed JWKSet should maintain key count");
        }

        @Test
        @DisplayName("Should throw IOException when refresh fails")
        void shouldThrowIOExceptionWhenRefreshFails() {
            // Arrange
            JwksProvider provider = new FailingJwksProvider();

            // Act & Assert
            assertThrows(IOException.class, provider::refresh,
                    "Should throw IOException when refresh fails");
        }
    }

    @Nested
    @DisplayName("Integration tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should maintain consistency between getJwkSource and getJwkSet")
        void shouldMaintainConsistencyBetweenGetJwkSourceAndGetJwkSet() throws IOException, KeySourceException {
            // Arrange
            JwksProvider provider = new TestJwksProvider();
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());

            // Act
            List<JWK> fromSource = provider.getJwkSource().get(selector, null);
            List<JWK> fromMethod = provider.getJwkSet().getKeys();

            // Assert
            assertEquals(fromSource.size(), fromMethod.size(),
                    "Both methods should return consistent key counts");
        }

        @Test
        @DisplayName("Should handle multiple refresh operations correctly")
        void shouldHandleMultipleRefreshOperationsCorrectly() throws IOException {
            // Arrange
            TestJwksProvider provider = new TestJwksProvider();

            // Act
            JWKSet first = provider.getJwkSet();
            provider.refresh();
            JWKSet second = provider.getJwkSet();
            provider.refresh();
            JWKSet third = provider.getJwkSet();

            // Assert
            assertNotNull(first, "First retrieval should succeed");
            assertNotNull(second, "Second retrieval should succeed");
            assertNotNull(third, "Third retrieval should succeed");
            assertEquals(first.getKeys().size(), second.getKeys().size(),
                    "Keys should remain consistent after first refresh");
            assertEquals(second.getKeys().size(), third.getKeys().size(),
                    "Keys should remain consistent after second refresh");
        }
    }

    /**
     * Test implementation of JwksProvider for testing purposes.
     */
    private static class TestJwksProvider implements JwksProvider {
        private JWKSource<SecurityContext> jwkSource;
        private JWKSet jwkSet;

        TestJwksProvider() throws IOException {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();
                
                RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyID("test-key-id")
                        .build();
                
                this.jwkSet = new JWKSet(Collections.singletonList(rsaKey));
                this.jwkSource = (jwkSelector, context) -> jwkSelector.select(jwkSet);
            } catch (Exception e) {
                throw new IOException("Failed to initialize test JWK set", e);
            }
        }

        @Override
        public JWKSource<SecurityContext> getJwkSource() {
            return jwkSource;
        }

        @Override
        public JWKSet getJwkSet() {
            return jwkSet;
        }

        @Override
        public void refresh() throws IOException {
            // Simulate refresh by re-initializing
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();
                
                RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyID("test-key-id")
                        .build();
                
                this.jwkSet = new JWKSet(Collections.singletonList(rsaKey));
                this.jwkSource = (jwkSelector, context) -> jwkSelector.select(jwkSet);
            } catch (Exception e) {
                throw new IOException("Failed to refresh JWK set", e);
            }
        }
    }

    /**
     * Failing test implementation of JwksProvider for error testing.
     */
    private static class FailingJwksProvider implements JwksProvider {
        @Override
        public JWKSource<SecurityContext> getJwkSource() throws IOException {
            throw new IOException("Failed to retrieve JWK source");
        }

        @Override
        public JWKSet getJwkSet() throws IOException {
            throw new IOException("Failed to retrieve JWK set");
        }

        @Override
        public void refresh() throws IOException {
            throw new IOException("Failed to refresh keys");
        }
    }
}