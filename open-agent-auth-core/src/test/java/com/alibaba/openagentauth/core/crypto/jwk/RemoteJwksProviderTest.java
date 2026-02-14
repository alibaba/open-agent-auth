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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link RemoteJwksProvider}.
 * <p>
 * Tests the remote JWKS provider functionality including:
 * </p>
 * <ul>
 *   <li>Creating provider with URL and URL string</li>
 *   <li>Getting JWK source and JWK set</li>
 *   <li>Refresh functionality</li>
 *   <li>Error handling for invalid URLs</li>
 *   <li>Getter methods for JWKS URL</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("RemoteJwksProvider Tests")
class RemoteJwksProviderTest {

    private static final String TEST_JWKS_URL = "https://example.com/.well-known/jwks.json";
    private static final String INVALID_URL = "not-a-valid-url";

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create provider with valid URL")
        void shouldCreateProviderWithValidUrl() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            assertThat(provider).isNotNull();
            assertThat(provider.getJwksUrl()).isEqualTo(url);
        }

        @Test
        @DisplayName("Should create provider with valid URL string")
        void shouldCreateProviderWithValidUrlString() throws Exception {
            RemoteJwksProvider provider = new RemoteJwksProvider(TEST_JWKS_URL);

            assertThat(provider).isNotNull();
            assertThat(provider.getJwksUrl().toString()).isEqualTo(TEST_JWKS_URL);
        }

        @Test
        @DisplayName("Should throw exception when URL is null")
        void shouldThrowExceptionWhenUrlIsNull() {
            assertThatThrownBy(() -> new RemoteJwksProvider((URL) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWKS URL");
        }

        @Test
        @DisplayName("Should throw exception when URL string is null")
        void shouldThrowExceptionWhenUrlStringIsNull() {
            assertThatThrownBy(() -> new RemoteJwksProvider((String) null))
                    .isInstanceOf(MalformedURLException.class);
        }

        @Test
        @DisplayName("Should throw exception when URL string is invalid")
        void shouldThrowExceptionWhenUrlStringIsInvalid() {
            assertThatThrownBy(() -> new RemoteJwksProvider(INVALID_URL))
                    .isInstanceOf(MalformedURLException.class);
        }
    }

    @Nested
    @DisplayName("JWK Source Tests")
    class JwkSourceTests {

        @Test
        @DisplayName("Should return JWK source")
        void shouldReturnJwkSource() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            assertThat(provider.getJwkSource()).isNotNull();
        }

        @Test
        @DisplayName("Should return same JWK source on multiple calls")
        void shouldReturnSameJwkSourceOnMultipleCalls() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            var source1 = provider.getJwkSource();
            var source2 = provider.getJwkSource();

            assertThat(source1).isSameAs(source2);
        }
    }

    @Nested
    @DisplayName("Get JWK Set Tests")
    class GetJwkSetTests {

        @Test
        @DisplayName("Should attempt to get JWK set")
        void shouldAttemptToGetJwkSet() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            // This will fail due to network, but we're testing the code path
            assertThatThrownBy(() -> provider.getJwkSet())
                    .isInstanceOf(IOException.class);
        }

        @Test
        @DisplayName("Should throw IOException when URL is unreachable")
        void shouldThrowIOExceptionWhenUrlIsUnreachable() throws Exception {
            URL url = new URL("https://nonexistent-domain-12345.com/.well-known/jwks.json");
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            assertThatThrownBy(() -> provider.getJwkSet())
                    .isInstanceOf(IOException.class);
        }
    }

    @Nested
    @DisplayName("Refresh Tests")
    class RefreshTests {

        @Test
        @DisplayName("Should execute refresh without throwing exception")
        void shouldExecuteRefreshWithoutThrowingException() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            // Refresh should not throw exception even if URL is unreachable
            provider.refresh();
        }

        @Test
        @DisplayName("Should execute refresh multiple times")
        void shouldExecuteRefreshMultipleTimes() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            // Multiple refresh calls should not throw exceptions
            provider.refresh();
            provider.refresh();
            provider.refresh();
        }
    }

    @Nested
    @DisplayName("Getter Methods Tests")
    class GetterMethodsTests {

        @Test
        @DisplayName("Should return correct JWKS URL")
        void shouldReturnCorrectJwksUrl() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            assertThat(provider.getJwksUrl()).isEqualTo(url);
        }

        @Test
        @DisplayName("Should return JWKS URL string")
        void shouldReturnJwksUrlString() throws Exception {
            RemoteJwksProvider provider = new RemoteJwksProvider(TEST_JWKS_URL);

            assertThat(provider.getJwksUrl().toString()).isEqualTo(TEST_JWKS_URL);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should be thread-safe for concurrent operations")
        void shouldBeThreadSafeForConcurrentOperations() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            Thread thread1 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        provider.getJwkSource();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            Thread thread2 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        provider.refresh();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should support full workflow")
        void shouldSupportFullWorkflow() throws Exception {
            URL url = new URL(TEST_JWKS_URL);
            RemoteJwksProvider provider = new RemoteJwksProvider(url);

            // Get JWK source
            var source = provider.getJwkSource();
            assertThat(source).isNotNull();

            // Get JWKS URL
            assertThat(provider.getJwksUrl()).isEqualTo(url);

            // Refresh
            provider.refresh();
        }
    }
}