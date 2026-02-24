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
package com.alibaba.openagentauth.core.crypto.key.resolve;

import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link LocalKeyResolver}.
 */
@DisplayName("LocalKeyResolver Tests")
class LocalKeyResolverTest {

    private KeyManager keyManager;
    private LocalKeyResolver localKeyResolver;

    @BeforeEach
    void setUp() {
        keyManager = new DefaultKeyManager(new InMemoryKeyStore());
        localKeyResolver = new LocalKeyResolver(keyManager);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when KeyManager is null")
        void shouldThrowExceptionWhenKeyManagerIsNull() {
            assertThatThrownBy(() -> new LocalKeyResolver(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("KeyManager cannot be null");
        }

        @Test
        @DisplayName("Should create LocalKeyResolver with valid KeyManager")
        void shouldCreateLocalKeyResolverWithValidKeyManager() {
            LocalKeyResolver resolver = new LocalKeyResolver(keyManager);

            assertThat(resolver).isNotNull();
        }
    }

    @Nested
    @DisplayName("Supports Tests")
    class SupportsTests {

        @Test
        @DisplayName("Should return true for local key definition")
        void shouldReturnTrueForLocalKeyDefinition() {
            KeyDefinition localKeyDefinition = KeyDefinition.builder()
                    .keyId("local-key")
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .build();

            assertThat(localKeyResolver.supports(localKeyDefinition)).isTrue();
        }

        @Test
        @DisplayName("Should return false for remote key definition")
        void shouldReturnFalseForRemoteKeyDefinition() {
            KeyDefinition remoteKeyDefinition = KeyDefinition.builder()
                    .keyId("remote-key")
                    .algorithm(KeyAlgorithm.ES256)
                    .jwksConsumer("agent-idp")
                    .build();

            assertThat(localKeyResolver.supports(remoteKeyDefinition)).isFalse();
        }

        @Test
        @DisplayName("Should return false for null key definition")
        void shouldReturnFalseForNullKeyDefinition() {
            assertThat(localKeyResolver.supports(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("Resolve Tests")
    class ResolveTests {

        @Test
        @DisplayName("Should resolve local key with ES256 algorithm successfully")
        void shouldResolveLocalKeyWithES256Successfully() throws Exception {
            String keyId = "es256-test-key";
            keyManager.generateKeyPair(KeyAlgorithm.ES256, keyId);

            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId(keyId)
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .build();

            JWK resolvedKey = localKeyResolver.resolve(keyDefinition);

            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(ECKey.class);
            assertThat(resolvedKey.getKeyID()).isEqualTo(keyId);
        }

        @Test
        @DisplayName("Should auto-generate key when key does not exist but algorithm is provided")
        void shouldAutoGenerateKeyWhenNotExistButAlgorithmProvided() throws Exception {
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("auto-generated-key")
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .build();

            JWK resolvedKey = localKeyResolver.resolve(keyDefinition);

            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(ECKey.class);
            assertThat(resolvedKey.getKeyID()).isEqualTo("auto-generated-key");
        }

        @Test
        @DisplayName("Should throw KeyResolutionException when key does not exist and no algorithm")
        void shouldThrowExceptionWhenKeyDoesNotExistAndNoAlgorithm() {
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("non-existent-key")
                    .build();

            assertThatThrownBy(() -> localKeyResolver.resolve(keyDefinition))
                    .isInstanceOf(KeyResolutionException.class)
                    .hasMessageContaining("non-existent-key");
        }
    }

    @Nested
    @DisplayName("GetOrder Tests")
    class GetOrderTests {

        @Test
        @DisplayName("Should return 0 as the order")
        void shouldReturnZeroAsOrder() {
            assertThat(localKeyResolver.getOrder()).isEqualTo(0);
        }
    }
}
