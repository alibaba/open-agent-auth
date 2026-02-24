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

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link JwksConsumerKeyResolver}.
 */
@DisplayName("JwksConsumerKeyResolver Tests")
class JwksConsumerKeyResolverTest {

    private JwksConsumerKeyResolver resolver;
    private Map<String, String> consumerEndpoints;

    @BeforeEach
    void setUp() {
        consumerEndpoints = new HashMap<>();
        consumerEndpoints.put("agent-idp", "https://idp.example.com/.well-known/jwks.json");
        consumerEndpoints.put("another-idp", "https://another.example.com/jwks");
        resolver = new JwksConsumerKeyResolver(consumerEndpoints);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when consumerEndpoints is null")
        void shouldThrowExceptionWhenConsumerEndpointsIsNull() {
            assertThatThrownBy(() -> new JwksConsumerKeyResolver(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Consumer endpoints map cannot be null");
        }

        @Test
        @DisplayName("Should create resolver with empty map")
        void shouldCreateResolverWithEmptyMap() {
            JwksConsumerKeyResolver emptyResolver = new JwksConsumerKeyResolver(Collections.emptyMap());

            assertThat(emptyResolver).isNotNull();
        }

        @Test
        @DisplayName("Should create resolver with non-empty map")
        void shouldCreateResolverWithNonEmptyMap() {
            assertThat(resolver).isNotNull();
        }
    }

    @Nested
    @DisplayName("Supports Tests")
    class SupportsTests {

        @Test
        @DisplayName("Should return false for null key definition")
        void shouldReturnFalseForNullKeyDefinition() {
            assertThat(resolver.supports(null)).isFalse();
        }

        @Test
        @DisplayName("Should return false for local key (no jwksConsumer)")
        void shouldReturnFalseForLocalKey() {
            KeyDefinition localKeyDefinition = KeyDefinition.builder()
                    .keyId("local-key")
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .build();

            assertThat(resolver.supports(localKeyDefinition)).isFalse();
        }

        @Test
        @DisplayName("Should return false for remote key with consumer not in endpoints")
        void shouldReturnFalseForRemoteKeyWithUnknownConsumer() {
            KeyDefinition remoteKeyDefinition = KeyDefinition.builder()
                    .keyId("remote-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("unknown-idp")
                    .build();

            assertThat(resolver.supports(remoteKeyDefinition)).isFalse();
        }

        @Test
        @DisplayName("Should return true for remote key with consumer in endpoints")
        void shouldReturnTrueForRemoteKeyWithKnownConsumer() {
            KeyDefinition remoteKeyDefinition = KeyDefinition.builder()
                    .keyId("remote-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("agent-idp")
                    .build();

            assertThat(resolver.supports(remoteKeyDefinition)).isTrue();
        }

        @Test
        @DisplayName("Should return false for remote key with blank jwksConsumer")
        void shouldReturnFalseForRemoteKeyWithBlankConsumer() {
            KeyDefinition blankConsumerKeyDefinition = KeyDefinition.builder()
                    .keyId("remote-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("  ")
                    .build();

            assertThat(resolver.supports(blankConsumerKeyDefinition)).isFalse();
        }
    }

    @Nested
    @DisplayName("GetOrder Tests")
    class GetOrderTests {

        @Test
        @DisplayName("Should return 10 as the order")
        void shouldReturnTenAsOrder() {
            assertThat(resolver.getOrder()).isEqualTo(10);
        }
    }

    @Nested
    @DisplayName("ClearCache Tests")
    class ClearCacheTests {

        @Test
        @DisplayName("Should not throw exception when clearing all cache")
        void shouldNotThrowExceptionWhenClearingAllCache() {
            assertThatCode(() -> resolver.clearCache())
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should not throw exception when clearing cache for specific consumer")
        void shouldNotThrowExceptionWhenClearingCacheForSpecificConsumer() {
            assertThatCode(() -> resolver.clearCache("agent-idp"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should not throw exception when clearing cache for non-existent consumer")
        void shouldNotThrowExceptionWhenClearingCacheForNonExistentConsumer() {
            assertThatCode(() -> resolver.clearCache("non-existent-consumer"))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Resolve Tests")
    class ResolveTests {

        @Test
        @DisplayName("Should throw KeyResolutionException when consumer not in endpoints")
        void shouldThrowExceptionWhenConsumerNotInEndpoints() {
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("test-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("unknown-consumer")
                    .build();

            assertThatThrownBy(() -> resolver.resolve(keyDefinition))
                    .isInstanceOf(KeyResolutionException.class)
                    .hasMessageContaining("No JWKS endpoint configured for consumer 'unknown-consumer'");
        }

        @Test
        @DisplayName("Should throw KeyResolutionException when endpoint is empty string")
        void shouldThrowExceptionWhenEndpointIsEmptyString() {
            Map<String, String> emptyEndpointMap = new HashMap<>();
            emptyEndpointMap.put("empty-idp", "");

            JwksConsumerKeyResolver resolverWithEmptyEndpoint = new JwksConsumerKeyResolver(emptyEndpointMap);

            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("test-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("empty-idp")
                    .build();

            assertThatThrownBy(() -> resolverWithEmptyEndpoint.resolve(keyDefinition))
                    .isInstanceOf(KeyResolutionException.class)
                    .hasMessageContaining("No JWKS endpoint configured for consumer 'empty-idp'");
        }

        @Test
        @DisplayName("Should throw KeyResolutionException when endpoint is blank string")
        void shouldThrowExceptionWhenEndpointIsBlankString() {
            Map<String, String> blankEndpointMap = new HashMap<>();
            blankEndpointMap.put("blank-idp", "   ");

            JwksConsumerKeyResolver resolverWithBlankEndpoint = new JwksConsumerKeyResolver(blankEndpointMap);

            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("test-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .jwksConsumer("blank-idp")
                    .build();

            assertThatThrownBy(() -> resolverWithBlankEndpoint.resolve(keyDefinition))
                    .isInstanceOf(KeyResolutionException.class)
                    .hasMessageContaining("No JWKS endpoint configured for consumer 'blank-idp'");
        }
    }
}
