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
package com.alibaba.openagentauth.framework.model.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AgentAuthorizationContext}.
 * <p>
 * This test class verifies the behavior of the AgentAuthorizationContext class,
 * including builder pattern, immutability, and thread safety.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentAuthorizationContext Tests")
class AgentAuthorizationContextTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build context with all fields")
        void shouldBuildContextWithAllFields() {
            Map<String, String> headers = new HashMap<>();
            headers.put("X-Custom-Header", "value");

            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wit("wit-token")
                .wpt("wpt-token")
                .aoat("aoat-token")
                .additionalHeaders(headers)
                .build();

            assertThat(context.getWit()).isEqualTo("wit-token");
            assertThat(context.getWpt()).isEqualTo("wpt-token");
            assertThat(context.getAoat()).isEqualTo("aoat-token");
            assertThat(context.getAdditionalHeaders()).containsExactlyInAnyOrderEntriesOf(headers);
        }

        @Test
        @DisplayName("Should build context with only wit")
        void shouldBuildContextWithOnlyWit() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wit("wit-token")
                .build();

            assertThat(context.getWit()).isEqualTo("wit-token");
            assertThat(context.getWpt()).isNull();
            assertThat(context.getAoat()).isNull();
            assertThat(context.getAdditionalHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should build context with only wpt")
        void shouldBuildContextWithOnlyWpt() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wpt("wpt-token")
                .build();

            assertThat(context.getWit()).isNull();
            assertThat(context.getWpt()).isEqualTo("wpt-token");
            assertThat(context.getAoat()).isNull();
            assertThat(context.getAdditionalHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should build context with only aoat")
        void shouldBuildContextWithOnlyAoat() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .aoat("aoat-token")
                .build();

            assertThat(context.getWit()).isNull();
            assertThat(context.getWpt()).isNull();
            assertThat(context.getAoat()).isEqualTo("aoat-token");
            assertThat(context.getAdditionalHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should build empty context")
        void shouldBuildEmptyContext() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .build();

            assertThat(context.getWit()).isNull();
            assertThat(context.getWpt()).isNull();
            assertThat(context.getAoat()).isNull();
            assertThat(context.getAdditionalHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wit("wit")
                .wpt("wpt")
                .aoat("aoat")
                .additionalHeaders(Collections.emptyMap())
                .build();

            assertThat(context).isNotNull();
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create unmodifiable additional headers map")
        void shouldCreateUnmodifiableAdditionalHeadersMap() {
            Map<String, String> headers = new HashMap<>();
            headers.put("key", "value");

            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            assertThatThrownBy(() -> {
                context.getAdditionalHeaders().put("new-key", "new-value");
            }).isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should not affect original map after build")
        void shouldNotAffectOriginalMapAfterBuild() {
            Map<String, String> headers = new HashMap<>();
            headers.put("key", "value");

            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            headers.put("new-key", "new-value");

            assertThat(context.getAdditionalHeaders()).hasSize(1);
            assertThat(context.getAdditionalHeaders()).containsKey("key");
            assertThat(context.getAdditionalHeaders()).doesNotContainKey("new-key");
        }

        @Test
        @DisplayName("Should handle null additional headers")
        void shouldHandleNullAdditionalHeaders() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(null)
                .build();

            assertThat(context.getAdditionalHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should handle empty additional headers")
        void shouldHandleEmptyAdditionalHeaders() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(Collections.emptyMap())
                .build();

            assertThat(context.getAdditionalHeaders()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return wit token")
        void shouldReturnWitToken() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wit("wit-token")
                .build();

            assertThat(context.getWit()).isEqualTo("wit-token");
        }

        @Test
        @DisplayName("Should return wpt token")
        void shouldReturnWptToken() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .wpt("wpt-token")
                .build();

            assertThat(context.getWpt()).isEqualTo("wpt-token");
        }

        @Test
        @DisplayName("Should return aoat token")
        void shouldReturnAoatToken() {
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .aoat("aoat-token")
                .build();

            assertThat(context.getAoat()).isEqualTo("aoat-token");
        }

        @Test
        @DisplayName("Should return additional headers")
        void shouldReturnAdditionalHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("key1", "value1");
            headers.put("key2", "value2");

            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            assertThat(context.getAdditionalHeaders()).hasSize(2);
            assertThat(context.getAdditionalHeaders()).containsEntry("key1", "value1");
            assertThat(context.getAdditionalHeaders()).containsEntry("key2", "value2");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should support multiple builder instances")
        void shouldSupportMultipleBuilderInstances() {
            AgentAuthorizationContext context1 = AgentAuthorizationContext.builder()
                .wit("wit1")
                .build();

            AgentAuthorizationContext context2 = AgentAuthorizationContext.builder()
                .wit("wit2")
                .build();

            assertThat(context1.getWit()).isEqualTo("wit1");
            assertThat(context2.getWit()).isEqualTo("wit2");
        }

        @Test
        @DisplayName("Should create independent instances")
        void shouldCreateIndependentInstances() {
            Map<String, String> headers = new HashMap<>();
            headers.put("key", "value");

            AgentAuthorizationContext context1 = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            AgentAuthorizationContext context2 = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            assertThat(context1).isNotSameAs(context2);
            assertThat(context1.getAdditionalHeaders()).isNotSameAs(context2.getAdditionalHeaders());
        }

        @Test
        @DisplayName("Should handle complex header values")
        void shouldHandleComplexHeaderValues() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer token123");
            headers.put("User-Agent", "TestAgent/1.0");
            headers.put("Accept", "application/json");

            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                .additionalHeaders(headers)
                .build();

            assertThat(context.getAdditionalHeaders()).hasSize(3);
            assertThat(context.getAdditionalHeaders().get("Authorization")).isEqualTo("Bearer token123");
            assertThat(context.getAdditionalHeaders().get("User-Agent")).isEqualTo("TestAgent/1.0");
            assertThat(context.getAdditionalHeaders().get("Accept")).isEqualTo("application/json");
        }
    }
}
