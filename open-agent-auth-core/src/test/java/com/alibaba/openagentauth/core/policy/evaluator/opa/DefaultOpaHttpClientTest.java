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
package com.alibaba.openagentauth.core.policy.evaluator.opa;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DefaultOpaHttpClient Tests")
class DefaultOpaHttpClientTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create client with default constructor")
        void shouldCreateClientWithDefaultConstructor() {
            // Act
            DefaultOpaHttpClient client = new DefaultOpaHttpClient();

            // Assert
            assertThat(client).isNotNull();
        }

        @Test
        @DisplayName("Should create client with timeout")
        void shouldCreateClientWithTimeout() {
            // Act
            DefaultOpaHttpClient client = new DefaultOpaHttpClient(Duration.ofSeconds(30));

            // Assert
            assertThat(client).isNotNull();
        }

        @Test
        @DisplayName("Should create client with custom HttpClient")
        void shouldCreateClientWithCustomHttpClient() {
            // Arrange
            HttpClient httpClient = HttpClient.newHttpClient();

            // Act
            DefaultOpaHttpClient client = new DefaultOpaHttpClient(httpClient);

            // Assert
            assertThat(client).isNotNull();
        }
    }
}
