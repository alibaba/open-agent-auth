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

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("DefaultOpaHttpResponse Tests")
class DefaultOpaHttpResponseTest {

    @Nested
    @DisplayName("Constructor and Delegation Tests")
    class ConstructorAndDelegationTests {

        @Test
        @DisplayName("Should return status code from wrapped HttpResponse")
        @SuppressWarnings("unchecked")
        void shouldReturnStatusCodeFromWrappedHttpResponse() {
            // Arrange
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(200);

            // Act
            DefaultOpaHttpResponse<String> response = new DefaultOpaHttpResponse<>(mockResponse);

            // Assert
            assertThat(response.statusCode()).isEqualTo(200);
        }

        @Test
        @DisplayName("Should return body from wrapped HttpResponse")
        @SuppressWarnings("unchecked")
        void shouldReturnBodyFromWrappedHttpResponse() {
            // Arrange
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.body()).thenReturn("{\"result\": true}");

            // Act
            DefaultOpaHttpResponse<String> response = new DefaultOpaHttpResponse<>(mockResponse);

            // Assert
            assertThat(response.body()).isEqualTo("{\"result\": true}");
        }

        @Test
        @DisplayName("Should handle non-200 status code")
        @SuppressWarnings("unchecked")
        void shouldHandleNon200StatusCode() {
            // Arrange
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(404);
            when(mockResponse.body()).thenReturn("Not Found");

            // Act
            DefaultOpaHttpResponse<String> response = new DefaultOpaHttpResponse<>(mockResponse);

            // Assert
            assertThat(response.statusCode()).isEqualTo(404);
            assertThat(response.body()).isEqualTo("Not Found");
        }

        @Test
        @DisplayName("Should handle null body")
        @SuppressWarnings("unchecked")
        void shouldHandleNullBody() {
            // Arrange
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(204);
            when(mockResponse.body()).thenReturn(null);

            // Act
            DefaultOpaHttpResponse<String> response = new DefaultOpaHttpResponse<>(mockResponse);

            // Assert
            assertThat(response.statusCode()).isEqualTo(204);
            assertThat(response.body()).isNull();
        }
    }
}
