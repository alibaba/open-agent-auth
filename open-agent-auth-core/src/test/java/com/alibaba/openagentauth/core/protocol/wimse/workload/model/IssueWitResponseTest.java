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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("IssueWitResponse Tests")
class IssueWitResponseTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build IssueWitResponse with wit")
        void shouldBuildIssueWitResponseWithWit() {
            // Act
            IssueWitResponse response = IssueWitResponse.builder()
                    .wit("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getWit()).isEqualTo("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...");
        }

        @Test
        @DisplayName("Should build IssueWitResponse without wit")
        void shouldBuildIssueWitResponseWithoutWit() {
            // Act
            IssueWitResponse response = IssueWitResponse.builder().build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getWit()).isNull();
        }
    }

    @Nested
    @DisplayName("Static Factory Method Tests")
    class StaticFactoryMethodTests {

        @Test
        @DisplayName("Should create error response")
        void shouldCreateErrorResponse() {
            // Act
            IssueWitResponse response = IssueWitResponse.error("Something went wrong");

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getError()).isEqualTo("Something went wrong");
            assertThat(response.getWit()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get wit")
        void shouldSetAndGetWit() {
            // Arrange
            IssueWitResponse response = new IssueWitResponse();

            // Act
            response.setWit("new.wit.value");

            // Assert
            assertThat(response.getWit()).isEqualTo("new.wit.value");
        }

        @Test
        @DisplayName("Should set and get error")
        void shouldSetAndGetError() {
            // Arrange
            IssueWitResponse response = new IssueWitResponse();

            // Act
            response.setError("error message");

            // Assert
            assertThat(response.getError()).isEqualTo("error message");
        }
    }
}
