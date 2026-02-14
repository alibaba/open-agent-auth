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
package com.alibaba.openagentauth.core.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link UriQueryBuilder}.
 * Tests verify that URL query strings can be correctly constructed
 * with proper parameter encoding and separator management.
 */
@DisplayName("UriQueryBuilder Tests")
class UriQueryBuilderTest {

    private UriQueryBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new UriQueryBuilder();
    }

    @Nested
    @DisplayName("Basic Construction Tests")
    class BasicConstructionTests {

        @Test
        @DisplayName("Should build empty string when no parameters added")
        void shouldBuildEmptyStringWhenNoParametersAdded() {
            // Act
            String query = builder.build();

            // Assert
            assertThat(query).isEmpty();
        }

        @Test
        @DisplayName("Should build single parameter")
        void shouldBuildSingleParameter() {
            // Act
            String query = builder.add("param1", "value1").build();

            // Assert
            assertThat(query).isEqualTo("param1=value1");
        }

        @Test
        @DisplayName("Should build multiple parameters with & separator")
        void shouldBuildMultipleParametersWithSeparator() {
            // Act
            String query = builder.add("param1", "value1")
                    .add("param2", "value2")
                    .add("param3", "value3")
                    .build();

            // Assert
            assertThat(query).isEqualTo("param1=value1&param2=value2&param3=value3");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            // Act
            String query = builder.add("a", "1").add("b", "2").add("c", "3").build();

            // Assert
            assertThat(query).isEqualTo("a=1&b=2&c=3");
        }
    }

    @Nested
    @DisplayName("Parameter Encoding Tests")
    class ParameterEncodingTests {

        @Test
        @DisplayName("Should URL-encode parameter name and value with addEncoded")
        void shouldUrlEncodeParameterNameAndValueWithAddEncoded() {
            // Act
            String query = builder.addEncoded("client id", "my client").build();

            // Assert
            assertThat(query).isEqualTo("client+id=my+client");
        }

        @Test
        @DisplayName("Should URL-encode special characters")
        void shouldUrlEncodeSpecialCharacters() {
            // Act
            String query = builder.addEncoded("redirect_uri", "https://example.com/callback?param=value")
                    .build();

            // Assert
            assertThat(query).isEqualTo("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue");
        }

        @Test
        @DisplayName("Should URL-encode spaces as plus signs")
        void shouldUrlEncodeSpacesAsPlusSigns() {
            // Act
            String query = builder.addEncoded("name", "John Doe").build();

            // Assert
            assertThat(query).isEqualTo("name=John+Doe");
        }

        @Test
        @DisplayName("Should not encode values added with add method")
        void shouldNotEncodeValuesAddedWithAddMethod() {
            // Act
            String query = builder.add("client_id", "my%20client").build();

            // Assert
            assertThat(query).isEqualTo("client_id=my%20client");
        }

        @Test
        @DisplayName("Should handle mixed add and addEncoded calls")
        void shouldHandleMixedAddAndAddEncodedCalls() {
            // Act
            String query = builder.add("client_id", "my-client")
                    .addEncoded("redirect_uri", "https://example.com")
                    .build();

            // Assert
            assertThat(query).isEqualTo("client_id=my-client&redirect_uri=https%3A%2F%2Fexample.com");
        }
    }

    @Nested
    @DisplayName("Raw Query Append Tests")
    class RawQueryAppendTests {

        @Test
        @DisplayName("Should append raw query string")
        void shouldAppendRawQueryString() {
            // Act
            String query = builder.appendRaw("existing=param").build();

            // Assert
            assertThat(query).isEqualTo("existing=param");
        }

        @Test
        @DisplayName("Should append raw query and add new parameters")
        void shouldAppendRawQueryAndAddNewParameters() {
            // Act
            String query = builder.appendRaw("existing=param")
                    .add("new_param", "value")
                    .build();

            // Assert
            assertThat(query).isEqualTo("existing=param&new_param=value");
        }

        @Test
        @DisplayName("Should ignore null raw query")
        void shouldIgnoreNullRawQuery() {
            // Act
            String query = builder.appendRaw(null).add("param", "value").build();

            // Assert
            assertThat(query).isEqualTo("param=value");
        }

        @Test
        @DisplayName("Should ignore empty raw query")
        void shouldIgnoreEmptyRawQuery() {
            // Act
            String query = builder.appendRaw("").add("param", "value").build();

            // Assert
            assertThat(query).isEqualTo("param=value");
        }

        @Test
        @DisplayName("Should ignore blank raw query")
        void shouldIgnoreBlankRawQuery() {
            // Act
            String query = builder.appendRaw("   ").add("param", "value").build();

            // Assert
            assertThat(query).isEqualTo("param=value");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when parameter name is null in add")
        void shouldThrowExceptionWhenParameterNameIsNullInAdd() {
            // Act & Assert
            assertThatThrownBy(() -> builder.add(null, "value"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Parameter name")
                    .hasMessageContaining("cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when parameter value is null in add")
        void shouldThrowExceptionWhenParameterValueIsNullInAdd() {
            // Act & Assert
            assertThatThrownBy(() -> builder.add("param", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Parameter value")
                    .hasMessageContaining("cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when parameter name is null in addEncoded")
        void shouldThrowExceptionWhenParameterNameIsNullInAddEncoded() {
            // Act & Assert
            assertThatThrownBy(() -> builder.addEncoded(null, "value"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Parameter name")
                    .hasMessageContaining("cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when parameter value is null in addEncoded")
        void shouldThrowExceptionWhenParameterValueIsNullInAddEncoded() {
            // Act & Assert
            assertThatThrownBy(() -> builder.addEncoded("param", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Parameter value")
                    .hasMessageContaining("cannot be null");
        }
    }

    @Nested
    @DisplayName("Reset Tests")
    class ResetTests {

        @Test
        @DisplayName("Should support creating new builder instance")
        void shouldSupportCreatingNewBuilderInstance() {
            // Arrange
            String firstQuery = builder.add("param1", "value1").add("param2", "value2").build();

            // Act - create a new builder instance
            UriQueryBuilder newBuilder = new UriQueryBuilder();
            String secondQuery = newBuilder.add("new_param", "new_value").build();

            // Assert
            assertThat(firstQuery).isEqualTo("param1=value1&param2=value2");
            assertThat(secondQuery).isEqualTo("new_param=new_value");
        }
    }

    @Nested
    @DisplayName("Real-World Scenarios")
    class RealWorldScenariosTests {

        @Test
        @DisplayName("Should build OAuth2 authorization request URL")
        void shouldBuildOAuth2AuthorizationRequestUrl() {
            // Act
            String query = new UriQueryBuilder()
                    .add("response_type", "code")
                    .add("client_id", "my-client-id")
                    .addEncoded("redirect_uri", "https://example.com/callback")
                    .add("scope", "openid profile email")
                    .add("state", "xyz123")
                    .build();

            // Assert
            assertThat(query).contains("response_type=code");
            assertThat(query).contains("client_id=my-client-id");
            assertThat(query).contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
            assertThat(query).contains("scope=openid profile email");
            assertThat(query).contains("state=xyz123");
        }

        @Test
        @DisplayName("Should build DCR request with WIT parameter")
        void shouldBuildDcrRequestWithWitParameter() {
            // Act
            String query = new UriQueryBuilder()
                    .add("grant_type", "client_credentials")
                    .addEncoded("wit", "eyJhbGciOiJSUzI1NiIsInR5cCI6IndpdCtqd3QifQ...")
                    .add("scope", "agent:operation")
                    .build();

            // Assert
            assertThat(query).contains("grant_type=client_credentials");
            assertThat(query).contains("wit=eyJhbGciOiJSUzI1NiIsInR5cCI6IndpdCtqd3QifQ...");
            assertThat(query).contains("scope=agent:operation");
        }

        @Test
        @DisplayName("Should handle query with many parameters")
        void shouldHandleQueryWithManyParameters() {
            // Act
            String query = builder.add("p1", "v1")
                    .add("p2", "v2")
                    .add("p3", "v3")
                    .add("p4", "v4")
                    .add("p5", "v5")
                    .build();

            // Assert
            assertThat(query).isEqualTo("p1=v1&p2=v2&p3=v3&p4=v4&p5=v5");
        }
    }

    @Nested
    @DisplayName("Builder State Tests")
    class BuilderStateTests {

        @Test
        @DisplayName("Should build empty string from new builder instance")
        void shouldBuildEmptyStringFromNewBuilderInstance() {
            // Act & Assert
            assertThat(new UriQueryBuilder().build()).isEmpty();
        }

        @Test
        @DisplayName("Should build non-empty string after adding parameter")
        void shouldBuildNonEmptyStringAfterAddingParameter() {
            // Act
            String query = new UriQueryBuilder().add("param", "value").build();

            // Assert
            assertThat(query).isNotEmpty();
            assertThat(query).isEqualTo("param=value");
        }

        @Test
        @DisplayName("Should build different query strings from different builder instances")
        void shouldBuildDifferentQueryStringsFromDifferentBuilderInstances() {
            // Arrange
            UriQueryBuilder builder1 = new UriQueryBuilder();
            UriQueryBuilder builder2 = new UriQueryBuilder();

            // Act
            builder1.add("param1", "value1");
            builder2.add("param2", "value2");

            // Assert
            assertThat(builder1.build()).isEqualTo("param1=value1");
            assertThat(builder2.build()).isEqualTo("param2=value2");
        }
    }
}
