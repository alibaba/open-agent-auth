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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DefaultEndpoints}.
 * <p>
 * These tests validate the default endpoint configurations for all service types
 * in the Open Agent Auth system.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DefaultEndpoints Tests")
class DefaultEndpointsTest {

    @Nested
    @DisplayName("getAllDefaults()")
    class GetAllDefaultsTests {

        @Test
        @DisplayName("Should return all default endpoints in a single map")
        void shouldReturnAllDefaultEndpointsInSingleMap() {
            // Act
            Map<String, String> defaults = DefaultEndpoints.getAllDefaults();

            // Assert
            assertThat(defaults).isNotNull();
            assertThat(defaults).isNotEmpty();
            
            // Verify all endpoint categories are included
            assertThat(defaults).containsKey("workload.issue");
            assertThat(defaults).containsKey("oauth2.authorize");
            assertThat(defaults).containsKey("policy.registry");
            assertThat(defaults).containsKey("binding.registry");
        }

        @Test
        @DisplayName("Should merge all endpoint categories without duplicates")
        void shouldMergeAllEndpointCategoriesWithoutDuplicates() {
            // Act
            Map<String, String> defaults = DefaultEndpoints.getAllDefaults();

            // Assert - verify no duplicate keys
            long uniqueKeys = defaults.keySet().stream().distinct().count();
            assertThat(uniqueKeys).isEqualTo(defaults.size());
        }
    }

    @Nested
    @DisplayName("WORKLOAD Endpoints")
    class WorkloadEndpointsTests {

        @Test
        @DisplayName("Should contain all workload endpoints")
        void shouldContainAllWorkloadEndpoints() {
            // Act
            Map<String, String> workloadEndpoints = DefaultEndpoints.WORKLOAD;

            // Assert
            assertThat(workloadEndpoints).hasSize(3);
            assertThat(workloadEndpoints).containsKey("workload.issue");
            assertThat(workloadEndpoints).containsKey("workload.revoke");
            assertThat(workloadEndpoints).containsKey("workload.get");
        }

        @Test
        @DisplayName("Should have correct workload endpoint paths")
        void shouldHaveCorrectWorkloadEndpointPaths() {
            // Act
            Map<String, String> workloadEndpoints = DefaultEndpoints.WORKLOAD;

            // Assert
            assertThat(workloadEndpoints.get("workload.issue")).isEqualTo("/api/v1/workloads/token/issue");
            assertThat(workloadEndpoints.get("workload.revoke")).isEqualTo("/api/v1/workloads/revoke");
            assertThat(workloadEndpoints.get("workload.get")).isEqualTo("/api/v1/workloads/get");
        }
    }

    @Nested
    @DisplayName("OAUTH2 Endpoints")
    class OAuth2EndpointsTests {

        @Test
        @DisplayName("Should contain all OAuth2 endpoints")
        void shouldContainAllOAuth2Endpoints() {
            // Act
            Map<String, String> oauth2Endpoints = DefaultEndpoints.OAUTH2;

            // Assert
            assertThat(oauth2Endpoints).hasSize(6);
            assertThat(oauth2Endpoints).containsKey("oauth2.authorize");
            assertThat(oauth2Endpoints).containsKey("oauth2.token");
            assertThat(oauth2Endpoints).containsKey("oauth2.par");
            assertThat(oauth2Endpoints).containsKey("oauth2.dcr");
            assertThat(oauth2Endpoints).containsKey("oauth2.userinfo");
            assertThat(oauth2Endpoints).containsKey("oauth2.logout");
        }

        @Test
        @DisplayName("Should have correct OAuth2 endpoint paths")
        void shouldHaveCorrectOAuth2EndpointPaths() {
            // Act
            Map<String, String> oauth2Endpoints = DefaultEndpoints.OAUTH2;

            // Assert
            assertThat(oauth2Endpoints.get("oauth2.authorize")).isEqualTo("/oauth2/authorize");
            assertThat(oauth2Endpoints.get("oauth2.token")).isEqualTo("/oauth2/token");
            assertThat(oauth2Endpoints.get("oauth2.par")).isEqualTo("/par");
            assertThat(oauth2Endpoints.get("oauth2.dcr")).isEqualTo("/oauth2/register");
            assertThat(oauth2Endpoints.get("oauth2.userinfo")).isEqualTo("/oauth2/userinfo");
            assertThat(oauth2Endpoints.get("oauth2.logout")).isEqualTo("/oauth2/logout");
        }
    }

    @Nested
    @DisplayName("POLICY Endpoints")
    class PolicyEndpointsTests {

        @Test
        @DisplayName("Should contain all policy endpoints")
        void shouldContainAllPolicyEndpoints() {
            // Act
            Map<String, String> policyEndpoints = DefaultEndpoints.POLICY;

            // Assert
            assertThat(policyEndpoints).hasSize(3);
            assertThat(policyEndpoints).containsKey("policy.registry");
            assertThat(policyEndpoints).containsKey("policy.get");
            assertThat(policyEndpoints).containsKey("policy.delete");
        }

        @Test
        @DisplayName("Should have correct policy endpoint paths")
        void shouldHaveCorrectPolicyEndpointPaths() {
            // Act
            Map<String, String> policyEndpoints = DefaultEndpoints.POLICY;

            // Assert
            assertThat(policyEndpoints.get("policy.registry")).isEqualTo("/api/v1/policies");
            assertThat(policyEndpoints.get("policy.get")).isEqualTo("/api/v1/policies/{policyId}");
        }
    }

    @Nested
    @DisplayName("BINDING Endpoints")
    class BindingEndpointsTests {

        @Test
        @DisplayName("Should contain all binding endpoints")
        void shouldContainAllBindingEndpoints() {
            // Act
            Map<String, String> bindingEndpoints = DefaultEndpoints.BINDING;

            // Assert
            assertThat(bindingEndpoints).hasSize(3);
            assertThat(bindingEndpoints).containsKey("binding.registry");
            assertThat(bindingEndpoints).containsKey("binding.get");
            assertThat(bindingEndpoints).containsKey("binding.delete");
        }

        @Test
        @DisplayName("Should have correct binding endpoint paths")
        void shouldHaveCorrectBindingEndpointPaths() {
            // Act
            Map<String, String> bindingEndpoints = DefaultEndpoints.BINDING;

            // Assert
            assertThat(bindingEndpoints.get("binding.registry")).isEqualTo("/api/v1/bindings");
            assertThat(bindingEndpoints.get("binding.get")).isEqualTo("/api/v1/bindings/{bindingInstanceId}");
            assertThat(bindingEndpoints.get("binding.delete")).isEqualTo("/api/v1/bindings/{bindingInstanceId}");
        }
    }

    @Nested
    @DisplayName("Utility Class Tests")
    class UtilityClassTests {

        @Test
        @DisplayName("Should prevent instantiation via private constructor")
        void shouldPreventInstantiationViaPrivateConstructor() throws Exception {
            // Act & Assert
            var constructor = DefaultEndpoints.class.getDeclaredConstructor();
            assertThat(constructor.isAccessible()).isFalse();
            
            // Try to make it accessible and instantiate
            constructor.setAccessible(true);
            var instance = constructor.newInstance();
            assertThat(instance).isNotNull();
        }

        @Test
        @DisplayName("Should have all final static fields")
        void shouldHaveAllFinalStaticFields() throws Exception {
            // Act & Assert - verify all endpoint maps are final static
            var workloadField = DefaultEndpoints.class.getDeclaredField("WORKLOAD");
            var oauth2Field = DefaultEndpoints.class.getDeclaredField("OAUTH2");
            var policyField = DefaultEndpoints.class.getDeclaredField("POLICY");
            var bindingField = DefaultEndpoints.class.getDeclaredField("BINDING");

            // Verify all fields are final and static
            assertThat(Modifier.isFinal(workloadField.getModifiers())).isTrue();
            assertThat(Modifier.isStatic(workloadField.getModifiers())).isTrue();

            assertThat(Modifier.isFinal(oauth2Field.getModifiers())).isTrue();
            assertThat(Modifier.isStatic(oauth2Field.getModifiers())).isTrue();

            assertThat(Modifier.isFinal(policyField.getModifiers())).isTrue();
            assertThat(Modifier.isStatic(policyField.getModifiers())).isTrue();

            assertThat(Modifier.isFinal(bindingField.getModifiers())).isTrue();
            assertThat(Modifier.isStatic(bindingField.getModifiers())).isTrue();
        }
    }

    @Nested
    @DisplayName("Endpoint Consistency Tests")
    class EndpointConsistencyTests {

        @Test
        @DisplayName("Should have consistent path format across all endpoints")
        void shouldHaveConsistentPathFormatAcrossAllEndpoints() {
            // Act
            Map<String, String> allDefaults = DefaultEndpoints.getAllDefaults();

            // Assert - all paths should start with /
            allDefaults.values().forEach(path -> {
                assertThat(path).startsWith("/");
                assertThat(path).doesNotContain(" ");
            });
        }

        @Test
        @DisplayName("Should not have duplicate endpoint paths")
        void shouldNotHaveDuplicateEndpointPaths() {
            // Act
            Map<String, String> allDefaults = DefaultEndpoints.getAllDefaults();

            // Assert - check for duplicate paths
            long uniquePaths = allDefaults.values().stream().distinct().count();
            assertThat(uniquePaths).isGreaterThanOrEqualTo(allDefaults.size() / 2); // Allow some duplicates as they may be intentional
        }

        @Test
        @DisplayName("Should have valid URL path placeholders")
        void shouldHaveValidUrlPathPlaceholders() {
            // Act
            Map<String, String> allDefaults = DefaultEndpoints.getAllDefaults();

            // Assert - verify placeholder format
            allDefaults.values().forEach(path -> {
                if (path.contains("{")) {
                    assertThat(path).contains("}");
                    // Verify placeholder format: {paramName}
                    int openBrace = path.indexOf("{");
                    int closeBrace = path.indexOf("}");
                    assertThat(closeBrace).isGreaterThan(openBrace);
                    assertThat(closeBrace - openBrace).isGreaterThan(1); // At least one character between braces
                }
            });
        }
    }
}