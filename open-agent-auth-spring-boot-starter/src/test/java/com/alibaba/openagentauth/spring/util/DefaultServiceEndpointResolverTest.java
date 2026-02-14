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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for DefaultServiceEndpointResolver.
 * <p>
 * This test class verifies the functionality of resolving service endpoints.
 * </p>
 */
@DisplayName("DefaultServiceEndpointResolver Tests")
class DefaultServiceEndpointResolverTest {

    private DefaultServiceEndpointResolver resolver;
    private ServiceProperties serviceProperties;

    @BeforeEach
    void setUp() {
        serviceProperties = createTestServiceProperties();
        resolver = new DefaultServiceEndpointResolver(serviceProperties);
    }

    private ServiceProperties createTestServiceProperties() {
        ServiceProperties properties = new ServiceProperties();
        
        // Configure provider
        ServiceProperties.ProviderProperties provider = new ServiceProperties.ProviderProperties();
        provider.setEnabled(true);
        provider.setBaseUrl("https://provider.example.com");
        Map<String, String> providerEndpoints = new HashMap<>();
        providerEndpoints.put("authorize", "/oauth/authorize");
        providerEndpoints.put("token", "/oauth/token");
        providerEndpoints.put("userinfo", "/oauth/userinfo");
        provider.setEndpoints(providerEndpoints);
        properties.setProvider(provider);
        
        // Configure consumers
        ServiceProperties.ConsumerServiceProperties agentIdp = new ServiceProperties.ConsumerServiceProperties();
        agentIdp.setBaseUrl("https://agent-idp.example.com");
        Map<String, String> agentIdpEndpoints = new HashMap<>();
        agentIdpEndpoints.put("workload.issue", "/api/v1/workload/token/issue");
        agentIdpEndpoints.put("workload.revoke", "/api/v1/workload/revoke");
        agentIdp.setEndpoints(agentIdpEndpoints);
        
        Map<String, ServiceProperties.ConsumerServiceProperties> consumers = new HashMap<>();
        consumers.put("agent-idp", agentIdp);
        properties.setConsumers(consumers);
        
        return properties;
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create resolver with valid properties")
        void shouldCreateResolverWithValidProperties() {
            assertThat(resolver).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when properties is null")
        void shouldThrowExceptionWhenPropertiesIsNull() {
            assertThatThrownBy(() -> new DefaultServiceEndpointResolver(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ServiceProperties cannot be null");
        }
    }

    @Nested
    @DisplayName("Resolve Provider Tests")
    class ResolveProviderTests {

        @Test
        @DisplayName("Should resolve provider endpoint successfully")
        void shouldResolveProviderEndpointSuccessfully() {
            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com/oauth/token");
        }

        @Test
        @DisplayName("Should return null when provider is disabled")
        void shouldReturnNullWhenProviderIsDisabled() {
            serviceProperties.getProvider().setEnabled(false);

            String url = resolver.resolveProvider("token");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should return null when provider base URL is not configured")
        void shouldReturnNullWhenProviderBaseUrlIsNotConfigured() {
            serviceProperties.getProvider().setBaseUrl(null);

            String url = resolver.resolveProvider("token");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should return null when provider endpoint not found")
        void shouldReturnNullWhenProviderEndpointNotFound() {
            String url = resolver.resolveProvider("non-existent");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should handle base URL without trailing slash")
        void shouldHandleBaseUrlWithoutTrailingSlash() {
            serviceProperties.getProvider().setBaseUrl("https://provider.example.com");

            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com/oauth/token");
        }

        @Test
        @DisplayName("Should handle base URL with trailing slash")
        void shouldHandleBaseUrlWithTrailingSlash() {
            serviceProperties.getProvider().setBaseUrl("https://provider.example.com/");

            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com/oauth/token");
        }

        @Test
        @DisplayName("Should handle endpoint path without leading slash")
        void shouldHandleEndpointPathWithoutLeadingSlash() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("token", "oauth/token");
            serviceProperties.getProvider().setEndpoints(endpoints);

            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com/oauth/token");
        }

        @Test
        @DisplayName("Should handle endpoint path with leading slash")
        void shouldHandleEndpointPathWithLeadingSlash() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("token", "/oauth/token");
            serviceProperties.getProvider().setEndpoints(endpoints);

            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com/oauth/token");
        }

        @Test
        @DisplayName("Should throw exception when endpoint key is null")
        void shouldThrowExceptionWhenEndpointKeyIsNull() {
            assertThatThrownBy(() -> resolver.resolveProvider(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Endpoint key");
        }

        @Test
        @DisplayName("Should throw exception when endpoint key is empty")
        void shouldThrowExceptionWhenEndpointKeyIsEmpty() {
            assertThatThrownBy(() -> resolver.resolveProvider(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Endpoint key");
        }
    }

    @Nested
    @DisplayName("Resolve Consumer Tests")
    class ResolveConsumerTests {

        @Test
        @DisplayName("Should resolve consumer endpoint successfully")
        void shouldResolveConsumerEndpointSuccessfully() {
            String url = resolver.resolveConsumer("agent-idp", "workload.issue");

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/workload/token/issue");
        }

        @Test
        @DisplayName("Should return null when consumer service not found")
        void shouldReturnNullWhenConsumerServiceNotFound() {
            String url = resolver.resolveConsumer("non-existent", "workload.issue");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should return null when consumer base URL is not configured")
        void shouldReturnNullWhenConsumerBaseUrlIsNotConfigured() {
            serviceProperties.getConsumers().get("agent-idp").setBaseUrl(null);

            String url = resolver.resolveConsumer("agent-idp", "workload.issue");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should return null when consumer endpoint not found")
        void shouldReturnNullWhenConsumerEndpointNotFound() {
            String url = resolver.resolveConsumer("agent-idp", "non-existent");

            assertThat(url).isNull();
        }

        @Test
        @DisplayName("Should handle path variables")
        void shouldHandlePathVariables() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("workload.get", "/api/v1/workload/{workloadId}");
            serviceProperties.getConsumers().get("agent-idp").setEndpoints(endpoints);

            Map<String, String> pathVariables = new HashMap<>();
            pathVariables.put("workloadId", "123");

            String url = resolver.resolveConsumer("agent-idp", "workload.get", pathVariables);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/workload/123");
        }

        @Test
        @DisplayName("Should handle query parameters")
        void shouldHandleQueryParameters() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("param1", "value1");
            queryParams.put("param2", "value2");

            String url = resolver.resolveConsumer("agent-idp", "workload.issue", null, queryParams);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/workload/token/issue?param1=value1&param2=value2");
        }

        @Test
        @DisplayName("Should handle both path variables and query parameters")
        void shouldHandleBothPathVariablesAndQueryParameters() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("workload.get", "/api/v1/workload/{workloadId}");
            serviceProperties.getConsumers().get("agent-idp").setEndpoints(endpoints);

            Map<String, String> pathVariables = new HashMap<>();
            pathVariables.put("workloadId", "123");

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("detail", "true");

            String url = resolver.resolveConsumer("agent-idp", "workload.get", pathVariables, queryParams);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/workload/123?detail=true");
        }

        @Test
        @DisplayName("Should throw exception when service name is null")
        void shouldThrowExceptionWhenServiceNameIsNull() {
            assertThatThrownBy(() -> resolver.resolveConsumer(null, "workload.issue"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service name");
        }

        @Test
        @DisplayName("Should throw exception when service name is empty")
        void shouldThrowExceptionWhenServiceNameIsEmpty() {
            assertThatThrownBy(() -> resolver.resolveConsumer("", "workload.issue"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service name");
        }

        @Test
        @DisplayName("Should throw exception when endpoint key is null")
        void shouldThrowExceptionWhenEndpointKeyIsNull() {
            assertThatThrownBy(() -> resolver.resolveConsumer("agent-idp", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Endpoint key");
        }

        @Test
        @DisplayName("Should throw exception when endpoint key is empty")
        void shouldThrowExceptionWhenEndpointKeyIsEmpty() {
            assertThatThrownBy(() -> resolver.resolveConsumer("agent-idp", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Endpoint key");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle special characters in base URL")
        void shouldHandleSpecialCharactersInBaseUrl() {
            serviceProperties.getProvider().setBaseUrl("https://provider.example.com:8080/api/v1");

            String url = resolver.resolveProvider("token");

            assertThat(url).isEqualTo("https://provider.example.com:8080/api/v1/oauth/token");
        }

        @Test
        @DisplayName("Should handle special characters in path variables")
        void shouldHandleSpecialCharactersInPathVariables() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("resource.get", "/api/v1/resources/{resourceId}");
            serviceProperties.getConsumers().get("agent-idp").setEndpoints(endpoints);

            Map<String, String> pathVariables = new HashMap<>();
            pathVariables.put("resourceId", "resource-123_abc@def");

            String url = resolver.resolveConsumer("agent-idp", "resource.get", pathVariables);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/resources/resource-123_abc@def");
        }

        @Test
        @DisplayName("Should handle special characters in query parameters")
        void shouldHandleSpecialCharactersInQueryParameters() {
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("filter", "status==active&type==admin");

            String url = resolver.resolveConsumer("agent-idp", "workload.issue", null, queryParams);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/workload/token/issue?filter=status==active&type==admin");
        }

        @Test
        @DisplayName("Should handle multiple path variables")
        void shouldHandleMultiplePathVariables() {
            Map<String, String> endpoints = new HashMap<>();
            endpoints.put("nested.resource", "/api/v1/projects/{projectId}/resources/{resourceId}");
            serviceProperties.getConsumers().get("agent-idp").setEndpoints(endpoints);

            Map<String, String> pathVariables = new HashMap<>();
            pathVariables.put("projectId", "project-1");
            pathVariables.put("resourceId", "resource-2");

            String url = resolver.resolveConsumer("agent-idp", "nested.resource", pathVariables);

            assertThat(url).isEqualTo("https://agent-idp.example.com/api/v1/projects/project-1/resources/resource-2");
        }
    }
}
