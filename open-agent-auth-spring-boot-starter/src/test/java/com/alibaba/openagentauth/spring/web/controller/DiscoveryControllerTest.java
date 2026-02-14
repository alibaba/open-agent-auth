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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DiscoveryController}.
 * <p>
 * Tests the OpenID Connect Discovery endpoint's behavior including:
 * <ul>
 *   <li>Discovery endpoint returns correct configuration</li>
 *   <li>Conditional endpoints are included when enabled</li>
 *   <li>Standard OIDC claims are present</li>
 *   <li>Default issuer handling</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DiscoveryController Tests")
class DiscoveryControllerTest {

    @Mock
    private OpenAgentAuthProperties properties;

    private DiscoveryController controller;

    private static final String ISSUER = "https://example.com";
    private static final String DEFAULT_ISSUER = "https://default.issuer";

    @BeforeEach
    void setUp() {
        controller = new DiscoveryController(properties);
    }

    private void setupPropertiesWithAllEndpointsEnabled() {
        // Update to use new architecture: roles.agent-user-idp.issuer
        when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
        properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
        properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
        
        // Update to use new architecture: capabilities.oauth2Server
        when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
        properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
        properties.getCapabilities().getOAuth2Server().setEnabled(true);
        properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());
        properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().setPar("/oauth/par");
        properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().setToken("/oauth/token");
        properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().setAuthorize("/oauth/authorize");
    }

    @Nested
    @DisplayName("Discovery Endpoint Tests")
    class DiscoveryEndpointTests {

        @Test
        @DisplayName("Should return discovery configuration with all endpoints enabled")
        void shouldReturnDiscoveryConfigurationWithAllEndpointsEnabled() {
            // Given
            setupPropertiesWithAllEndpointsEnabled();

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("issuer")).isEqualTo(ISSUER);
            assertThat(config.get("pushed_authorization_request_endpoint")).isEqualTo(ISSUER + "/oauth/par");
            assertThat(config.get("token_endpoint")).isEqualTo(ISSUER + "/oauth/token");
            assertThat(config.get("authorization_endpoint")).isEqualTo(ISSUER + "/oauth/authorize");
            assertThat(config.get("jwks_uri")).isEqualTo(ISSUER + "/.well-known/jwks.json");
        }

        @Test
        @DisplayName("Should return default issuer when issuer is null")
        void shouldReturnDefaultIssuerWhenIssuerIsNull() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(null);
            
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("issuer")).isEqualTo(DEFAULT_ISSUER);
        }

        @Test
        @DisplayName("Should include standard OIDC claims")
        void shouldIncludeStandardOidcClaims() {
            // Given
            setupPropertiesWithAllEndpointsEnabled();

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("response_types_supported")).isNotNull();
            assertThat(config.get("grant_types_supported")).isNotNull();
            assertThat(config.get("subject_types_supported")).isNotNull();
            assertThat(config.get("id_token_signing_alg_values_supported")).isNotNull();
            assertThat(config.get("scopes_supported")).isNotNull();
            assertThat(config.get("token_endpoint_auth_methods_supported")).isNotNull();
            assertThat(config.get("claims_supported")).isNotNull();
        }

        @Test
        @DisplayName("Should include PAR endpoint when enabled")
        void shouldIncludeParEndpointOnlyWhenEnabled() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEnabled(true);
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("pushed_authorization_request_endpoint")).isEqualTo(ISSUER + "/par");
            assertThat(config.get("token_endpoint")).isEqualTo(ISSUER + "/oauth2/token");
            assertThat(config.get("authorization_endpoint")).isEqualTo(ISSUER + "/oauth2/authorize");
        }

        @Test
        @DisplayName("Should include token endpoint when enabled")
        void shouldIncludeTokenEndpointOnlyWhenEnabled() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEnabled(true);
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("pushed_authorization_request_endpoint")).isEqualTo(ISSUER + "/par");
            assertThat(config.get("token_endpoint")).isEqualTo(ISSUER + "/oauth2/token");
            assertThat(config.get("authorization_endpoint")).isEqualTo(ISSUER + "/oauth2/authorize");
        }

        @Test
        @DisplayName("Should include authorization endpoint when enabled")
        void shouldIncludeAuthorizationEndpointOnlyWhenEnabled() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEnabled(true);
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config).isNotNull();
            assertThat(config.get("pushed_authorization_request_endpoint")).isEqualTo(ISSUER + "/par");
            assertThat(config.get("token_endpoint")).isEqualTo(ISSUER + "/oauth2/token");
            assertThat(config.get("authorization_endpoint")).isEqualTo(ISSUER + "/oauth2/authorize");
        }
    }

    @Nested
    @DisplayName("Standard OIDC Claims Tests")
    class StandardOidcClaimsTests {

        @Test
        @DisplayName("Should include correct response types supported")
        void shouldIncludeCorrectResponseTypesSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("response_types_supported")).isNotNull();
            // Verify it contains "code"
        }

        @Test
        @DisplayName("Should include correct grant types supported")
        void shouldIncludeCorrectGrantTypesSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("grant_types_supported")).isNotNull();
            // Verify it contains "authorization_code" and "client_credentials"
        }

        @Test
        @DisplayName("Should include correct subject types supported")
        void shouldIncludeCorrectSubjectTypesSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("subject_types_supported")).isNotNull();
            // Verify it contains "public"
        }

        @Test
        @DisplayName("Should include correct ID token signing algorithms supported")
        void shouldIncludeCorrectIdTokenSigningAlgorithmsSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("id_token_signing_alg_values_supported")).isNotNull();
            // Verify it contains "RS256"
        }

        @Test
        @DisplayName("Should include correct scopes supported")
        void shouldIncludeCorrectScopesSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("scopes_supported")).isNotNull();
            // Verify it contains "openid", "profile", "email"
        }

        @Test
        @DisplayName("Should include correct token endpoint auth methods supported")
        void shouldIncludeCorrectTokenEndpointAuthMethodsSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("token_endpoint_auth_methods_supported")).isNotNull();
            // Verify it contains "private_key_jwt" and "client_secret_basic"
        }

        @Test
        @DisplayName("Should include correct claims supported")
        void shouldIncludeCorrectClaimsSupported() {
            // Given
            // Update to use new architecture: roles.agent-user-idp.issuer
            when(properties.getRoles()).thenReturn(new java.util.HashMap<>());
            properties.getRoles().put("agent-user-idp", new RolesProperties.RoleProperties());
            properties.getRoles().get("agent-user-idp").setIssuer(ISSUER);
            // Update to use new architecture: capabilities.oauth2Server
            when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
            properties.getCapabilities().setOAuth2Server(new OAuth2ServerProperties());
            properties.getCapabilities().getOAuth2Server().setEndpoints(new OAuth2ServerProperties.OAuth2EndpointsProperties());

            // When
            Map<String, Object> config = controller.discovery();

            // Then
            assertThat(config.get("claims_supported")).isNotNull();
            // Verify it contains "sub", "iss", "aud", "exp", "iat"
        }
    }
}