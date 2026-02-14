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

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2DcrController}.
 * <p>
 * This test class verifies the OAuth 2.0 Dynamic Client Registration (DCR) endpoint functionality,
 * including client registration, read, update, and delete operations according to RFC 7591 and RFC 7592.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2DcrController Tests")
class OAuth2DcrControllerTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_SECRET = "test-client-secret";
    private static final String REGISTRATION_ACCESS_TOKEN = "test-registration-token";
    private static final String CLIENT_NAME = "Test Client";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String SCOPE = "openid profile email";
    private static final String AUTHORIZATION_HEADER = "Bearer " + REGISTRATION_ACCESS_TOKEN;

    @Mock
    private OAuth2DcrServer dcrServer;

    @InjectMocks
    private OAuth2DcrController controller;

    private DcrResponse mockDcrResponse;

    @BeforeEach
    void setUp() {
        mockDcrResponse = DcrResponse.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .clientIdIssuedAt(Instant.now().getEpochSecond())
                .clientSecretExpiresAt(Instant.now().plusSeconds(3600).getEpochSecond())
                .registrationAccessToken(REGISTRATION_ACCESS_TOKEN)
                .registrationClientUri("https://example.com/oauth2/register/" + CLIENT_ID)
                .clientName(CLIENT_NAME)
                .redirectUris(List.of(REDIRECT_URI))
                .scope(SCOPE)
                .grantTypes(List.of("authorization_code"))
                .responseTypes(List.of("code"))
                .tokenEndpointAuthMethod("client_secret_basic")
                .build();
    }

    @Nested
    @DisplayName("POST /oauth2/register - Client Registration")
    class RegisterClientTests {

        @Test
        @DisplayName("Should register client successfully")
        void shouldRegisterClientSuccessfully() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", CLIENT_NAME,
                    "scope", SCOPE,
                    "grant_types", List.of("authorization_code"),
                    "response_types", List.of("code"),
                    "token_endpoint_auth_method", "client_secret_basic"
            );

            when(dcrServer.registerClient(any(DcrRequest.class))).thenReturn(mockDcrResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("client_id", CLIENT_ID);
            assertThat(response.getBody()).containsEntry("client_secret", CLIENT_SECRET);
            assertThat(response.getBody()).containsEntry("client_name", CLIENT_NAME);
            assertThat(response.getBody()).containsEntry("registration_access_token", REGISTRATION_ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should handle DCR exception during registration")
        void shouldHandleDcrExceptionDuringRegistration() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", CLIENT_NAME
            );

            DcrException dcrException = DcrException.invalidRedirectUri("Invalid redirect URI");
            when(dcrServer.registerClient(any(DcrRequest.class))).thenThrow(dcrException);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", dcrException.getErrorCode());
            assertThat(response.getBody()).containsEntry("error_description", dcrException.getMessage());
        }

        @Test
        @DisplayName("Should handle unexpected error during registration")
        void shouldHandleUnexpectedErrorDuringRegistration() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", CLIENT_NAME
            );

            when(dcrServer.registerClient(any(DcrRequest.class))).thenThrow(new RuntimeException("Unexpected error"));

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "server_error");
            assertThat(response.getBody()).containsEntry("error_description", "Internal server error");
        }

        @Test
        @DisplayName("Should handle single redirect URI as string")
        void shouldHandleSingleRedirectUriAsString() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", REDIRECT_URI,
                    "client_name", CLIENT_NAME
            );

            when(dcrServer.registerClient(any(DcrRequest.class))).thenReturn(mockDcrResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).isNotNull();
        }
    }

    @Nested
    @DisplayName("GET /oauth2/register/{clientId} - Read Client")
    class ReadClientTests {

        @Test
        @DisplayName("Should read client successfully")
        void shouldReadClientSuccessfully() throws Exception {
            // Arrange
            when(dcrServer.readClient(CLIENT_ID, REGISTRATION_ACCESS_TOKEN)).thenReturn(mockDcrResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.readClient(CLIENT_ID, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("client_id", CLIENT_ID);
            assertThat(response.getBody()).containsEntry("client_name", CLIENT_NAME);
        }

        @Test
        @DisplayName("Should handle invalid authorization header")
        void shouldHandleInvalidAuthorizationHeader() throws Exception {
            // Arrange
            String invalidAuthHeader = "InvalidToken";

            // Act & Assert
            assertThatThrownBy(() -> controller.readClient(CLIENT_ID, invalidAuthHeader))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Missing or invalid Authorization header");
        }

        @Test
        @DisplayName("Should handle DCR exception during read")
        void shouldHandleDcrExceptionDuringRead() throws Exception {
            // Arrange
            DcrException dcrException = DcrException.invalidClientId("Invalid client");
            when(dcrServer.readClient(CLIENT_ID, REGISTRATION_ACCESS_TOKEN)).thenThrow(dcrException);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.readClient(CLIENT_ID, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", dcrException.getErrorCode());
            assertThat(response.getBody()).containsEntry("error_description", dcrException.getMessage());
        }
    }

    @Nested
    @DisplayName("PUT /oauth2/register/{clientId} - Update Client")
    class UpdateClientTests {

        @Test
        @DisplayName("Should update client successfully")
        void shouldUpdateClientSuccessfully() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", "Updated Client Name",
                    "scope", "openid profile"
            );

            DcrResponse updatedResponse = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .clientIdIssuedAt(Instant.now().getEpochSecond())
                    .clientSecretExpiresAt(Instant.now().plusSeconds(3600).getEpochSecond())
                    .registrationAccessToken(REGISTRATION_ACCESS_TOKEN)
                    .registrationClientUri("https://example.com/oauth2/register/" + CLIENT_ID)
                    .clientName("Updated Client Name")
                    .redirectUris(List.of(REDIRECT_URI))
                    .scope("openid profile")
                    .grantTypes(List.of("authorization_code"))
                    .responseTypes(List.of("code"))
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();

            when(dcrServer.updateClient(anyString(), anyString(), any(DcrRequest.class))).thenReturn(updatedResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.updateClient(CLIENT_ID, requestBody, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("client_id", CLIENT_ID);
            assertThat(response.getBody()).containsEntry("client_name", "Updated Client Name");
            assertThat(response.getBody()).containsEntry("scope", "openid profile");
        }

        @Test
        @DisplayName("Should handle DCR exception during update")
        void shouldHandleDcrExceptionDuringUpdate() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", "Updated Client Name"
            );

            DcrException dcrException = DcrException.invalidClientMetadata("Invalid client metadata");
            when(dcrServer.updateClient(anyString(), anyString(), any(DcrRequest.class))).thenThrow(dcrException);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.updateClient(CLIENT_ID, requestBody, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", dcrException.getErrorCode());
            assertThat(response.getBody()).containsEntry("error_description", dcrException.getMessage());
        }
    }

    @Nested
    @DisplayName("DELETE /oauth2/register/{clientId} - Delete Client")
    class DeleteClientTests {

        @Test
        @DisplayName("Should delete client successfully")
        void shouldDeleteClientSuccessfully() throws Exception {
            // Arrange
            org.mockito.Mockito.doNothing().when(dcrServer).deleteClient(CLIENT_ID, REGISTRATION_ACCESS_TOKEN);

            // Act
            ResponseEntity<Void> response = controller.deleteClient(CLIENT_ID, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        }

        @Test
        @DisplayName("Should handle DCR exception during deletion")
        void shouldHandleDcrExceptionDuringDeletion() throws Exception {
            // Arrange
            DcrException dcrException = DcrException.invalidClientId("Invalid client");
            org.mockito.Mockito.doThrow(dcrException).when(dcrServer).deleteClient(CLIENT_ID, REGISTRATION_ACCESS_TOKEN);

            // Act
            ResponseEntity<Void> response = controller.deleteClient(CLIENT_ID, AUTHORIZATION_HEADER);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    @Nested
    @DisplayName("Request Parsing Tests")
    class RequestParsingTests {

        @Test
        @DisplayName("Should parse DCR request with all fields")
        void shouldParseDcrRequestWithAllFields() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI),
                    "client_name", CLIENT_NAME,
                    "scope", SCOPE,
                    "grant_types", List.of("authorization_code", "refresh_token"),
                    "response_types", List.of("code"),
                    "token_endpoint_auth_method", "client_secret_basic"
            );

            when(dcrServer.registerClient(any(DcrRequest.class))).thenReturn(mockDcrResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        }

        @Test
        @DisplayName("Should parse DCR request with minimal fields")
        void shouldParseDcrRequestWithMinimalFields() throws Exception {
            // Arrange
            Map<String, Object> requestBody = Map.of(
                    "redirect_uris", List.of(REDIRECT_URI)
            );

            when(dcrServer.registerClient(any(DcrRequest.class))).thenReturn(mockDcrResponse);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.registerClient(requestBody);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        }
    }
}
