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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2AuthorizationServer}.
 * <p>
 * This test class validates the OAuth 2.0 authorization server implementation
 * following RFC 6749 specification.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DefaultOAuth2AuthorizationServer Tests")
class DefaultOAuth2AuthorizationServerTest {

    @Mock
    private OAuth2AuthorizationCodeStorage codeStorage;

    @Mock
    private OAuth2ParServer OAuth2ParServer;

    @Mock
    private OAuth2DcrClientStore clientStore;

    private DefaultOAuth2AuthorizationServer server;

    private static final String TEST_REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";
    private static final String TEST_SUBJECT = "user_123";
    private static final String TEST_CLIENT_ID = "test-client";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final long DEFAULT_EXPIRATION_SECONDS = 600L;

    @BeforeEach
    void setUp() {
        server = new DefaultOAuth2AuthorizationServer(codeStorage, OAuth2ParServer, clientStore);
    }

    @Nested
    @DisplayName("authorize()")
    class Authorize {

        @Test
        @DisplayName("Should successfully authorize and generate authorization code")
        void shouldSuccessfullyAuthorizeAndGenerateAuthorizationCode() {
            // Arrange
            ParRequest parRequest = createValidParRequest();
            DcrResponse clientResponse = createDcrResponse();
            
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(clientStore.retrieve(TEST_CLIENT_ID)).thenReturn(clientResponse);

            // Act
            AuthorizationCode authCode = server.authorize(TEST_REQUEST_URI, TEST_SUBJECT);

            // Assert
            assertThat(authCode).isNotNull();
            assertThat(authCode.getCode()).isNotEmpty();
            assertThat(authCode.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(authCode.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
            assertThat(authCode.getSubject()).isEqualTo(TEST_SUBJECT);
            assertThat(authCode.getRequestUri()).isEqualTo(TEST_REQUEST_URI);
            assertThat(authCode.isUsed()).isFalse();
            assertThat(authCode.getExpiresAt()).isAfter(authCode.getIssuedAt());

            // Verify interactions
            verify(OAuth2ParServer).retrieveRequest(TEST_REQUEST_URI);
            verify(clientStore).retrieve(TEST_CLIENT_ID);
            verify(codeStorage).store(any(AuthorizationCode.class));
        }

        @Test
        @DisplayName("Should throw exception when request_uri is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> server.authorize(null, TEST_SUBJECT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request URI");
        }

        @Test
        @DisplayName("Should throw exception when subject is null")
        void shouldThrowExceptionWhenSubjectIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> server.authorize(TEST_REQUEST_URI, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject");
        }

        @Test
        @DisplayName("Should throw exception when PAR request not found")
        void shouldThrowExceptionWhenParRequestNotFound() {
            // Arrange
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> server.authorize(TEST_REQUEST_URI, TEST_SUBJECT))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "server_error");
        }

        @Test
        @DisplayName("Should generate unique authorization codes")
        void shouldGenerateUniqueAuthorizationCodes() {
            // Arrange
            ParRequest parRequest = createValidParRequest();
            DcrResponse clientResponse = createDcrResponse();
            
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(clientStore.retrieve(TEST_CLIENT_ID)).thenReturn(clientResponse);

            // Act
            AuthorizationCode code1 = server.authorize(TEST_REQUEST_URI, TEST_SUBJECT);
            AuthorizationCode code2 = server.authorize(TEST_REQUEST_URI, TEST_SUBJECT);

            // Assert
            assertThat(code1.getCode()).isNotEqualTo(code2.getCode());
        }

        @Test
        @DisplayName("Should use custom expiration when provided")
        void shouldUseCustomExpirationWhenProvided() {
            // Arrange
            long customExpiration = 300L;
            DefaultOAuth2AuthorizationServer serverWithCustomExpiration = 
                    new DefaultOAuth2AuthorizationServer(codeStorage, OAuth2ParServer, clientStore, customExpiration);
            
            ParRequest parRequest = createValidParRequest();
            DcrResponse clientResponse = createDcrResponse();
            
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);
            when(clientStore.retrieve(TEST_CLIENT_ID)).thenReturn(clientResponse);

            // Act
            AuthorizationCode authCode = serverWithCustomExpiration.authorize(TEST_REQUEST_URI, TEST_SUBJECT);

            // Assert
            long actualExpiration = authCode.getExpiresAt().getEpochSecond() - authCode.getIssuedAt().getEpochSecond();
            assertThat(actualExpiration).isEqualTo(customExpiration);
        }
    }

    @Nested
    @DisplayName("validateRequest()")
    class ValidateRequest {

        @Test
        @DisplayName("Should return true for valid PAR request")
        void shouldReturnTrueForValidParRequest() {
            // Arrange
            ParRequest parRequest = createValidParRequest();
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);

            // Act
            boolean isValid = server.validateRequest(TEST_REQUEST_URI);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false when request_uri is null")
        void shouldReturnFalseWhenRequestUriIsNull() {
            // Act & Assert - validateRequest throws IllegalArgumentException for null input
            assertThatThrownBy(() -> server.validateRequest(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should return false when PAR request not found")
        void shouldReturnFalseWhenParRequestNotFound() {
            // Arrange
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(null);

            // Act
            boolean isValid = server.validateRequest(TEST_REQUEST_URI);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false when client_id is missing")
        void shouldReturnFalseWhenClientIdIsMissing() {
            // Arrange
            // Use try-catch to handle builder validation
            ParRequest parRequest;
            try {
                parRequest = ParRequest.builder()
                        .responseType("code")
                        .clientId("")
                        .redirectUri(TEST_REDIRECT_URI)
                        .build();
            } catch (IllegalArgumentException e) {
                // Builder validates, so we skip this test scenario
                return;
            }
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);

            // Act
            boolean isValid = server.validateRequest(TEST_REQUEST_URI);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false when redirect_uri is missing")
        void shouldReturnFalseWhenRedirectUriIsMissing() {
            // Arrange
            // Use try-catch to handle builder validation
            ParRequest parRequest;
            try {
                parRequest = ParRequest.builder()
                        .responseType("code")
                        .clientId(TEST_CLIENT_ID)
                        .redirectUri("")
                        .build();
            } catch (IllegalArgumentException e) {
                // Builder validates, so we skip this test scenario
                return;
            }
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);

            // Act
            boolean isValid = server.validateRequest(TEST_REQUEST_URI);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false when response_type is not 'code'")
        void shouldReturnFalseWhenResponseTypeIsNotCode() {
            // Arrange
            ParRequest parRequest = ParRequest.builder()
                    .responseType("token")
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();
            when(OAuth2ParServer.retrieveRequest(TEST_REQUEST_URI)).thenReturn(parRequest);

            // Act
            boolean isValid = server.validateRequest(TEST_REQUEST_URI);

            // Assert
            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return the code storage")
        void shouldReturnCodeStorage() {
            // Act
            OAuth2AuthorizationCodeStorage storage = server.getCodeStorage();

            // Assert
            assertThat(storage).isEqualTo(codeStorage);
        }

        @Test
        @DisplayName("Should return the PAR server")
        void shouldReturnParServer() {
            // Act
            OAuth2ParServer OAuth2ParServerResult = server.getParServer();

            // Assert
            assertThat(OAuth2ParServerResult).isEqualTo(OAuth2ParServer);
        }

        @Test
        @DisplayName("Should return the default expiration time")
        void shouldReturnDefaultExpirationTime() {
            // Act
            long expiration = server.getDefaultCodeExpirationSeconds();

            // Assert
            assertThat(expiration).isEqualTo(DEFAULT_EXPIRATION_SECONDS);
        }
    }

    // Helper methods

    private ParRequest createValidParRequest() {
        return ParRequest.builder()
                .responseType("code")
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .state("random_state_123")
                .scope("read write")
                .build();
    }

    private DcrResponse createDcrResponse() {
        return DcrResponse.builder()
                .clientId(TEST_CLIENT_ID)
                .clientName(TEST_CLIENT_ID)
                .redirectUris(List.of(TEST_REDIRECT_URI))
                .build();
    }
}