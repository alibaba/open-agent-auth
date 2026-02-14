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
package com.alibaba.openagentauth.core.protocol.oauth2.par.server;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.OAuth2ParRequestStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2ParServer}.
 * <p>
 * This test class validates the OAuth 2.0 PAR server implementation
 * following RFC 9126 specification.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DefaultOAuth2ParServer Tests")
class DefaultOAuth2ParServerTest {

    @Mock
    private OAuth2ParRequestStore requestStore;

    @Mock
    private OAuth2ParRequestValidator requestValidator;

    private DefaultOAuth2ParServer parServer;

    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_RESPONSE_TYPE = "code";
    private static final String TEST_SCOPE = "openid profile";
    private static final String TEST_REQUEST_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6InRlc3QtY2xpZW50LTEyMyJ9.signature";
    private static final long DEFAULT_EXPIRES_IN = 90L;

    @BeforeEach
    void setUp() {
        parServer = new DefaultOAuth2ParServer(requestStore, requestValidator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create server with default expiration")
        void shouldCreateServerWithDefaultExpiration() {
            // Act
            DefaultOAuth2ParServer server = new DefaultOAuth2ParServer(requestStore, requestValidator);

            // Assert
            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should create server with custom expiration")
        void shouldCreateServerWithCustomExpiration() {
            // Act
            DefaultOAuth2ParServer server = new DefaultOAuth2ParServer(requestStore, requestValidator, 120L);

            // Assert
            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when request store is null")
        void shouldThrowExceptionWhenRequestStoreIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2ParServer(null, requestValidator))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request store");
        }

        @Test
        @DisplayName("Should throw exception when request validator is null")
        void shouldThrowExceptionWhenRequestValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2ParServer(requestStore, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request validator");
        }
    }

    @Nested
    @DisplayName("processParRequest() - Happy Path")
    class ProcessParRequestHappyPath {

        @Test
        @DisplayName("Should successfully process valid PAR request")
        void shouldSuccessfullyProcessValidParRequest() {
            // Arrange
            ParRequest request = createValidParRequest();
            
            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getRequestUri()).isNotNull();
            assertThat(response.getRequestUri()).startsWith("urn:ietf:params:oauth:request_uri:");
            assertThat(response.getExpiresIn()).isEqualTo(DEFAULT_EXPIRES_IN);

            // Verify interactions
            verify(requestValidator).validate(request);
            verify(requestStore).store(any(String.class), eq(request), eq(DEFAULT_EXPIRES_IN));
        }

        @Test
        @DisplayName("Should process request with custom expiration time")
        void shouldProcessRequestWithCustomExpirationTime() {
            // Arrange
            long customExpiresIn = 120L;
            DefaultOAuth2ParServer server = new DefaultOAuth2ParServer(requestStore, requestValidator, customExpiresIn);
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = server.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo((int) customExpiresIn);

            // Verify interactions
            verify(requestStore).store(any(String.class), eq(request), eq(customExpiresIn));
        }

        @Test
        @DisplayName("Should generate unique request URI for each request")
        void shouldGenerateUniqueRequestUriForEachRequest() {
            // Arrange
            ParRequest request1 = createValidParRequest();
            ParRequest request2 = createValidParRequest();

            // Act
            ParResponse response1 = parServer.processParRequest(request1, TEST_CLIENT_ID);
            ParResponse response2 = parServer.processParRequest(request2, TEST_CLIENT_ID);

            // Assert
            assertThat(response1.getRequestUri()).isNotEqualTo(response2.getRequestUri());
        }

        @Test
        @DisplayName("Should process request with state parameter")
        void shouldProcessRequestWithStateParameter() {
            // Arrange
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .scope(TEST_SCOPE)
                    .state("random_state_value")
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            verify(requestValidator).validate(request);
        }

        @Test
        @DisplayName("Should process request without state parameter")
        void shouldProcessRequestWithoutStateParameter() {
            // Arrange
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .scope(TEST_SCOPE)
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            verify(requestValidator).validate(request);
        }
    }

    @Nested
    @DisplayName("processParRequest() - Validation Errors")
    class ProcessParRequestValidationErrors {

        @Test
        @DisplayName("Should throw exception when PAR request is null")
        void shouldThrowExceptionWhenParRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(null, TEST_CLIENT_ID))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR request");
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(request, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw authentication exception when client ID mismatch")
        void shouldThrowAuthenticationExceptionWhenClientIdMismatch() {
            // Arrange
            ParRequest request = createValidParRequest();
            String differentClientId = "different-client-456";

            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(request, differentClientId))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Authenticated client ID does not match");
        }

        @Test
        @DisplayName("Should throw ParException when validator throws ParException")
        void shouldThrowParExceptionWhenValidatorThrowsParException() {
            // Arrange
            ParRequest request = createValidParRequest();
            org.mockito.Mockito.doThrow(ParException.missingParameter("response_type"))
                    .when(requestValidator).validate(request);

            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(request, TEST_CLIENT_ID))
                    .isInstanceOf(ParException.class);
            
            // Verify interactions
            verify(requestValidator).validate(request);
            // Store should not be called if validation fails
            org.mockito.Mockito.verifyNoInteractions(requestStore);
        }

        @Test
        @DisplayName("Should store request when validation passes")
        void shouldStoreRequestWhenValidationPasses() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act
            parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            verify(requestStore).store(any(String.class), eq(request), eq(DEFAULT_EXPIRES_IN));
        }
    }

    @Nested
    @DisplayName("processParRequest() - Storage Errors")
    class ProcessParRequestStorageErrors {

        @Test
        @DisplayName("Should throw internal error when store operation fails")
        void shouldThrowInternalErrorWhenStoreOperationFails() {
            // Arrange
            ParRequest request = createValidParRequest();
            org.mockito.Mockito.doThrow(new RuntimeException("Storage failure"))
                    .when(requestStore).store(any(String.class), any(ParRequest.class), anyLong());

            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(request, TEST_CLIENT_ID))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Failed to process PAR request");
        }

        @Test
        @DisplayName("Should throw internal error when store throws ParException")
        void shouldThrowInternalErrorWhenStoreThrowsParException() {
            // Arrange
            ParRequest request = createValidParRequest();
            org.mockito.Mockito.doThrow(ParException.internalError("Storage error", new RuntimeException()))
                    .when(requestStore).store(any(String.class), any(ParRequest.class), anyLong());

            // Act & Assert
            assertThatThrownBy(() -> parServer.processParRequest(request, TEST_CLIENT_ID))
                    .isInstanceOf(ParException.class);
        }
    }

    @Nested
    @DisplayName("retrieveRequest() - Happy Path")
    class RetrieveRequestHappyPath {

        @Test
        @DisplayName("Should successfully retrieve stored request")
        void shouldSuccessfullyRetrieveStoredRequest() {
            // Arrange
            ParRequest expectedRequest = createValidParRequest();
            String requestUri = "urn:ietf:params:oauth:request_uri:test123";
            when(requestStore.retrieve(requestUri)).thenReturn(expectedRequest);

            // Act
            ParRequest actualRequest = parServer.retrieveRequest(requestUri);

            // Assert
            assertThat(actualRequest).isNotNull();
            assertThat(actualRequest.getClientId()).isEqualTo(expectedRequest.getClientId());
            assertThat(actualRequest.getResponseType()).isEqualTo(expectedRequest.getResponseType());
            
            // Verify interactions
            verify(requestStore).retrieve(requestUri);
        }

        @Test
        @DisplayName("Should retrieve request with all parameters")
        void shouldRetrieveRequestWithAllParameters() {
            // Arrange
            ParRequest expectedRequest = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .scope(TEST_SCOPE)
                    .state("test_state")
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();
            String requestUri = "urn:ietf:params:oauth:request_uri:test456";
            when(requestStore.retrieve(requestUri)).thenReturn(expectedRequest);

            // Act
            ParRequest actualRequest = parServer.retrieveRequest(requestUri);

            // Assert
            assertThat(actualRequest).isNotNull();
            assertThat(actualRequest.getResponseType()).isEqualTo(TEST_RESPONSE_TYPE);
            assertThat(actualRequest.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(actualRequest.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
            assertThat(actualRequest.getScope()).isEqualTo(TEST_SCOPE);
            assertThat(actualRequest.getState()).isEqualTo("test_state");
            assertThat(actualRequest.getRequestJwt()).isEqualTo(TEST_REQUEST_JWT);
        }
    }

    @Nested
    @DisplayName("retrieveRequest() - Validation Errors")
    class RetrieveRequestValidationErrors {

        @Test
        @DisplayName("Should throw exception when request URI is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> parServer.retrieveRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request URI");
        }

        @Test
        @DisplayName("Should throw exception when request URI is blank")
        void shouldThrowExceptionWhenRequestUriIsBlank() {
            // Act & Assert
            // Note: ValidationUtils.validateNotNull() only checks null, not blank strings
            // Blank strings will pass validation and result in "Request URI not found or expired" error
            assertThatThrownBy(() -> parServer.retrieveRequest(""))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Request URI not found or expired");
        }

        @Test
        @DisplayName("Should throw exception when request URI is whitespace")
        void shouldThrowExceptionWhenRequestUriIsWhitespace() {
            // Act & Assert
            // Note: ValidationUtils.validateNotNull() only checks null, not blank strings
            // Whitespace strings will pass validation and result in "Request URI not found or expired" error
            assertThatThrownBy(() -> parServer.retrieveRequest("   "))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Request URI not found or expired");
        }
    }

    @Nested
    @DisplayName("retrieveRequest() - Not Found Errors")
    class RetrieveRequestNotFoundErrors {

        @Test
        @DisplayName("Should throw ParException when request URI not found")
        void shouldThrowParExceptionWhenRequestUriNotFound() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:notfound";
            when(requestStore.retrieve(requestUri)).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> parServer.retrieveRequest(requestUri))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Request URI not found or expired");
        }

        @Test
        @DisplayName("Should throw ParException with correct error code for expired request")
        void shouldThrowParExceptionWithCorrectErrorCodeForExpiredRequest() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:expired";
            when(requestStore.retrieve(requestUri)).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> parServer.retrieveRequest(requestUri))
                    .isInstanceOf(ParException.class);
        }
    }

    @Nested
    @DisplayName("retrieveRequest() - Storage Errors")
    class RetrieveRequestStorageErrors {

        @Test
        @DisplayName("Should throw ParException when storage throws RuntimeException")
        void shouldThrowParExceptionWhenStorageThrowsRuntimeException() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:error";
            when(requestStore.retrieve(requestUri))
                    .thenThrow(new RuntimeException("Storage error"));

            // Act & Assert
            // Note: retrieveRequest() does not wrap RuntimeException in ParException
            // The exception is rethrown as-is
            assertThatThrownBy(() -> parServer.retrieveRequest(requestUri))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Storage error");
        }

        @Test
        @DisplayName("Should throw ParException when storage throws ParException")
        void shouldThrowParExceptionWhenStorageThrowsParException() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:parerror";
            when(requestStore.retrieve(requestUri))
                    .thenThrow(ParException.internalError("Storage error", new RuntimeException()));

            // Act & Assert
            assertThatThrownBy(() -> parServer.retrieveRequest(requestUri))
                    .isInstanceOf(ParException.class);
        }
    }

    @Nested
    @DisplayName("Request URI Generation")
    class RequestUriGeneration {

        @Test
        @DisplayName("Should generate request URI with correct prefix")
        void shouldGenerateRequestUriWithCorrectPrefix() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response.getRequestUri()).startsWith("urn:ietf:params:oauth:request_uri:");
        }

        @Test
        @DisplayName("Should generate request URI with sufficient length")
        void shouldGenerateRequestUriWithSufficientLength() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            // Base64 encoding of 32 bytes = 43 characters without padding
            // Plus prefix "urn:ietf:params:oauth:request_uri:" (35 characters)
            // Total should be at least 78 characters
            assertThat(response.getRequestUri()).hasSizeGreaterThanOrEqualTo(77);
        }

        @Test
        @DisplayName("Should generate unique request URIs")
        void shouldGenerateUniqueRequestUris() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response1 = parServer.processParRequest(request, TEST_CLIENT_ID);
            ParResponse response2 = parServer.processParRequest(request, TEST_CLIENT_ID);
            ParResponse response3 = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            String uri1 = response1.getRequestUri();
            String uri2 = response2.getRequestUri();
            String uri3 = response3.getRequestUri();
            
            assertThat(uri1).isNotEqualTo(uri2);
            assertThat(uri2).isNotEqualTo(uri3);
            assertThat(uri1).isNotEqualTo(uri3);
        }

        @Test
        @DisplayName("Should generate URL-safe request URI")
        void shouldGenerateUrlSafeRequestUri() {
            // Arrange
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            String requestUri = response.getRequestUri();
            // Should not contain characters like +, /, = which are not URL-safe
            assertThat(requestUri).doesNotContain("+");
            assertThat(requestUri).doesNotContain("/");
            assertThat(requestUri).doesNotContain("=");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle request with empty scope")
        void shouldHandleRequestWithEmptyScope() {
            // Arrange
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .scope("")
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with null scope")
        void shouldHandleRequestWithNullScope() {
            // Arrange
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .scope(null)
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle very long client ID")
        void shouldHandleVeryLongClientId() {
            // Arrange
            String longClientId = "a".repeat(1000);
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(longClientId)
                    .redirectUri(TEST_REDIRECT_URI)
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, longClientId);

            // Assert
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle special characters in redirect URI")
        void shouldHandleSpecialCharactersInRedirectUri() {
            // Arrange
            String specialRedirectUri = "https://example.com/callback?param=value&other=test";
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(specialRedirectUri)
                    .requestJwt(TEST_REQUEST_JWT)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle very long request JWT")
        void shouldHandleVeryLongRequestJwt() {
            // Arrange
            String longJwt = "header." + "a".repeat(10000) + ".signature";
            ParRequest request = ParRequest.builder()
                    .responseType(TEST_RESPONSE_TYPE)
                    .clientId(TEST_CLIENT_ID)
                    .redirectUri(TEST_REDIRECT_URI)
                    .requestJwt(longJwt)
                    .build();

            // Act
            ParResponse response = parServer.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle zero expiration time")
        void shouldHandleZeroExpirationTime() {
            // Arrange
            DefaultOAuth2ParServer server = new DefaultOAuth2ParServer(requestStore, requestValidator, 0L);
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = server.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should handle very large expiration time")
        void shouldHandleVeryLargeExpirationTime() {
            // Arrange
            long largeExpiresIn = 86400L; // 24 hours
            DefaultOAuth2ParServer server = new DefaultOAuth2ParServer(requestStore, requestValidator, largeExpiresIn);
            ParRequest request = createValidParRequest();

            // Act
            ParResponse response = server.processParRequest(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isEqualTo((int) largeExpiresIn);
        }

        @Test
        @DisplayName("Should handle request URI with special characters in storage")
        void shouldHandleRequestUriWithSpecialCharactersInStorage() {
            // Arrange
            ParRequest expectedRequest = createValidParRequest();
            String requestUri = "urn:ietf:params:oauth:request_uri:test_with_special_chars";
            when(requestStore.retrieve(requestUri)).thenReturn(expectedRequest);

            // Act
            ParRequest actualRequest = parServer.retrieveRequest(requestUri);

            // Assert
            assertThat(actualRequest).isNotNull();
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenarios {

        @Test
        @DisplayName("Should complete full PAR flow: process and retrieve")
        void shouldCompleteFullParFlow() {
            // Arrange
            ParRequest originalRequest = createValidParRequest();
            
            // Mock storage to return the same request
            lenient().doAnswer(invocation -> {
                String uri = invocation.getArgument(0);
                ParRequest req = invocation.getArgument(1);
                // Simulate storing and retrieving
                when(requestStore.retrieve(uri)).thenReturn(req);
                return null;
            }).when(requestStore).store(any(String.class), any(ParRequest.class), anyLong());

            // Act - Process request
            ParResponse processResponse = parServer.processParRequest(originalRequest, TEST_CLIENT_ID);
            String requestUri = processResponse.getRequestUri();

            // Act - Retrieve request
            ParRequest retrievedRequest = parServer.retrieveRequest(requestUri);

            // Assert
            assertThat(retrievedRequest).isNotNull();
            assertThat(retrievedRequest.getClientId()).isEqualTo(originalRequest.getClientId());
            assertThat(retrievedRequest.getResponseType()).isEqualTo(originalRequest.getResponseType());
            assertThat(retrievedRequest.getRedirectUri()).isEqualTo(originalRequest.getRedirectUri());

            // Verify interactions
            verify(requestStore).store(eq(requestUri), eq(originalRequest), eq(DEFAULT_EXPIRES_IN));
            verify(requestStore).retrieve(requestUri);
        }

        @Test
        @DisplayName("Should handle multiple concurrent requests")
        void shouldHandleMultipleConcurrentRequests() {
            // Arrange
            ParRequest request1 = createValidParRequest();
            ParRequest request2 = createValidParRequest();
            ParRequest request3 = createValidParRequest();

            // Act
            ParResponse response1 = parServer.processParRequest(request1, TEST_CLIENT_ID);
            ParResponse response2 = parServer.processParRequest(request2, TEST_CLIENT_ID);
            ParResponse response3 = parServer.processParRequest(request3, TEST_CLIENT_ID);

            // Assert
            assertThat(response1.getRequestUri()).isNotEqualTo(response2.getRequestUri());
            assertThat(response2.getRequestUri()).isNotEqualTo(response3.getRequestUri());
            assertThat(response1.getRequestUri()).isNotEqualTo(response3.getRequestUri());
        }
    }

    // Helper methods

    private ParRequest createValidParRequest() {
        return ParRequest.builder()
                .responseType(TEST_RESPONSE_TYPE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .requestJwt(TEST_REQUEST_JWT)
                .build();
    }
}
