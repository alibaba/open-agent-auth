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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for {@link DefaultOAuth2ParRequestValidator}.
 * <p>
 * This test class validates the parameter validation logic according to RFC 9126 specification.
 * It covers normal flow, exception flow, and edge cases for all validation methods.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DefaultOAuth2ParRequestValidator Test")
class DefaultOAuth2ParRequestValidatorTest {

    private DefaultOAuth2ParRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new DefaultOAuth2ParRequestValidator();
    }

    /**
     * Helper method to create a ParRequest with null responseType using reflection.
     * This is needed because the Builder enforces non-null constraints on required fields.
     */
    private ParRequest createParRequestWithNullResponseType() {
        return createParRequestWithField("responseType", null);
    }

    /**
     * Helper method to create a ParRequest with null clientId using reflection.
     * This is needed because the Builder enforces non-null constraints on required fields.
     */
    private ParRequest createParRequestWithNullClientId() {
        return createParRequestWithField("clientId", null);
    }

    /**
     * Helper method to create a ParRequest with null redirectUri using reflection.
     * This is needed because the Builder enforces non-null constraints on required fields.
     */
    private ParRequest createParRequestWithNullRedirectUri() {
        return createParRequestWithField("redirectUri", null);
    }

    /**
     * Helper method to create a ParRequest with all required fields null using reflection.
     * This is needed because the Builder enforces non-null constraints on required fields.
     */
    private ParRequest createParRequestWithAllNulls() {
        try {
            // Create a valid ParRequest first
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            // Use reflection to set all required fields to null
            java.lang.reflect.Field responseTypeField = ParRequest.class.getDeclaredField("responseType");
            responseTypeField.setAccessible(true);
            responseTypeField.set(request, null);

            java.lang.reflect.Field clientIdField = ParRequest.class.getDeclaredField("clientId");
            clientIdField.setAccessible(true);
            clientIdField.set(request, null);

            java.lang.reflect.Field redirectUriField = ParRequest.class.getDeclaredField("redirectUri");
            redirectUriField.setAccessible(true);
            redirectUriField.set(request, null);

            return request;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create ParRequest with all nulls", e);
        }
    }

    /**
     * Helper method to create a ParRequest with null clientId and redirectUri using reflection.
     * This is needed because the Builder enforces non-null constraints on required fields.
     */
    private ParRequest createParRequestWithNullClientIdAndRedirectUri() {
        try {
            // Create a valid ParRequest first
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            // Use reflection to set clientId and redirectUri to null
            java.lang.reflect.Field clientIdField = ParRequest.class.getDeclaredField("clientId");
            clientIdField.setAccessible(true);
            clientIdField.set(request, null);

            java.lang.reflect.Field redirectUriField = ParRequest.class.getDeclaredField("redirectUri");
            redirectUriField.setAccessible(true);
            redirectUriField.set(request, null);

            return request;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create ParRequest with null clientId and redirectUri", e);
        }
    }

    /**
     * Helper method to create a ParRequest with a specific field set to null using reflection.
     * This bypasses the Builder's validation to allow testing the validator's null checks.
     *
     * @param fieldName the name of the field to set to null
     * @return a ParRequest with the specified field set to null
     */
    private ParRequest createParRequestWithField(String fieldName, Object value) {
        try {
            // Create a valid ParRequest first
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            // Use reflection to set the field to null
            java.lang.reflect.Field field = ParRequest.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(request, value);

            return request;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create ParRequest with null field: " + fieldName, e);
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create validator instance successfully")
        void shouldCreateValidatorInstanceSuccessfully() {
            assertThat(validator).isNotNull();
            assertThat(validator).isInstanceOf(OAuth2ParRequestValidator.class);
        }
    }

    @Nested
    @DisplayName("Validate Method - Normal Flow")
    class ValidateMethodNormalFlow {

        @Test
        @DisplayName("Should validate valid PAR request successfully")
        void shouldValidateValidParRequestSuccessfully() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid profile")
                    .state("state_123")
                    .requestJwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }

        @Test
        @DisplayName("Should validate request with minimal required fields")
        void shouldValidateRequestWithMinimalRequiredFields() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }

        @Test
        @DisplayName("Should validate request with empty scope")
        void shouldValidateRequestWithEmptyScope() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope("")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }

        @Test
        @DisplayName("Should validate request with null scope")
        void shouldValidateRequestWithNullScope() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope(null)
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }

        @Test
        @DisplayName("Should validate request with empty state")
        void shouldValidateRequestWithEmptyState() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .state("")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }

        @Test
        @DisplayName("Should validate request with null state")
        void shouldValidateRequestWithNullState() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .state(null)
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown means validation passed
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Null Request")
    class ValidateMethodExceptionFlowNullRequest {

        @Test
        @DisplayName("Should throw IllegalArgumentException when request is null")
        void shouldThrowIllegalArgumentExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> validator.validate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR request cannot be null");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Missing response_type")
    class ValidateMethodExceptionFlowMissingResponseType {

        @Test
        @DisplayName("Should throw ParException when response_type is null")
        void shouldThrowParExceptionWhenResponseTypeIsNull() {
            ParRequest request = createParRequestWithNullResponseType();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: response_type");
        }

        @Test
        @DisplayName("Should throw ParException when response_type is empty")
        void shouldThrowParExceptionWhenResponseTypeIsEmpty() {
            ParRequest request = ParRequest.builder()
                    .responseType("")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: response_type");
        }

        @Test
        @DisplayName("Should throw ParException when response_type is blank")
        void shouldThrowParExceptionWhenResponseTypeIsBlank() {
            ParRequest request = ParRequest.builder()
                    .responseType("   ")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: response_type");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Invalid response_type")
    class ValidateMethodExceptionFlowInvalidResponseType {

        @Test
        @DisplayName("Should throw ParException when response_type is token")
        void shouldThrowParExceptionWhenResponseTypeIsToken() {
            ParRequest request = ParRequest.builder()
                    .responseType("token")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid response_type")
                    .hasMessageContaining("Only 'code' response_type is supported");
        }

        @Test
        @DisplayName("Should throw ParException when response_type is id_token")
        void shouldThrowParExceptionWhenResponseTypeIsIdToken() {
            ParRequest request = ParRequest.builder()
                    .responseType("id_token")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid response_type");
        }

        @Test
        @DisplayName("Should throw ParException when response_type is code token")
        void shouldThrowParExceptionWhenResponseTypeIsCodeToken() {
            ParRequest request = ParRequest.builder()
                    .responseType("code token")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid response_type");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Missing client_id")
    class ValidateMethodExceptionFlowMissingClientId {

        @Test
        @DisplayName("Should throw ParException when client_id is null")
        void shouldThrowParExceptionWhenClientIdIsNull() {
            ParRequest request = createParRequestWithNullClientId();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: client_id");
        }

        @Test
        @DisplayName("Should throw ParException when client_id is empty")
        void shouldThrowParExceptionWhenClientIdIsEmpty() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: client_id");
        }

        @Test
        @DisplayName("Should throw ParException when client_id is blank")
        void shouldThrowParExceptionWhenClientIdIsBlank() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("   ")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: client_id");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Missing redirect_uri")
    class ValidateMethodExceptionFlowMissingRedirectUri {

        @Test
        @DisplayName("Should throw ParException when redirect_uri is null")
        void shouldThrowParExceptionWhenRedirectUriIsNull() {
            ParRequest request = createParRequestWithNullRedirectUri();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: redirect_uri");
        }

        @Test
        @DisplayName("Should throw ParException when redirect_uri is empty")
        void shouldThrowParExceptionWhenRedirectUriIsEmpty() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: redirect_uri");
        }

        @Test
        @DisplayName("Should throw ParException when redirect_uri is blank")
        void shouldThrowParExceptionWhenRedirectUriIsBlank() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("   ")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: redirect_uri");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Invalid redirect_uri")
    class ValidateMethodExceptionFlowInvalidRedirectUri {

        @Test
        @DisplayName("Should throw ParException when redirect_uri is not a valid URI")
        void shouldThrowParExceptionWhenRedirectUriIsNotValidUri() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("not a valid uri")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid redirect_uri")
                    .hasMessageContaining("redirect_uri must be a valid URI");
        }

        @Test
        @DisplayName("Should throw ParException when redirect_uri has invalid format")
        void shouldThrowParExceptionWhenRedirectUriHasInvalidFormat() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("http://[invalid-ipv6]")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid redirect_uri");
        }

        @Test
        @DisplayName("Should throw ParException when redirect_uri contains invalid characters")
        void shouldThrowParExceptionWhenRedirectUriContainsInvalidCharacters() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback with spaces")
                    .requestJwt("header.payload.signature")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid redirect_uri");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Missing request JWT")
    class ValidateMethodExceptionFlowMissingRequestJwt {

        @Test
        @DisplayName("Should throw ParException when request JWT is null")
        void shouldThrowParExceptionWhenRequestJwtIsNull() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt(null)
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: request");
        }

        @Test
        @DisplayName("Should throw ParException when request JWT is empty")
        void shouldThrowParExceptionWhenRequestJwtIsEmpty() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: request");
        }

        @Test
        @DisplayName("Should throw ParException when request JWT is blank")
        void shouldThrowParExceptionWhenRequestJwtIsBlank() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("   ")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Missing required parameter: request");
        }
    }

    @Nested
    @DisplayName("Validate Method - Exception Flow - Invalid request JWT format")
    class ValidateMethodExceptionFlowInvalidRequestJwtFormat {

        @Test
        @DisplayName("Should throw ParException when request JWT has only one part")
        void shouldThrowParExceptionWhenRequestJwtHasOnlyOnePart() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("onlyheader")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid request")
                    .hasMessageContaining("request must be a valid JWT with header, payload, and signature");
        }

        @Test
        @DisplayName("Should throw ParException when request JWT has only two parts")
        void shouldThrowParExceptionWhenRequestJwtHasOnlyTwoParts() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid request")
                    .hasMessageContaining("request must be a valid JWT with header, payload, and signature");
        }

        @Test
        @DisplayName("Should throw ParException when request JWT has more than three parts")
        void shouldThrowParExceptionWhenRequestJwtHasMoreThanThreeParts() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature.extra")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid request")
                    .hasMessageContaining("request must be a valid JWT with header, payload, and signature");
        }

        @Test
        @DisplayName("Should throw ParException when request JWT has no separators")
        void shouldThrowParExceptionWhenRequestJwtHasNoSeparators() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("no_separators_here")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("Invalid request");
        }
    }

    @Nested
    @DisplayName("Validate Method - Edge Cases - Valid redirect_uri formats")
    class ValidateMethodEdgeCasesValidRedirectUriFormats {

        @Test
        @DisplayName("Should validate HTTPS redirect URI")
        void shouldValidateHttpsRedirectUri() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate HTTP redirect URI")
        void shouldValidateHttpRedirectUri() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("http://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with port")
        void shouldValidateRedirectUriWithPort() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com:8443/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with query parameters")
        void shouldValidateRedirectUriWithQueryParameters() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback?param1=value1&param2=value2")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with fragment")
        void shouldValidateRedirectUriWithFragment() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback#fragment")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with path")
        void shouldValidateRedirectUriWithPath() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/auth/callback/oauth2")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with custom scheme")
        void shouldValidateRedirectUriWithCustomScheme() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("myapp://callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with localhost")
        void shouldValidateRedirectUriWithLocalhost() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("http://localhost:8080/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate redirect URI with IP address")
        void shouldValidateRedirectUriWithIpAddress() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://192.168.1.1/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }
    }

    @Nested
    @DisplayName("Validate Method - Edge Cases - Valid request JWT formats")
    class ValidateMethodEdgeCasesValidRequestJwtFormats {

        @Test
        @DisplayName("Should validate request JWT with minimal parts")
        void shouldValidateRequestJwtWithMinimalParts() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("a.b.c")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate request JWT with long parts")
        void shouldValidateRequestJwtWithLongParts() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("very_long_header_part.very_long_payload_part.very_long_signature_part")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate request JWT with special characters")
        void shouldValidateRequestJwtWithSpecialCharacters() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("eyJhbGc-iOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate request JWT with numbers")
        void shouldValidateRequestJwtWithNumbers() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("123.456.789")
                    .build();

            validator.validate(request);

            // No exception thrown
        }
    }

    @Nested
    @DisplayName("Validate Method - Edge Cases - Client ID values")
    class ValidateMethodEdgeCasesClientIdValues {

        @Test
        @DisplayName("Should validate client ID with special characters")
        void shouldValidateClientIdWithSpecialCharacters() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123-abc@xyz")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate client ID with UUID format")
        void shouldValidateClientIdWithUuidFormat() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("550e8400-e29b-41d4-a716-446655440000")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate client ID with numbers")
        void shouldValidateClientIdWithNumbers() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("123456")
                    .redirectUri("https://example.com/callback")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }
    }

    @Nested
    @DisplayName("Validate Method - Edge Cases - Scope values")
    class ValidateMethodEdgeCasesScopeValues {

        @Test
        @DisplayName("Should validate single scope")
        void shouldValidateSingleScope() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate multiple scopes")
        void shouldValidateMultipleScopes() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid profile email")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate scope with custom values")
        void shouldValidateScopeWithCustomValues() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .scope("read write delete")
                    .requestJwt("header.payload.signature")
                    .build();

            validator.validate(request);

            // No exception thrown
        }
    }

    @Nested
    @DisplayName("Validate Method - Validation Order")
    class ValidateMethodValidationOrder {

        @Test
        @DisplayName("Should validate response_type first when all parameters are missing")
        void shouldValidateResponseTypeFirstWhenAllParametersAreMissing() {
            ParRequest request = createParRequestWithAllNulls();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("response_type");
        }

        @Test
        @DisplayName("Should validate client_id second when response_type is valid but others are missing")
        void shouldValidateClientIdSecondWhenResponseTypeIsValidButOthersAreMissing() {
            ParRequest request = createParRequestWithNullClientIdAndRedirectUri();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("client_id");
        }

        @Test
        @DisplayName("Should validate redirect_uri third when response_type and client_id are valid")
        void shouldValidateRedirectUriThirdWhenResponseTypeAndClientIdAreValid() {
            ParRequest request = createParRequestWithNullRedirectUri();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("redirect_uri");
        }

        @Test
        @DisplayName("Should validate request JWT last when other required parameters are valid")
        void shouldValidateRequestJwtLastWhenOtherRequiredParametersAreValid() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback")
                    .requestJwt(null)
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("request");
        }
    }

    @Nested
    @DisplayName("Validate Method - Integration Scenarios")
    class ValidateMethodIntegrationScenarios {

        @Test
        @DisplayName("Should validate complete PAR request with all fields")
        void shouldValidateCompleteParRequestWithAllFields() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("client_123")
                    .redirectUri("https://example.com/callback?param=value")
                    .scope("openid profile email")
                    .state("abc123xyz")
                    .requestJwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should validate PAR request with minimal valid data")
        void shouldValidateParRequestWithMinimalValidData() {
            ParRequest request = ParRequest.builder()
                    .responseType("code")
                    .clientId("c")
                    .redirectUri("http://a.b/c")
                    .requestJwt("x.y.z")
                    .build();

            validator.validate(request);

            // No exception thrown
        }

        @Test
        @DisplayName("Should fail validation for first invalid parameter when multiple parameters are invalid")
        void shouldFailValidationForFirstInvalidParameterWhenMultipleParametersAreInvalid() {
            // Since Builder validates required fields, we create a valid request first
            // then test that validator catches the first validation error
            ParRequest request = ParRequest.builder()
                    .responseType("invalid")
                    .clientId("client_123")
                    .redirectUri("invalid uri")
                    .requestJwt("invalid")
                    .build();

            assertThatThrownBy(() -> validator.validate(request))
                    .isInstanceOf(ParException.class)
                    .hasMessageContaining("response_type");
        }
    }
}
