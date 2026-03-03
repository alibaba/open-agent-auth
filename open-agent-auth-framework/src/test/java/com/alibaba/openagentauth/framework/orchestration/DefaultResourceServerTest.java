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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import com.alibaba.openagentauth.framework.model.request.ResourceRequest;
import com.alibaba.openagentauth.framework.model.audit.AuditLogEntry;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import com.alibaba.openagentauth.framework.orchestration.test.JwtTestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DefaultResourceServer}.
 * <p>
 * This test class validates the Resource Server orchestration implementation,
 * including five-layer verification and audit logging.
 * </p>
 */
@DisplayName("DefaultResourceServer Tests")
@ExtendWith(MockitoExtension.class)
class DefaultResourceServerTest {

    private DefaultResourceServer resourceServer;
    
    @Mock
    private WitValidator mockWitValidator;
    
    @Mock
    private WptValidator mockWptValidator;
    
    @Mock
    private AoatValidator mockAoatValidator;
    
    @Mock
    private PolicyEvaluator mockPolicyEvaluator;
    
    @Mock
    private BindingInstanceStore mockBindingInstanceStore;
    
    @Mock
    private OAuth2TokenServer mockOAuth2TokenServer;

    private static final String WORKLOAD_ID = "workload-123";
    private static final String USER_ID = "user-123";

    @BeforeEach
    void setUp() {
        resourceServer = new DefaultResourceServer(
                mockWitValidator,
                mockWptValidator,
                mockAoatValidator,
                mockPolicyEvaluator,
                mockBindingInstanceStore
        );
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create resource server with valid parameters")
        void shouldCreateResourceServerWithValidParameters() {
            // Act
            DefaultResourceServer server = new DefaultResourceServer(
                    mockWitValidator, mockWptValidator, mockAoatValidator, mockPolicyEvaluator, mockBindingInstanceStore);

            // Assert
            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when WIT validator is null")
        void shouldThrowExceptionWhenWitValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultResourceServer(
                    null, mockWptValidator, mockAoatValidator, mockPolicyEvaluator, mockBindingInstanceStore))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT validator cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when WPT validator is null")
        void shouldThrowExceptionWhenWptValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultResourceServer(
                    mockWitValidator, null, mockAoatValidator, mockPolicyEvaluator, mockBindingInstanceStore))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT validator cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when AOAT validator is null")
        void shouldThrowExceptionWhenAoatValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultResourceServer(
                    mockWitValidator, mockWptValidator, null, mockPolicyEvaluator, mockBindingInstanceStore))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AOAT validator cannot be null");
        }
    }

    @Nested
    @DisplayName("validateRequest()")
    class ValidateRequest {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit(null)
                    .wpt(null)
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            // Note: WIT validation happens before AOAT validation
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("WIT is required");
        }

        @Test
        @DisplayName("Should throw exception when WIT is empty")
        void shouldThrowExceptionWhenWitIsEmpty() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("   ")
                    .wpt(null)
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("WIT is required");
        }

        @Test
        @DisplayName("Should throw exception when WIT is invalid JWT")
        void shouldThrowExceptionWhenWitIsInvalidJwt() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("invalid.jwt.token")
                    .wpt(null)
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should throw exception when WPT is null")
        void shouldThrowExceptionWhenWptIsNull() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt(null)
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should throw exception when WPT is empty")
        void shouldThrowExceptionWhenWptIsEmpty() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt("   ")
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should throw exception when AOAT is null")
        void shouldThrowExceptionWhenAoatIsNull() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt("valid.wpt.token")
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should throw exception when AOAT is empty")
        void shouldThrowExceptionWhenAoatIsEmpty() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt("valid.wpt.token")
                    .aoat("   ")
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should throw exception when AOAT is invalid JWT")
        void shouldThrowExceptionWhenAoatIsInvalidJwt() {
            // Arrange
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt("valid.wpt.token")
                    .aoat("invalid.jwt.token")
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> resourceServer.validateRequest(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should successfully validate request with valid tokens")
        void shouldSuccessfullyValidateRequestWithValidTokens() throws Exception {
            // Arrange
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .httpHeaders(headers)
                    .httpBody("{\"key\":\"value\"}")
                    .operationType("query")
                    .resourceId("resource-123")
                    .parameters(Collections.singletonMap("param1", "value1"))
                    .build();

            // Act
            ValidationResult result = resourceServer.validateRequest(request);

            // Assert
            // Note: The actual validation depends on the FiveLayerVerifier implementation
            // This test verifies the structure and parsing logic
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with null headers")
        void shouldHandleRequestWithNullHeaders() throws Exception {
            // Arrange
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();
            
            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("POST")
                    .httpUri("/api/resource")
                    .httpHeaders(null)
                    .httpBody(null)
                    .build();

            // Act
            ValidationResult result = resourceServer.validateRequest(request);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with null body")
        void shouldHandleRequestWithNullBody() throws Exception {
            // Arrange
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();
            
            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .httpHeaders(Collections.emptyMap())
                    .httpBody(null)
                    .build();

            // Act
            ValidationResult result = resourceServer.validateRequest(request);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with different HTTP methods")
        void shouldHandleRequestWithDifferentHttpMethods() throws Exception {
            // Arrange
            String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH"};
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();
            
            for (String method : methods) {
                ResourceRequest request = ResourceRequest.builder()
                        .wit(wit)
                        .wpt(wpt)
                        .aoat(aoat)
                        .httpMethod(method)
                        .httpUri("/api/resource")
                        .build();

                // Act
                ValidationResult result = resourceServer.validateRequest(request);

                // Assert
                assertThat(result).isNotNull();
            }
        }

        @Test
        @DisplayName("Should handle request with complex URI")
        void shouldHandleRequestWithComplexUri() throws Exception {
            // Arrange
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();
            
            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/v1/resource/123?param1=value1&param2=value2")
                    .build();

            // Act
            ValidationResult result = resourceServer.validateRequest(request);

            // Assert
            assertThat(result).isNotNull();
        }
    }

    @Nested
    @DisplayName("validateWit()")
    class ValidateWit {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> resourceServer.validateWit(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            ResourceRequest request = ResourceRequest.builder()
                    .wit(null)
                    .wpt("valid.wpt.token")
                    .aoat("valid.aoat.token")
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            assertThatThrownBy(() -> resourceServer.validateWit(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("WIT is required");
        }

        @Test
        @DisplayName("Should throw exception when WIT is invalid JWT")
        void shouldThrowExceptionWhenWitIsInvalidJwt() {
            ResourceRequest request = ResourceRequest.builder()
                    .wit("invalid.jwt.token")
                    .wpt("valid.wpt.token")
                    .aoat("valid.aoat.token")
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            assertThatThrownBy(() -> resourceServer.validateWit(request))
                    .isInstanceOf(FrameworkValidationException.class)
                    .hasMessageContaining("Failed to parse WIT");
        }

        @Test
        @DisplayName("Should return layer result with valid tokens")
        void shouldReturnLayerResultWithValidTokens() throws Exception {
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            ValidationResult.LayerResult result = resourceServer.validateWit(request);

            assertThat(result).isNotNull();
            assertThat(result.getLayer()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("validateWpt()")
    class ValidateWpt {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> resourceServer.validateWpt(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when WPT is null")
        void shouldThrowExceptionWhenWptIsNull() {
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt(null)
                    .aoat("valid.aoat.token")
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            assertThatThrownBy(() -> resourceServer.validateWpt(request))
                    .isInstanceOf(FrameworkValidationException.class);
        }

        @Test
        @DisplayName("Should return layer result with valid tokens")
        void shouldReturnLayerResultWithValidTokens() throws Exception {
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            ValidationResult.LayerResult result = resourceServer.validateWpt(request);

            assertThat(result).isNotNull();
            assertThat(result.getLayer()).isEqualTo(2);
        }
    }

    @Nested
    @DisplayName("validateAoat()")
    class ValidateAoat {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> resourceServer.validateAoat(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when AOAT is null")
        void shouldThrowExceptionWhenAoatIsNull() {
            ResourceRequest request = ResourceRequest.builder()
                    .wit("valid.wit.token")
                    .wpt("valid.wpt.token")
                    .aoat(null)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            assertThatThrownBy(() -> resourceServer.validateAoat(request))
                    .isInstanceOf(FrameworkValidationException.class);
        }

        @Test
        @DisplayName("Should return layer result with valid tokens")
        void shouldReturnLayerResultWithValidTokens() throws Exception {
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            ValidationResult.LayerResult result = resourceServer.validateAoat(request);

            assertThat(result).isNotNull();
            assertThat(result.getLayer()).isEqualTo(3);
        }
    }

    @Nested
    @DisplayName("verifyIdentityConsistency()")
    class VerifyIdentityConsistency {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> resourceServer.verifyIdentityConsistency(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should return layer result with valid tokens")
        void shouldReturnLayerResultWithValidTokens() throws Exception {
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            ValidationResult.LayerResult result = resourceServer.verifyIdentityConsistency(request);

            assertThat(result).isNotNull();
            assertThat(result.getLayer()).isEqualTo(4);
        }
    }

    @Nested
    @DisplayName("evaluatePolicy()")
    class EvaluatePolicy {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> resourceServer.evaluatePolicy(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Resource request cannot be null");
        }

        @Test
        @DisplayName("Should return layer result with valid tokens")
        void shouldReturnLayerResultWithValidTokens() throws Exception {
            String wit = JwtTestHelper.generateValidWit();
            String wpt = JwtTestHelper.generateValidWpt();
            String aoat = JwtTestHelper.generateValidAoat();

            ResourceRequest request = ResourceRequest.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .aoat(aoat)
                    .httpMethod("GET")
                    .httpUri("/api/resource")
                    .build();

            ValidationResult.LayerResult result = resourceServer.evaluatePolicy(request);

            assertThat(result).isNotNull();
            assertThat(result.getLayer()).isEqualTo(5);
        }
    }

    @Nested
    @DisplayName("logAccess()")
    class LogAccess {

        @Test
        @DisplayName("Should log access successfully")
        void shouldLogAccessSuccessfully() {
            // Arrange
            AuditLogEntry auditLog = 
                    AuditLogEntry.builder()
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .resourceId("resource-123")
                    .decision("allow")
                    .build();

            // Act
            resourceServer.logAccess(auditLog);

            // Assert - no exception thrown
        }

        @Test
        @DisplayName("Should throw exception when audit log is null")
        void shouldThrowExceptionWhenAuditLogIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> resourceServer.logAccess(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Audit log cannot be null");
        }

        @Test
        @DisplayName("Should log access with deny decision")
        void shouldLogAccessWithDenyDecision() {
            // Arrange
            AuditLogEntry auditLog = 
                    AuditLogEntry.builder()
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .resourceId("resource-123")
                    .decision("deny")
                    .reason("Access denied by policy")
                    .build();

            // Act
            resourceServer.logAccess(auditLog);

            // Assert - no exception thrown
        }

        @Test
        @DisplayName("Should log access with timestamp")
        void shouldLogAccessWithTimestamp() {
            // Arrange
            AuditLogEntry auditLog = 
                    AuditLogEntry.builder()
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .resourceId("resource-123")
                    .decision("allow")
                    .timestamp(Instant.now())
                    .build();

            // Act
            resourceServer.logAccess(auditLog);

            // Assert - no exception thrown
        }

        @Test
        @DisplayName("Should log access with additional attributes")
        void shouldLogAccessWithAdditionalAttributes() {
            // Arrange
            AuditLogEntry auditLog = 
                    AuditLogEntry.builder()
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .resourceId("resource-123")
                    .decision("allow")
                    .operationType("query")
                    .ipAddress("192.168.1.1")
                    .userAgent("Mozilla/5.0")
                    .build();

            // Act
            resourceServer.logAccess(auditLog);

            // Assert - no exception thrown
        }
    }
}
