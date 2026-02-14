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
package com.alibaba.openagentauth.core.validation.layer;

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WorkloadProofValidator}.
 * <p>
 * Tests cover:
 * <ul>
 *   <li>Happy path scenarios with valid tokens</li>
 *   <li>Parameter validation (null checks)</li>
 *   <li>WPT validation delegation</li>
 *   <li>OTH claim hash verification</li>
 *   <li>Error handling and edge cases</li>
 * </ul>
 * </p>
 */
@DisplayName("WorkloadProofValidator Tests")
@ExtendWith(MockitoExtension.class)
class WorkloadProofValidatorTest {

    private static final String WORKLOAD_ID = "workload-instance-456";
    private static final String USER_ID = "https://idp.example.com|user-123";
    private static final String AGENT_ID = "urn:uuid:agent-123";
    private static final String AOAT_JWT_STRING = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1IiwiaWF0IjoxNzMzNDkxMjAwLCJleHAiOjE3MzM0OTQ4MDB9.signature";

    @Mock
    private WptValidator mockWptValidator;

    private WorkloadProofValidator validator;

    @BeforeEach
    void setUp() {
        validator = new WorkloadProofValidator(mockWptValidator);
    }

    @Test
    @DisplayName("Should pass validation with valid WPT and WIT")
    void shouldPassValidationWithValidWptAndWit() {
        // Arrange
        WorkloadProofToken wpt = createValidWpt();
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should fail validation when WPT is null")
    void shouldFailValidationWhenWptIsNull() {
        // Arrange
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT is required");
    }

    @Test
    @DisplayName("Should fail validation when WIT is null")
    void shouldFailValidationWhenWitIsNull() {
        // Arrange
        WorkloadProofToken wpt = createValidWpt();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WIT is required");
    }

    @Test
    @DisplayName("Should fail validation when WPT validator returns failure")
    void shouldFailValidationWhenWptValidatorReturnsFailure() {
        // Arrange
        WorkloadProofToken wpt = createValidWpt();
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.failure("WPT signature verification failed"));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT signature verification failed");
    }

    @Test
    @DisplayName("Should skip OTH validation when OTH claim is not present")
    void shouldSkipOthValidationWhenOthClaimIsNotPresent() {
        // Arrange
        WorkloadProofToken wpt = createValidWptWithoutOth();
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should pass OTH validation with valid AOAT hash")
    void shouldPassOthValidationWithValidAoatHash() {
        // Arrange
        String aoatHash = JwtHashUtil.computeAoatHash(AOAT_JWT_STRING);
        WorkloadProofToken wpt = createValidWptWithOth(aoatHash);
        WorkloadIdentityToken wit = createValidWitWithHash();
        AgentOperationAuthToken aoat = createValidAoatWithJwtString(AOAT_JWT_STRING);
        
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should fail OTH validation when AOAT hash does not match")
    void shouldFailOthValidationWhenAoatHashDoesNotMatch() {
        // Arrange
        String wrongHash = "wrong-hash-value";
        WorkloadProofToken wpt = createValidWptWithOth(wrongHash);
        WorkloadIdentityToken wit = createValidWitWithHash();
        AgentOperationAuthToken aoat = createValidAoatWithJwtString(AOAT_JWT_STRING);
        
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT oth claim aoat hash does not match");
    }

    @Test
    @DisplayName("Should fail OTH validation when AOAT is missing from context")
    void shouldFailOthValidationWhenAoatIsMissingFromContext() {
        // Arrange
        String aoatHash = JwtHashUtil.computeAoatHash(AOAT_JWT_STRING);
        WorkloadProofToken wpt = createValidWptWithOth(aoatHash);
        WorkloadIdentityToken wit = createValidWitWithHash();
        
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT oth claim contains aoat hash but AOAT token is not provided");
    }

    @Test
    @DisplayName("Should fail OTH validation when AOAT JWT string is null")
    void shouldFailOthValidationWhenAoatJwtStringIsNull() throws JOSEException {
        // Arrange
        String aoatHash = JwtHashUtil.computeAoatHash(AOAT_JWT_STRING);
        WorkloadProofToken wpt = createValidWptWithOth(aoatHash);
        WorkloadIdentityToken wit = createValidWitWithHash();
        AgentOperationAuthToken aoat = createValidAoatWithNullJwtString();
        
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("AOAT token missing JWT string");
    }

    @Test
    @DisplayName("Should fail validation when WPT validator throws exception")
    void shouldFailValidationWhenWptValidatorThrowsException() {
        // Arrange
        WorkloadProofToken wpt = createValidWpt();
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenThrow(new RuntimeException("Unexpected error"));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT validation failed");
    }

    @Test
    @DisplayName("Should return correct validator name")
    void shouldReturnCorrectValidatorName() {
        // Act
        String name = validator.getName();

        // Assert
        assertThat(name).isEqualTo("Layer 2: Workload Proof Validator");
    }

    @Test
    @DisplayName("Should return correct validator order")
    void shouldReturnCorrectValidatorOrder() {
        // Act
        double order = validator.getOrder();

        // Assert
        assertThat(order).isEqualTo(2.0);
    }

    @Test
    @DisplayName("Should fail validation when WptValidator is null")
    void shouldFailValidationWhenWptValidatorIsNull() {
        // Act & Assert
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new WorkloadProofValidator(null)
        );
    }

    @Test
    @DisplayName("Should handle context with all null tokens gracefully")
    void shouldHandleContextWithAllNullTokensGracefully() {
        // Arrange
        ValidationContext context = ValidationContext.builder().build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WPT is required");
    }

    @Test
    @DisplayName("Should pass validation with empty OTH claim map")
    void shouldPassValidationWithEmptyOthClaimMap() {
        // Arrange
        WorkloadProofToken wpt = createValidWptWithEmptyOth();
        WorkloadIdentityToken wit = createValidWitWithHash();
        ValidationContext context = ValidationContext.builder()
                .wpt(wpt)
                .wit(wit)
                .build();

        when(mockWptValidator.validate(any(WorkloadProofToken.class), any(WorkloadIdentityToken.class)))
                .thenReturn(TokenValidationResult.success(wpt));

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    // Helper methods

    private WorkloadProofToken createValidWpt() {
        return createValidWptWithOth(null);
    }

    private WorkloadProofToken createValidWptWithoutOth() {
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type("wpt+jwt")
                        .algorithm("ES256")
                        .build())
                .claims(WorkloadProofToken.Claims.builder()
                        .audience("resource-server")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wpt-jti-123")
                        .workloadTokenHash("wit-hash-123")
                        .build())
                .jwtString("wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createValidWptWithOth(String aoatHash) {
        Map<String, String> othClaim = new HashMap<>();
        if (aoatHash != null) {
            othClaim.put("aoat", aoatHash);
        }
        
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type("wpt+jwt")
                        .algorithm("ES256")
                        .build())
                .claims(WorkloadProofToken.Claims.builder()
                        .audience("resource-server")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wpt-jti-123")
                        .workloadTokenHash("wit-hash-123")
                        .otherTokenHashes(othClaim.isEmpty() ? null : othClaim)
                        .build())
                .jwtString("wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createValidWptWithEmptyOth() {
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type("wpt+jwt")
                        .algorithm("ES256")
                        .build())
                .claims(WorkloadProofToken.Claims.builder()
                        .audience("resource-server")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wpt-jti-123")
                        .workloadTokenHash("wit-hash-123")
                        .otherTokenHashes(new HashMap<>())
                        .build())
                .jwtString("wpt.jwt.string")
                .build();
    }

    private WorkloadIdentityToken createValidWitWithHash() {
        WorkloadIdentityToken.Claims.Confirmation confirmation = 
            WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(Jwk.builder()
                        .keyType(Jwk.KeyType.EC)
                        .curve(Jwk.Curve.P_256)
                        .algorithm("ES256")
                        .keyId("key-123")
                        .x("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
                        .y("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
                        .build())
                .build();
        
        return WorkloadIdentityToken.builder()
                .claims(WorkloadIdentityToken.Claims.builder()
                        .issuer("wimse://example.com")
                        .subject(WORKLOAD_ID)
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wit-jti-123")
                        .confirmation(confirmation)
                        .build())
                .header(WorkloadIdentityToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .jwtString("wit.jwt.string")
                .build();
    }

    private AgentOperationAuthToken createValidAoatWithJwtString(String jwtString) {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(AGENT_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_ID)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .type("JWT")
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentity)
                        .authorization(authorization)
                        .build())
                .jwtString(jwtString)
                .build();
    }

    private AgentOperationAuthToken createValidAoatWithNullJwtString() {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(AGENT_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_ID)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .type("JWT")
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentity)
                        .authorization(authorization)
                        .build())
                .jwtString(null)
                .build();
    }
}
