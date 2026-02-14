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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link WorkloadIdentityValidator}.
 * <p>
 * Tests the Layer 1 validator for Workload Identity Token (WIT) verification.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("WorkloadIdentityValidator Tests")
class WorkloadIdentityValidatorTest {

    @Mock
    private WitValidator mockWitValidator;

    private WorkloadIdentityValidator validator;

    @BeforeEach
    void setUp() {
        validator = new WorkloadIdentityValidator(mockWitValidator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when WitValidator is null")
        void shouldThrowExceptionWhenWitValidatorIsNull() {
            assertThatThrownBy(() -> new WorkloadIdentityValidator(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WitValidator");
        }

        @Test
        @DisplayName("Should create validator successfully")
        void shouldCreateValidatorSuccessfully() {
            WorkloadIdentityValidator validator = new WorkloadIdentityValidator(mockWitValidator);
            assertThat(validator).isNotNull();
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should throw NullPointerException when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            assertThatThrownBy(() -> validator.validate(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("context");
        }

        @Test
        @DisplayName("Should return failure when WIT is null")
        void shouldReturnFailureWhenWitIsNull() {
            ValidationContext context = ValidationContext.builder()
                    .wit(null)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("WIT is required but not present in the validation context");
        }

        @Test
        @DisplayName("Should return failure when WIT JWT string is null")
        void shouldReturnFailureWhenWitJwtStringIsNull() {
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(wit.getJwtString()).thenReturn(null);

            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("WIT JWT string is required but not present in the validation context");
        }

        @Test
        @DisplayName("Should return failure when WIT JWT string is empty")
        void shouldReturnFailureWhenWitJwtStringIsEmpty() {
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(wit.getJwtString()).thenReturn("");

            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("WIT JWT string is required but not present in the validation context");
        }

        @Test
        @DisplayName("Should return success when WIT validation passes")
        void shouldReturnSuccessWhenWitValidationPasses() throws Exception {
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(wit.getJwtString()).thenReturn("valid.jwt.token");

            TokenValidationResult<WorkloadIdentityToken> validationResult = 
                    TokenValidationResult.success(wit);
            when(mockWitValidator.validate(anyString())).thenReturn(validationResult);

            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getMetadata()).isEqualTo("Layer 1: WIT validation completed successfully");
            verify(mockWitValidator, times(1)).validate("valid.jwt.token");
        }

        @Test
        @DisplayName("Should return failure when WIT validation fails")
        void shouldReturnFailureWhenWitValidationFails() throws Exception {
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(wit.getJwtString()).thenReturn("invalid.jwt.token");

            TokenValidationResult<WorkloadIdentityToken> validationResult = 
                    TokenValidationResult.failure("Invalid signature");
            when(mockWitValidator.validate(anyString())).thenReturn(validationResult);

            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("Invalid signature");
            assertThat(result.getMetadata()).isEqualTo("Layer 1 WIT Validation");
        }

        @Test
        @DisplayName("Should return failure when WitValidator throws exception")
        void shouldReturnFailureWhenWitValidatorThrowsException() throws Exception {
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(wit.getJwtString()).thenReturn("malformed.jwt.token");

            when(mockWitValidator.validate(anyString()))
                    .thenThrow(new RuntimeException("Parsing error"));

            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("WIT validation failed: Parsing error");
            assertThat(result.getMetadata()).isEqualTo("Layer 1 WIT Validation");
        }
    }

    @Nested
    @DisplayName("Metadata Tests")
    class MetadataTests {

        @Test
        @DisplayName("Should return correct validator name")
        void shouldReturnCorrectValidatorName() {
            assertThat(validator.getName()).isEqualTo("Layer 1: Workload Identity Validator");
        }

        @Test
        @DisplayName("Should return correct order")
        void shouldReturnCorrectOrder() {
            assertThat(validator.getOrder()).isEqualTo(1.0);
        }
    }
}
