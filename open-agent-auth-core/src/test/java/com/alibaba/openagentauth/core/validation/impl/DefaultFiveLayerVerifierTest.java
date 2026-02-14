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
package com.alibaba.openagentauth.core.validation.impl;

import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultFiveLayerVerifier}.
 * <p>
 * Tests the five-layer verification orchestrator's behavior including:
 * <ul>
 *   <li>Successful verification with all validators passing</li>
 *   <li>Fail-fast behavior on first failure</li>
 *   <li>Validator registration and ordering</li>
 *   <li>Error handling for null context and validators</li>
 *   <li>Thread-safe validator management</li>
 * </ul>
 * </p>
 */
@DisplayName("DefaultFiveLayerVerifier Tests")
class DefaultFiveLayerVerifierTest {

    private DefaultFiveLayerVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new DefaultFiveLayerVerifier();
    }

    @Nested
    @DisplayName("Verification Tests")
    class VerificationTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            assertThatThrownBy(() -> verifier.verify(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Validation context cannot be null");
        }

        @Test
        @DisplayName("Should return success when no validators are registered")
        void shouldReturnSuccessWhenNoValidatorsRegistered() {
            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getLayerResults()).isEmpty();
            assertThat(result.getFirstFailure()).isNull();
        }

        @Test
        @DisplayName("Should return success when all validators pass")
        void shouldReturnSuccessWhenAllValidatorsPass() {
            // Register 5 validators that all pass
            for (int i = 1; i <= 5; i++) {
                LayerValidator validator = createMockValidator("Layer " + i, i, true);
                verifier.registerValidator(validator);
            }

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getLayerResults()).hasSize(5);
            assertThat(result.getFirstFailure()).isNull();

            // Verify execution order
            List<VerificationResult.LayerResult> layerResults = result.getLayerResults();
            for (int i = 0; i < 5; i++) {
                assertThat(layerResults.get(i).getValidatorName()).isEqualTo("Layer " + (i + 1));
                assertThat(layerResults.get(i).getOrder()).isEqualTo(i + 1);
                assertThat(layerResults.get(i).getResult().isSuccess()).isTrue();
            }
        }

        @Test
        @DisplayName("Should stop at first failure (fail-fast)")
        void shouldStopAtFirstFailure() {
            // Register 5 validators, with layer 3 failing
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, true));
            verifier.registerValidator(createMockValidator("Layer 3", 3, false));
            verifier.registerValidator(createMockValidator("Layer 4", 4, true));
            verifier.registerValidator(createMockValidator("Layer 5", 5, true));

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getLayerResults()).hasSize(3); // Only layers 1, 2, 3 executed
            assertThat(result.getFirstFailure()).isNotNull();
            assertThat(result.getFirstFailure().getValidatorName()).isEqualTo("Layer 3");
            assertThat(result.getFirstFailure().getOrder()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should execute validators in order regardless of registration order")
        void shouldExecuteValidatorsInOrder() {
            // Register validators in random order
            verifier.registerValidator(createMockValidator("Layer 3", 3, true));
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 5", 5, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, true));
            verifier.registerValidator(createMockValidator("Layer 4", 4, true));

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            List<VerificationResult.LayerResult> layerResults = result.getLayerResults();
            assertThat(layerResults).hasSize(5);

            // Verify execution order
            assertThat(layerResults.get(0).getValidatorName()).isEqualTo("Layer 1");
            assertThat(layerResults.get(1).getValidatorName()).isEqualTo("Layer 2");
            assertThat(layerResults.get(2).getValidatorName()).isEqualTo("Layer 3");
            assertThat(layerResults.get(3).getValidatorName()).isEqualTo("Layer 4");
            assertThat(layerResults.get(4).getValidatorName()).isEqualTo("Layer 5");
        }

        @Test
        @DisplayName("Should handle validators with same order")
        void shouldHandleValidatorsWithSameOrder() {
            // Register validators with same order
            verifier.registerValidator(createMockValidator("Validator A", 1.0, true));
            verifier.registerValidator(createMockValidator("Validator B", 1.0, true));
            verifier.registerValidator(createMockValidator("Validator C", 2.0, true));

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getLayerResults()).hasSize(3);
        }

        @Test
        @DisplayName("Should collect all layer results on success")
        void shouldCollectAllLayerResultsOnSuccess() {
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, true));
            verifier.registerValidator(createMockValidator("Layer 3", 3, true));

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.getLayerResults()).hasSize(3);
            for (VerificationResult.LayerResult layerResult : result.getLayerResults()) {
                assertThat(layerResult.getResult().isSuccess()).isTrue();
            }
        }

        @Test
        @DisplayName("Should collect layer results up to failure point")
        void shouldCollectLayerResultsUpToFailurePoint() {
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, false));
            verifier.registerValidator(createMockValidator("Layer 3", 3, true));

            ValidationContext context = createValidContext();
            VerificationResult result = verifier.verify(context);

            assertThat(result.getLayerResults()).hasSize(2);
            assertThat(result.getLayerResults().get(0).getResult().isSuccess()).isTrue();
            assertThat(result.getLayerResults().get(1).getResult().isSuccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("Validator Registration Tests")
    class ValidatorRegistrationTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when registering null validator")
        void shouldThrowExceptionWhenRegisteringNullValidator() {
            assertThatThrownBy(() -> verifier.registerValidator(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Validator cannot be null");
        }

        @Test
        @DisplayName("Should register validator successfully")
        void shouldRegisterValidatorSuccessfully() {
            LayerValidator validator = createMockValidator("Test Validator", 1, true);
            verifier.registerValidator(validator);

            List<LayerValidator> validators = verifier.getValidators();
            assertThat(validators).hasSize(1);
            assertThat(validators.get(0)).isEqualTo(validator);
        }

        @Test
        @DisplayName("Should return copy of validators list")
        void shouldReturnCopyOfValidatorsList() {
            LayerValidator validator = createMockValidator("Test Validator", 1, true);
            verifier.registerValidator(validator);

            List<LayerValidator> validators = verifier.getValidators();
            validators.clear(); // Try to modify the returned list

            // Original list should not be affected
            assertThat(verifier.getValidators()).hasSize(1);
        }

        @Test
        @DisplayName("Should maintain sorted order after registration")
        void shouldMaintainSortedOrderAfterRegistration() {
            verifier.registerValidator(createMockValidator("Layer 3", 3, true));
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, true));

            List<LayerValidator> validators = verifier.getValidators();
            assertThat(validators.get(0).getName()).isEqualTo("Layer 1");
            assertThat(validators.get(1).getName()).isEqualTo("Layer 2");
            assertThat(validators.get(2).getName()).isEqualTo("Layer 3");
        }

        @Test
        @DisplayName("Should allow registering multiple validators")
        void shouldAllowRegisteringMultipleValidators() {
            verifier.registerValidator(createMockValidator("Layer 1", 1, true));
            verifier.registerValidator(createMockValidator("Layer 2", 2, true));
            verifier.registerValidator(createMockValidator("Layer 3", 3, true));

            assertThat(verifier.getValidators()).hasSize(3);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent validator registration")
        void shouldHandleConcurrentValidatorRegistration() throws InterruptedException {
            Thread thread1 = new Thread(() -> {
                for (int i = 0; i < 10; i++) {
                    verifier.registerValidator(createMockValidator("Thread1-Validator" + i, i, true));
                }
            });

            Thread thread2 = new Thread(() -> {
                for (int i = 0; i < 10; i++) {
                    verifier.registerValidator(createMockValidator("Thread2-Validator" + i, i + 10, true));
                }
            });

            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();

            assertThat(verifier.getValidators()).hasSize(20);
        }
    }

    /**
     * Creates a mock validator with the specified name, order, and result.
     *
     * @param name the validator name
     * @param order the validator order
     * @param success whether the validator should return success
     * @return the mock validator
     */
    private LayerValidator createMockValidator(String name, double order, boolean success) {
        LayerValidator validator = mock(LayerValidator.class);
        when(validator.getName()).thenReturn(name);
        when(validator.getOrder()).thenReturn(order);
        when(validator.validate(org.mockito.ArgumentMatchers.any(ValidationContext.class)))
                .thenReturn(success ? LayerValidationResult.success() 
                                   : LayerValidationResult.failure("Validation failed for " + name));
        return validator;
    }

    /**
     * Creates a valid validation context for testing.
     *
     * @return a valid validation context
     */
    private ValidationContext createValidContext() {
        return ValidationContext.builder()
                .httpMethod("GET")
                .httpUri("/api/resource")
                .requestTimestamp(new Date(System.currentTimeMillis()))
                .build();
    }
}
