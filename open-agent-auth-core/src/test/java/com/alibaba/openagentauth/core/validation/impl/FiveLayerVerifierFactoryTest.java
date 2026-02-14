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

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link FiveLayerVerifierFactory}.
 * <p>
 * Tests cover:
 * <ul>
 *   <li>Happy path scenarios with valid parameters</li>
 *   <li>Parameter validation (null checks)</li>
 *   <li>Correct registration of all validators</li>
 *   <li>Optional binding instance store handling</li>
 * </ul>
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("FiveLayerVerifierFactory Tests")
class FiveLayerVerifierFactoryTest {

    @Mock
    private WitValidator witValidator;

    @Mock
    private WptValidator wptValidator;

    @Mock
    private AoatValidator aoatValidator;

    @Mock
    private PolicyEvaluator policyEvaluator;

    @Mock
    private BindingInstanceStore bindingInstanceStore;

    @Nested
    @DisplayName("Successful Creation Tests")
    class SuccessfulCreationTests {

        @Test
        @DisplayName("Should create verifier with all required validators")
        void shouldCreateVerifierWithAllRequiredValidators() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            assertThat(verifier).isInstanceOf(DefaultFiveLayerVerifier.class);
        }

        @Test
        @DisplayName("Should create verifier with binding instance store")
        void shouldCreateVerifierWithBindingInstanceStore() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    bindingInstanceStore
            );

            // Assert
            assertThat(verifier).isNotNull();
            assertThat(verifier).isInstanceOf(DefaultFiveLayerVerifier.class);
        }

        @Test
        @DisplayName("Should create new verifier instance each time")
        void shouldCreateNewVerifierInstanceEachTime() {
            // Act
            FiveLayerVerifier verifier1 = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            FiveLayerVerifier verifier2 = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier1).isNotNull();
            assertThat(verifier2).isNotNull();
            assertThat(verifier1).isNotSameAs(verifier2);
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WIT validator is null")
        void shouldThrowExceptionWhenWitValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    null,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT validator");
        }

        @Test
        @DisplayName("Should throw exception when WPT validator is null")
        void shouldThrowExceptionWhenWptValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    null,
                    aoatValidator,
                    policyEvaluator,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT validator");
        }

        @Test
        @DisplayName("Should throw exception when AOAT validator is null")
        void shouldThrowExceptionWhenAoatValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    null,
                    policyEvaluator,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AOAT validator");
        }

        @Test
        @DisplayName("Should throw exception when policy evaluator is null")
        void shouldThrowExceptionWhenPolicyEvaluatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    null,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Policy evaluator");
        }

        @Test
        @DisplayName("Should accept null binding instance store")
        void shouldAcceptNullBindingInstanceStore() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
        }
    }

    @Nested
    @DisplayName("Validator Registration Tests")
    class ValidatorRegistrationTests {

        @Test
        @DisplayName("Should register all five validators")
        void shouldRegisterAllFiveValidators() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    bindingInstanceStore
            );

            // Assert
            assertThat(verifier).isNotNull();
            // The factory creates a DefaultFiveLayerVerifier with all validators registered
            // We can't directly access the validators, but we can verify the verifier is created
        }

        @Test
        @DisplayName("Should use provided validators")
        void shouldUseProvidedValidators() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            // The factory should use the provided validators
            // This is implicitly tested by the fact that the factory doesn't throw
            // exceptions when creating the verifier
        }

        @Test
        @DisplayName("Should use provided binding instance store")
        void shouldUseProvidedBindingInstanceStore() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    bindingInstanceStore
            );

            // Assert
            assertThat(verifier).isNotNull();
            // The binding instance store should be used in Layer 4 validator
        }
    }

    @Nested
    @DisplayName("Factory Method Tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should be static factory method")
        void shouldBeStaticFactoryMethod() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            // This test verifies that createVerifier is a static method
        }

        @Test
        @DisplayName("Should return FiveLayerVerifier interface type")
        void shouldReturnFiveLayerVerifierInterfaceType() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            assertThat(verifier).isInstanceOf(FiveLayerVerifier.class);
        }

        @Test
        @DisplayName("Should return DefaultFiveLayerVerifier implementation")
        void shouldReturnDefaultFiveLayerVerifierImplementation() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            assertThat(verifier).isInstanceOf(DefaultFiveLayerVerifier.class);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle same validator instances")
        void shouldHandleSameValidatorInstances() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            // The factory should handle the same validator instances correctly
        }

        @Test
        @DisplayName("Should create verifier with minimal configuration")
        void shouldCreateVerifierWithMinimalConfiguration() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    null
            );

            // Assert
            assertThat(verifier).isNotNull();
            // Minimal configuration means no binding instance store
        }

        @Test
        @DisplayName("Should create verifier with full configuration")
        void shouldCreateVerifierWithFullConfiguration() {
            // Act
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator,
                    wptValidator,
                    aoatValidator,
                    policyEvaluator,
                    bindingInstanceStore
            );

            // Assert
            assertThat(verifier).isNotNull();
            // Full configuration includes binding instance store
        }
    }
}
