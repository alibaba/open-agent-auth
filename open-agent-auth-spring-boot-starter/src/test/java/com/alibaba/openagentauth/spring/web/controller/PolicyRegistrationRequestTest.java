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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PolicyRegistryController.PolicyRegistrationRequest}.
 * <p>
 * This test class verifies the PolicyRegistrationRequest inner class functionality,
 * including field getters and setters, default values, and boundary conditions.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("PolicyRegistryController.PolicyRegistrationRequest Tests")
class PolicyRegistrationRequestTest {

    private PolicyRegistryController.PolicyRegistrationRequest request;

    @BeforeEach
    void setUp() {
        request = new PolicyRegistryController.PolicyRegistrationRequest();
    }

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("regoPolicy should be null by default")
        void regoPolicyShouldBeNullByDefault() {
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("description should be null by default")
        void descriptionShouldBeNullByDefault() {
            assertThat(request.getDescription())
                .as("description should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("createdBy should be null by default")
        void createdByShouldBeNullByDefault() {
            assertThat(request.getCreatedBy())
                .as("createdBy should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("expirationTime should be null by default")
        void expirationTimeShouldBeNullByDefault() {
            assertThat(request.getExpirationTime())
                .as("expirationTime should be null by default")
                .isNull();
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get regoPolicy")
        void shouldSetAndGetRegoPolicy() {
            String testRegoPolicy = "package test\nallow = true";
            request.setRegoPolicy(testRegoPolicy);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should match")
                .isEqualTo(testRegoPolicy);
        }

        @Test
        @DisplayName("Should set and get description")
        void shouldSetAndGetDescription() {
            String testDescription = "Test policy for allowing all requests";
            request.setDescription(testDescription);
            assertThat(request.getDescription())
                .as("description should match")
                .isEqualTo(testDescription);
        }

        @Test
        @DisplayName("Should set and get createdBy")
        void shouldSetAndGetCreatedBy() {
            String testCreatedBy = "admin";
            request.setCreatedBy(testCreatedBy);
            assertThat(request.getCreatedBy())
                .as("createdBy should match")
                .isEqualTo(testCreatedBy);
        }

        @Test
        @DisplayName("Should set and get expirationTime")
        void shouldSetAndGetExpirationTime() {
            Instant testExpirationTime = Instant.now().plusSeconds(3600);
            request.setExpirationTime(testExpirationTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should match")
                .isEqualTo(testExpirationTime);
        }
    }

    @Nested
    @DisplayName("Boundary Conditions and Null Value Tests")
    class BoundaryConditionsAndNullValueTests {

        @Test
        @DisplayName("Should handle null regoPolicy")
        void shouldHandleNullRegoPolicy() {
            request.setRegoPolicy("package test\nallow = true");
            request.setRegoPolicy(null);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null description")
        void shouldHandleNullDescription() {
            request.setDescription("test description");
            request.setDescription(null);
            assertThat(request.getDescription())
                .as("description should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null createdBy")
        void shouldHandleNullCreatedBy() {
            request.setCreatedBy("admin");
            request.setCreatedBy(null);
            assertThat(request.getCreatedBy())
                .as("createdBy should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null expirationTime")
        void shouldHandleNullExpirationTime() {
            request.setExpirationTime(Instant.now());
            request.setExpirationTime(null);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle empty string regoPolicy")
        void shouldHandleEmptyStringRegoPolicy() {
            request.setRegoPolicy("");
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle empty string description")
        void shouldHandleEmptyStringDescription() {
            request.setDescription("");
            assertThat(request.getDescription())
                .as("description should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle empty string createdBy")
        void shouldHandleEmptyStringCreatedBy() {
            request.setCreatedBy("");
            assertThat(request.getCreatedBy())
                .as("createdBy should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle past expirationTime")
        void shouldHandlePastExpirationTime() {
            Instant pastTime = Instant.now().minusSeconds(3600);
            request.setExpirationTime(pastTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be in the past")
                .isEqualTo(pastTime);
        }

        @Test
        @DisplayName("Should handle future expirationTime")
        void shouldHandleFutureExpirationTime() {
            Instant futureTime = Instant.now().plusSeconds(86400);
            request.setExpirationTime(futureTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be in the future")
                .isEqualTo(futureTime);
        }

        @Test
        @DisplayName("Should handle very long regoPolicy")
        void shouldHandleVeryLongRegoPolicy() {
            StringBuilder longPolicy = new StringBuilder("package test\n");
            for (int i = 0; i < 100; i++) {
                longPolicy.append("rule_").append(i).append(" {\n    allow := true\n}\n");
            }
            request.setRegoPolicy(longPolicy.toString());
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be very long")
                .hasSizeGreaterThan(1000);
        }

        @Test
        @DisplayName("Should handle very long description")
        void shouldHandleVeryLongDescription() {
            StringBuilder longDescription = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                longDescription.append("This is a very long description line ").append(i).append(". ");
            }
            request.setDescription(longDescription.toString());
            assertThat(request.getDescription())
                .as("description should be very long")
                .hasSizeGreaterThan(1000);
        }

        @Test
        @DisplayName("Should handle special characters in description")
        void shouldHandleSpecialCharactersInDescription() {
            String specialDescription = "Test policy with special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/~`";
            request.setDescription(specialDescription);
            assertThat(request.getDescription())
                .as("description with special characters should match")
                .isEqualTo(specialDescription);
        }

        @Test
        @DisplayName("Should handle unicode in createdBy")
        void shouldHandleUnicodeInCreatedBy() {
            String unicodeCreatedBy = "管理员-中文";
            request.setCreatedBy(unicodeCreatedBy);
            assertThat(request.getCreatedBy())
                .as("createdBy with unicode should match")
                .isEqualTo(unicodeCreatedBy);
        }

        @Test
        @DisplayName("Should handle multi-line regoPolicy")
        void shouldHandleMultiLineRegoPolicy() {
            String multiLinePolicy = "package authz\n\n" +
                "default allow = false\n\n" +
                "allow {\n" +
                "    input.user == \"admin\"\n" +
                "    input.method == \"GET\"\n" +
                "}\n";
            request.setRegoPolicy(multiLinePolicy);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be multi-line")
                .contains("\n")
                .contains("package authz")
                .contains("allow {");
        }
    }

    @Nested
    @DisplayName("Complete Configuration Tests")
    class CompleteConfigurationTests {

        @Test
        @DisplayName("Should create complete policy registration request")
        void shouldCreateCompletePolicyRegistrationRequest() {
            String regoPolicy = "package test\nallow = input.user == \"admin\"";
            String description = "Policy to allow only admin users";
            String createdBy = "admin";
            Instant expirationTime = Instant.now().plusSeconds(86400);

            request.setRegoPolicy(regoPolicy);
            request.setDescription(description);
            request.setCreatedBy(createdBy);
            request.setExpirationTime(expirationTime);

            assertThat(request.getRegoPolicy()).isEqualTo(regoPolicy);
            assertThat(request.getDescription()).isEqualTo(description);
            assertThat(request.getCreatedBy()).isEqualTo(createdBy);
            assertThat(request.getExpirationTime()).isEqualTo(expirationTime);
        }

        @Test
        @DisplayName("Should create minimal policy registration request")
        void shouldCreateMinimalPolicyRegistrationRequest() {
            String regoPolicy = "package test\nallow = true";

            request.setRegoPolicy(regoPolicy);

            assertThat(request.getRegoPolicy()).isEqualTo(regoPolicy);
            assertThat(request.getDescription()).isNull();
            assertThat(request.getCreatedBy()).isNull();
            assertThat(request.getExpirationTime()).isNull();
        }

        @Test
        @DisplayName("Should allow updating configuration")
        void shouldAllowUpdatingConfiguration() {
            request.setRegoPolicy("package test\nallow = false");
            request.setDescription("Old description");
            request.setCreatedBy("old-admin");

            assertThat(request.getRegoPolicy()).isEqualTo("package test\nallow = false");
            assertThat(request.getDescription()).isEqualTo("Old description");
            assertThat(request.getCreatedBy()).isEqualTo("old-admin");

            request.setRegoPolicy("package test\nallow = true");
            request.setDescription("New description");
            request.setCreatedBy("new-admin");

            assertThat(request.getRegoPolicy()).isEqualTo("package test\nallow = true");
            assertThat(request.getDescription()).isEqualTo("New description");
            assertThat(request.getCreatedBy()).isEqualTo("new-admin");
        }

        @Test
        @DisplayName("Should create policy with only required fields")
        void shouldCreatePolicyWithOnlyRequiredFields() {
            String regoPolicy = "package authz\ndefault allow = false";

            request.setRegoPolicy(regoPolicy);

            assertThat(request.getRegoPolicy()).isNotNull();
            assertThat(request.getRegoPolicy()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Time-based Tests")
    class TimeBasedTests {

        @Test
        @DisplayName("Should handle current time as expirationTime")
        void shouldHandleCurrentTimeAsExpirationTime() {
            Instant currentTime = Instant.now();
            request.setExpirationTime(currentTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be current time")
                .isEqualTo(currentTime);
        }

        @Test
        @DisplayName("Should handle epoch time for expirationTime")
        void shouldHandleEpochTimeForExpirationTime() {
            Instant epochTime = Instant.EPOCH;
            request.setExpirationTime(epochTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be epoch time")
                .isEqualTo(epochTime);
        }

        @Test
        @DisplayName("Should handle max instant for expirationTime")
        void shouldHandleMaxInstantForExpirationTime() {
            Instant maxTime = Instant.MAX;
            request.setExpirationTime(maxTime);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be max instant")
                .isEqualTo(maxTime);
        }

        @Test
        @DisplayName("Should handle year 2100 for expirationTime")
        void shouldHandleYear2100ForExpirationTime() {
            Instant year2100 = Instant.parse("2100-01-01T00:00:00Z");
            request.setExpirationTime(year2100);
            assertThat(request.getExpirationTime())
                .as("expirationTime should be year 2100")
                .isEqualTo(year2100);
        }
    }

    @Nested
    @DisplayName("Rego Policy Format Tests")
    class RegoPolicyFormatTests {

        @Test
        @DisplayName("Should handle simple allow policy")
        void shouldHandleSimpleAllowPolicy() {
            String simplePolicy = "package test\nallow = true";
            request.setRegoPolicy(simplePolicy);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should be simple allow policy")
                .isEqualTo(simplePolicy);
        }

        @Test
        @DisplayName("Should handle complex policy with rules")
        void shouldHandleComplexPolicyWithRules() {
            String complexPolicy = "package authz\n\n" +
                "import input.user\n" +
                "import input.resource\n\n" +
                "default allow = false\n\n" +
                "allow {\n" +
                "    user_is_admin\n" +
                "    resource_is_public\n" +
                "}\n\n" +
                "user_is_admin {\n" +
                "    user.roles[_] == \"admin\"\n" +
                "}\n\n" +
                "resource_is_public {\n" +
                "    resource.access == \"public\"\n" +
                "}\n";
            request.setRegoPolicy(complexPolicy);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should contain multiple rules")
                .contains("user_is_admin")
                .contains("resource_is_public");
        }

        @Test
        @DisplayName("Should handle policy with imports")
        void shouldHandlePolicyWithImports() {
            String policyWithImports = "package test\n\n" +
                "import data.users\n" +
                "import input.request\n\n" +
                "allow {\n" +
                "    users[input.user]\n" +
                "}\n";
            request.setRegoPolicy(policyWithImports);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should contain imports")
                .contains("import data.users")
                .contains("import input.request");
        }

        @Test
        @DisplayName("Should handle policy with comments")
        void shouldHandlePolicyWithComments() {
            String policyWithComments = "package test\n\n" +
                "# This is a comment\n" +
                "# Policy to allow admin access\n" +
                "allow {\n" +
                "    input.user == \"admin\"  # Check if user is admin\n" +
                "}\n";
            request.setRegoPolicy(policyWithComments);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should contain comments")
                .contains("# This is a comment")
                .contains("# Policy to allow admin access");
        }
    }

    @Nested
    @DisplayName("Multiple Instance Tests")
    class MultipleInstanceTests {

        @Test
        @DisplayName("Should create independent instances")
        void shouldCreateIndependentInstances() {
            PolicyRegistryController.PolicyRegistrationRequest request1 = 
                new PolicyRegistryController.PolicyRegistrationRequest();
            PolicyRegistryController.PolicyRegistrationRequest request2 = 
                new PolicyRegistryController.PolicyRegistrationRequest();

            request1.setRegoPolicy("package test\nallow = true");
            request2.setRegoPolicy("package test\nallow = false");

            assertThat(request1.getRegoPolicy())
                .as("request1 regoPolicy should be allow = true")
                .isEqualTo("package test\nallow = true");
            assertThat(request2.getRegoPolicy())
                .as("request2 regoPolicy should be allow = false")
                .isEqualTo("package test\nallow = false");
        }

        @Test
        @DisplayName("Should allow independent expirationTime modifications")
        void shouldAllowIndependentExpirationTimeModifications() {
            PolicyRegistryController.PolicyRegistrationRequest request1 = 
                new PolicyRegistryController.PolicyRegistrationRequest();
            PolicyRegistryController.PolicyRegistrationRequest request2 = 
                new PolicyRegistryController.PolicyRegistrationRequest();

            Instant time1 = Instant.now().plusSeconds(3600);
            Instant time2 = Instant.now().plusSeconds(7200);

            request1.setExpirationTime(time1);
            request2.setExpirationTime(time2);

            assertThat(request1.getExpirationTime())
                .as("request1 expirationTime should be 1 hour from now")
                .isEqualTo(time1);
            assertThat(request2.getExpirationTime())
                .as("request2 expirationTime should be 2 hours from now")
                .isEqualTo(time2);
        }
    }

    @Nested
    @DisplayName("Field Validation Tests")
    class FieldValidationTests {

        @Test
        @DisplayName("Should handle whitespace only regoPolicy")
        void shouldHandleWhitespaceOnlyRegoPolicy() {
            String whitespacePolicy = "   \n\t\n  ";
            request.setRegoPolicy(whitespacePolicy);
            assertThat(request.getRegoPolicy())
                .as("regoPolicy should contain only whitespace")
                .isEqualTo(whitespacePolicy);
        }

        @Test
        @DisplayName("Should handle description with line breaks")
        void shouldHandleDescriptionWithLineBreaks() {
            String multilineDescription = "This is a description\nwith multiple\nlines";
            request.setDescription(multilineDescription);
            assertThat(request.getDescription())
                .as("description should contain line breaks")
                .contains("\n");
        }

        @Test
        @DisplayName("Should handle createdBy with email format")
        void shouldHandleCreatedByWithEmailFormat() {
            String emailCreatedBy = "admin@example.com";
            request.setCreatedBy(emailCreatedBy);
            assertThat(request.getCreatedBy())
                .as("createdBy should be email format")
                .isEqualTo(emailCreatedBy);
        }

        @Test
        @DisplayName("Should handle createdBy with user ID format")
        void shouldHandleCreatedByWithUserIdFormat() {
            String userIdCreatedBy = "user-12345";
            request.setCreatedBy(userIdCreatedBy);
            assertThat(request.getCreatedBy())
                .as("createdBy should be user ID format")
                .isEqualTo(userIdCreatedBy);
        }
    }
}
