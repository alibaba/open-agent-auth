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
package com.alibaba.openagentauth.core.model.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link UserInfo}.
 * <p>
 * Tests the UserInfo model's behavior including:
 * <ul>
 *   <li>Building UserInfo with all standard and optional fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Validation logic for required fields</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Builder pattern with validation</li>
 *   <li>Address inner class</li>
 *   <li>Additional claims handling</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("UserInfo Tests")
class UserInfoTest {

    private static final String SUB = "user-123";
    private static final String NAME = "John Doe";
    private static final String EMAIL = "john.doe@example.com";
    private static final Long UPDATED_AT = 1234567890L;

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build UserInfo with all fields")
        void shouldBuildUserInfoWithAllFields() {
            // Given
            UserInfo.Address address = new UserInfo.Address(
                    "123 Main St, Apt 4B",
                    "123 Main St",
                    "New York",
                    "NY",
                    "10001",
                    "USA"
            );
            Map<String, Object> additionalClaims = new HashMap<>();
            additionalClaims.put("custom_claim", "custom_value");

            // When
            UserInfo userInfo = UserInfo.builder()
                    .sub(SUB)
                    .name(NAME)
                    .givenName("John")
                    .familyName("Doe")
                    .middleName("William")
                    .nickname("Johnny")
                    .preferredUsername("johndoe")
                    .profile("https://example.com/johndoe")
                    .picture("https://example.com/johndoe.jpg")
                    .website("https://johndoe.com")
                    .email(EMAIL)
                    .emailVerified(true)
                    .gender("male")
                    .birthdate("1990-01-15")
                    .zoneinfo("America/New_York")
                    .locale("en-US")
                    .phoneNumber("+1-555-123-4567")
                    .phoneNumberVerified(true)
                    .address(address)
                    .updatedAt(UPDATED_AT)
                    .additionalClaims(additionalClaims)
                    .build();

            // Then
            assertThat(userInfo).isNotNull();
            assertThat(userInfo.getSub()).isEqualTo(SUB);
            assertThat(userInfo.getName()).isEqualTo(NAME);
            assertThat(userInfo.getGivenName()).isEqualTo("John");
            assertThat(userInfo.getFamilyName()).isEqualTo("Doe");
            assertThat(userInfo.getMiddleName()).isEqualTo("William");
            assertThat(userInfo.getNickname()).isEqualTo("Johnny");
            assertThat(userInfo.getPreferredUsername()).isEqualTo("johndoe");
            assertThat(userInfo.getProfile()).isEqualTo("https://example.com/johndoe");
            assertThat(userInfo.getPicture()).isEqualTo("https://example.com/johndoe.jpg");
            assertThat(userInfo.getWebsite()).isEqualTo("https://johndoe.com");
            assertThat(userInfo.getEmail()).isEqualTo(EMAIL);
            assertThat(userInfo.getEmailVerified()).isTrue();
            assertThat(userInfo.getGender()).isEqualTo("male");
            assertThat(userInfo.getBirthdate()).isEqualTo("1990-01-15");
            assertThat(userInfo.getZoneinfo()).isEqualTo("America/New_York");
            assertThat(userInfo.getLocale()).isEqualTo("en-US");
            assertThat(userInfo.getPhoneNumber()).isEqualTo("+1-555-123-4567");
            assertThat(userInfo.getPhoneNumberVerified()).isTrue();
            assertThat(userInfo.getAddress()).isNotNull();
            assertThat(userInfo.getUpdatedAt()).isEqualTo(UPDATED_AT);
            assertThat(userInfo.getAdditionalClaims()).isEqualTo(additionalClaims);
        }

        @Test
        @DisplayName("Should build UserInfo with minimum required fields")
        void shouldBuildUserInfoWithMinimumRequiredFields() {
            // When
            UserInfo userInfo = UserInfo.builder()
                    .sub(SUB)
                    .build();

            // Then
            assertThat(userInfo).isNotNull();
            assertThat(userInfo.getSub()).isEqualTo(SUB);
            assertThat(userInfo.getName()).isNull();
            assertThat(userInfo.getEmail()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when sub is null")
        void shouldThrowExceptionWhenSubIsNull() {
            // When & Then
            assertThatThrownBy(() -> UserInfo.builder().build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("sub (subject) is required");
        }

        @Test
        @DisplayName("Should throw exception when sub is empty")
        void shouldThrowExceptionWhenSubIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> UserInfo.builder().sub("").build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("sub (subject) is required");
        }

        @Test
        @DisplayName("Should build UserInfo with boolean false values")
        void shouldBuildUserInfoWithBooleanFalseValues() {
            // When
            UserInfo userInfo = UserInfo.builder()
                    .sub(SUB)
                    .email(EMAIL)
                    .emailVerified(false)
                    .phoneNumberVerified(false)
                    .build();

            // Then
            assertThat(userInfo.getEmailVerified()).isFalse();
            assertThat(userInfo.getPhoneNumberVerified()).isFalse();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct sub")
        void shouldReturnCorrectSub() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getSub()).isEqualTo(SUB);
        }

        @Test
        @DisplayName("Should return correct name")
        void shouldReturnCorrectName() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getName()).isEqualTo(NAME);
        }

        @Test
        @DisplayName("Should return correct givenName")
        void shouldReturnCorrectGivenName() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getGivenName()).isEqualTo("John");
        }

        @Test
        @DisplayName("Should return correct familyName")
        void shouldReturnCorrectFamilyName() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getFamilyName()).isEqualTo("Doe");
        }

        @Test
        @DisplayName("Should return correct middleName")
        void shouldReturnCorrectMiddleName() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getMiddleName()).isEqualTo("William");
        }

        @Test
        @DisplayName("Should return correct nickname")
        void shouldReturnCorrectNickname() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getNickname()).isEqualTo("Johnny");
        }

        @Test
        @DisplayName("Should return correct preferredUsername")
        void shouldReturnCorrectPreferredUsername() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getPreferredUsername()).isEqualTo("johndoe");
        }

        @Test
        @DisplayName("Should return correct profile")
        void shouldReturnCorrectProfile() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getProfile()).isEqualTo("https://example.com/johndoe");
        }

        @Test
        @DisplayName("Should return correct picture")
        void shouldReturnCorrectPicture() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getPicture()).isEqualTo("https://example.com/johndoe.jpg");
        }

        @Test
        @DisplayName("Should return correct website")
        void shouldReturnCorrectWebsite() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getWebsite()).isEqualTo("https://johndoe.com");
        }

        @Test
        @DisplayName("Should return correct email")
        void shouldReturnCorrectEmail() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getEmail()).isEqualTo(EMAIL);
        }

        @Test
        @DisplayName("Should return correct emailVerified")
        void shouldReturnCorrectEmailVerified() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("Should return correct gender")
        void shouldReturnCorrectGender() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getGender()).isEqualTo("male");
        }

        @Test
        @DisplayName("Should return correct birthdate")
        void shouldReturnCorrectBirthdate() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getBirthdate()).isEqualTo("1990-01-15");
        }

        @Test
        @DisplayName("Should return correct zoneinfo")
        void shouldReturnCorrectZoneinfo() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getZoneinfo()).isEqualTo("America/New_York");
        }

        @Test
        @DisplayName("Should return correct locale")
        void shouldReturnCorrectLocale() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getLocale()).isEqualTo("en-US");
        }

        @Test
        @DisplayName("Should return correct phoneNumber")
        void shouldReturnCorrectPhoneNumber() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getPhoneNumber()).isEqualTo("+1-555-123-4567");
        }

        @Test
        @DisplayName("Should return correct phoneNumberVerified")
        void shouldReturnCorrectPhoneNumberVerified() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getPhoneNumberVerified()).isTrue();
        }

        @Test
        @DisplayName("Should return correct address")
        void shouldReturnCorrectAddress() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getAddress()).isNotNull();
            assertThat(userInfo.getAddress().getFormatted()).isEqualTo("123 Main St, Apt 4B");
            assertThat(userInfo.getAddress().getCountry()).isEqualTo("USA");
        }

        @Test
        @DisplayName("Should return correct updatedAt")
        void shouldReturnCorrectUpdatedAt() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo.getUpdatedAt()).isEqualTo(UPDATED_AT);
        }

        @Test
        @DisplayName("Should return correct additionalClaims")
        void shouldReturnCorrectAdditionalClaims() {
            // Given
            Map<String, Object> additionalClaims = new HashMap<>();
            additionalClaims.put("custom_claim", "custom_value");
            UserInfo userInfo = UserInfo.builder()
                    .sub(SUB)
                    .additionalClaims(additionalClaims)
                    .build();

            // When & Then
            assertThat(userInfo.getAdditionalClaims()).isNotNull();
            assertThat(userInfo.getAdditionalClaims()).hasSize(1);
            assertThat(userInfo.getAdditionalClaims().get("custom_claim")).isEqualTo("custom_value");
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when sub, name, and email match")
        void shouldBeEqualWhenSubNameAndEmailMatch() {
            // Given
            UserInfo userInfo1 = createTestUserInfo();
            UserInfo userInfo2 = createTestUserInfo();

            // When & Then
            assertThat(userInfo1).isEqualTo(userInfo2);
            assertThat(userInfo1.hashCode()).isEqualTo(userInfo2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when sub differs")
        void shouldNotBeEqualWhenSubDiffers() {
            // Given
            UserInfo userInfo1 = createTestUserInfo();
            UserInfo userInfo2 = UserInfo.builder()
                    .sub("different-sub")
                    .name(NAME)
                    .email(EMAIL)
                    .build();

            // When & Then
            assertThat(userInfo1).isNotEqualTo(userInfo2);
        }

        @Test
        @DisplayName("Should not be equal when name differs")
        void shouldNotBeEqualWhenNameDiffers() {
            // Given
            UserInfo userInfo1 = createTestUserInfo();
            UserInfo userInfo2 = UserInfo.builder()
                    .sub(SUB)
                    .name("Different Name")
                    .email(EMAIL)
                    .build();

            // When & Then
            assertThat(userInfo1).isNotEqualTo(userInfo2);
        }

        @Test
        @DisplayName("Should not be equal when email differs")
        void shouldNotBeEqualWhenEmailDiffers() {
            // Given
            UserInfo userInfo1 = createTestUserInfo();
            UserInfo userInfo2 = UserInfo.builder()
                    .sub(SUB)
                    .name(NAME)
                    .email("different@example.com")
                    .build();

            // When & Then
            assertThat(userInfo1).isNotEqualTo(userInfo2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo).isEqualTo(userInfo);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When & Then
            assertThat(userInfo).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain sub, name, and email in toString")
        void shouldContainSubNameAndEmailInToString() {
            // Given
            UserInfo userInfo = createTestUserInfo();

            // When
            String toString = userInfo.toString();

            // Then
            assertThat(toString).contains("UserInfo");
            assertThat(toString).contains("sub='user-123'");
            assertThat(toString).contains("name='John Doe'");
            assertThat(toString).contains("email='john.doe@example.com'");
        }

        @Test
        @DisplayName("Should handle null fields in toString")
        void shouldHandleNullFieldsInToString() {
            // Given
            UserInfo userInfo = UserInfo.builder()
                    .sub(SUB)
                    .build();

            // When
            String toString = userInfo.toString();

            // Then
            assertThat(toString).isNotNull();
            assertThat(toString).contains("UserInfo");
        }
    }

    @Nested
    @DisplayName("Address Tests")
    class AddressTests {

        @Test
        @DisplayName("Should create address with all fields")
        void shouldCreateAddressWithAllFields() {
            // Given
            UserInfo.Address address = new UserInfo.Address(
                    "123 Main St, Apt 4B",
                    "123 Main St",
                    "New York",
                    "NY",
                    "10001",
                    "USA"
            );

            // When & Then
            assertThat(address.getFormatted()).isEqualTo("123 Main St, Apt 4B");
            assertThat(address.getStreetAddress()).isEqualTo("123 Main St");
            assertThat(address.getLocality()).isEqualTo("New York");
            assertThat(address.getRegion()).isEqualTo("NY");
            assertThat(address.getPostalCode()).isEqualTo("10001");
            assertThat(address.getCountry()).isEqualTo("USA");
        }

        @Test
        @DisplayName("Should create address with null fields")
        void shouldCreateAddressWithNullFields() {
            // Given
            UserInfo.Address address = new UserInfo.Address(
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
            );

            // When & Then
            assertThat(address.getFormatted()).isNull();
            assertThat(address.getStreetAddress()).isNull();
            assertThat(address.getLocality()).isNull();
            assertThat(address.getRegion()).isNull();
            assertThat(address.getPostalCode()).isNull();
            assertThat(address.getCountry()).isNull();
        }
    }

    /**
     * Helper method to create a test UserInfo instance.
     *
     * @return a test UserInfo instance
     */
    private UserInfo createTestUserInfo() {
        UserInfo.Address address = new UserInfo.Address(
                "123 Main St, Apt 4B",
                "123 Main St",
                "New York",
                "NY",
                "10001",
                "USA"
        );

        return UserInfo.builder()
                .sub(SUB)
                .name(NAME)
                .givenName("John")
                .familyName("Doe")
                .middleName("William")
                .nickname("Johnny")
                .preferredUsername("johndoe")
                .profile("https://example.com/johndoe")
                .picture("https://example.com/johndoe.jpg")
                .website("https://johndoe.com")
                .email(EMAIL)
                .emailVerified(true)
                .gender("male")
                .birthdate("1990-01-15")
                .zoneinfo("America/New_York")
                .locale("en-US")
                .phoneNumber("+1-555-123-4567")
                .phoneNumberVerified(true)
                .address(address)
                .updatedAt(UPDATED_AT)
                .build();
    }
}
