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

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link IdTokenClaims}.
 * <p>
 * This test class validates the ID token claims model
 * following the OpenID Connect Core 1.0 specification.
 * </p>
 */
@DisplayName("IdTokenClaims Tests")
class IdTokenClaimsTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String SUBJECT = "user_12345";
    private static final String AUDIENCE = "client_67890";

    @Nested
    @DisplayName("Builder")
    class Builder {

        @Test
        @DisplayName("Should build claims with all required fields")
        void shouldBuildClaimsWithAllRequiredFields() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();
            long iat = Instant.now().getEpochSecond();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(exp)
                    .iat(iat)
                    .build();

            assertThat(claims.getIss()).isEqualTo(ISSUER);
            assertThat(claims.getSub()).isEqualTo(SUBJECT);
            assertThat(claims.getAud()).isEqualTo(AUDIENCE);
            assertThat(claims.getExp()).isEqualTo(exp);
            assertThat(claims.getIat()).isEqualTo(iat);
        }

        @Test
        @DisplayName("Should throw exception when iss is null")
        void shouldThrowExceptionWhenIssIsNull() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();
            long iat = Instant.now().getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss(null)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(exp)
                    .iat(iat)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("iss (issuer) is required");
        }

        @Test
        @DisplayName("Should throw exception when iss is empty")
        void shouldThrowExceptionWhenIssIsEmpty() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();
            long iat = Instant.now().getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss("")
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(exp)
                    .iat(iat)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("iss (issuer) is required");
        }

        @Test
        @DisplayName("Should throw exception when sub is null")
        void shouldThrowExceptionWhenSubIsNull() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();
            long iat = Instant.now().getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(null)
                    .aud(AUDIENCE)
                    .exp(exp)
                    .iat(iat)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("sub (subject) is required");
        }

        @Test
        @DisplayName("Should throw exception when aud is null")
        void shouldThrowExceptionWhenAudIsNull() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();
            long iat = Instant.now().getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(null)
                    .exp(exp)
                    .iat(iat)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("aud (audience) is required");
        }

        @Test
        @DisplayName("Should throw exception when exp is null")
        void shouldThrowExceptionWhenExpIsNull() {
            long iat = Instant.now().getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp((Long) null)
                    .iat(iat)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exp (expiration) is required");
        }

        @Test
        @DisplayName("Should throw exception when iat is null")
        void shouldThrowExceptionWhenIatIsNull() {
            long exp = Instant.now().plusSeconds(3600).getEpochSecond();

            assertThatThrownBy(() -> IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(exp)
                    .iat((Long) null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("iat (issued at) is required");
        }
    }

    @Nested
    @DisplayName("Optional Claims")
    class OptionalClaims {

        @Test
        @DisplayName("Should build claims with auth_time")
        void shouldBuildClaimsWithAuthTime() {
            long authTime = Instant.now().getEpochSecond();

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .authTime(authTime)
                    .build();

            assertThat(claims.getAuthTime()).isEqualTo(authTime);
        }

        @Test
        @DisplayName("Should build claims with nonce")
        void shouldBuildClaimsWithNonce() {
            String nonce = "nonce-123";

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .nonce(nonce)
                    .build();

            assertThat(claims.getNonce()).isEqualTo(nonce);
        }

        @Test
        @DisplayName("Should build claims with acr")
        void shouldBuildClaimsWithAcr() {
            String acr = "urn:mace:incommon:iap:silver";

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .acr(acr)
                    .build();

            assertThat(claims.getAcr()).isEqualTo(acr);
        }

        @Test
        @DisplayName("Should build claims with amr")
        void shouldBuildClaimsWithAmr() {
            String[] amr = new String[]{"pwd", "mfa"};

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .amr(amr)
                    .build();

            assertThat(claims.getAmr()).isEqualTo(amr);
        }

        @Test
        @DisplayName("Should build claims with azp")
        void shouldBuildClaimsWithAzp() {
            String azp = "azp-client";

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .azp(azp)
                    .build();

            assertThat(claims.getAzp()).isEqualTo(azp);
        }

        @Test
        @DisplayName("Should build claims with additional claims")
        void shouldBuildClaimsWithAdditionalClaims() {
            Map<String, Object> additionalClaims = Map.of(
                    "custom_claim", "custom_value",
                    "number_claim", 123
            );

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .additionalClaims(additionalClaims)
                    .build();

            assertThat(claims.getAdditionalClaims()).isNotNull();
            assertThat(claims.getAdditionalClaims().get("custom_claim")).isEqualTo("custom_value");
            assertThat(claims.getAdditionalClaims().get("number_claim")).isEqualTo(123);
        }
    }

    @Nested
    @DisplayName("Instant Methods")
    class InstantMethods {

        @Test
        @DisplayName("Should set exp from Instant")
        void shouldSetExpFromInstant() {
            Instant expInstant = Instant.now().plusSeconds(3600);

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .exp(expInstant)
                    .build();

            assertThat(claims.getExp()).isEqualTo(expInstant.getEpochSecond());
        }

        @Test
        @DisplayName("Should set iat from Instant")
        void shouldSetIatFromInstant() {
            Instant iatInstant = Instant.now();

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .iat(iatInstant)
                    .build();

            assertThat(claims.getIat()).isEqualTo(iatInstant.getEpochSecond());
        }

        @Test
        @DisplayName("Should set auth_time from Instant")
        void shouldSetAuthTimeFromInstant() {
            Instant authTimeInstant = Instant.now().minusSeconds(60);

            IdTokenClaims claims = createBasicClaimsBuilder()
                    .authTime(authTimeInstant)
                    .build();

            assertThat(claims.getAuthTime()).isEqualTo(authTimeInstant.getEpochSecond());
        }
    }

    @Nested
    @DisplayName("Equals and HashCode")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            IdTokenClaims claims1 = createBasicClaimsBuilder()
                    .nonce("nonce-123")
                    .acr("acr-456")
                    .build();

            IdTokenClaims claims2 = createBasicClaimsBuilder()
                    .nonce("nonce-123")
                    .acr("acr-456")
                    .build();

            assertThat(claims1).isEqualTo(claims2);
            assertThat(claims1.hashCode()).isEqualTo(claims2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when fields differ")
        void shouldNotBeEqualWhenFieldsDiffer() {
            IdTokenClaims claims1 = createBasicClaimsBuilder()
                    .nonce("nonce-123")
                    .build();

            IdTokenClaims claims2 = createBasicClaimsBuilder()
                    .nonce("nonce-456")
                    .build();

            assertThat(claims1).isNotEqualTo(claims2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            IdTokenClaims claims = createBasicClaimsBuilder().build();

            assertThat(claims).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different class")
        void shouldNotBeEqualToDifferentClass() {
            IdTokenClaims claims = createBasicClaimsBuilder().build();

            assertThat(claims).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString")
    class ToString {

        @Test
        @DisplayName("Should include required fields in toString")
        void shouldIncludeRequiredFieldsInToString() {
            IdTokenClaims claims = createBasicClaimsBuilder().build();

            String toString = claims.toString();

            assertThat(toString).contains(ISSUER);
            assertThat(toString).contains(SUBJECT);
            assertThat(toString).contains(AUDIENCE);
        }

        @Test
        @DisplayName("Should include optional fields when set")
        void shouldIncludeOptionalFieldsWhenSet() {
            IdTokenClaims claims = createBasicClaimsBuilder()
                    .nonce("nonce-123")
                    .acr("acr-456")
                    .azp("azp-789")
                    .build();

            String toString = claims.toString();

            assertThat(toString).contains("nonce-123");
            assertThat(toString).contains("acr-456");
            assertThat(toString).contains("azp-789");
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return null for unset optional fields")
        void shouldReturnNullForUnsetOptionalFields() {
            IdTokenClaims claims = createBasicClaimsBuilder().build();

            assertThat(claims.getAuthTime()).isNull();
            assertThat(claims.getNonce()).isNull();
            assertThat(claims.getAcr()).isNull();
            assertThat(claims.getAmr()).isNull();
            assertThat(claims.getAzp()).isNull();
            assertThat(claims.getAdditionalClaims()).isNull();
        }
    }

    // Helper methods

    private IdTokenClaims.Builder createBasicClaimsBuilder() {
        long exp = Instant.now().plusSeconds(3600).getEpochSecond();
        long iat = Instant.now().getEpochSecond();

        return IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .exp(exp)
                .iat(iat);
    }
}
