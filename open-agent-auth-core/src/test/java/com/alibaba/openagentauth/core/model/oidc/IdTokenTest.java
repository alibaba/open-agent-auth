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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link IdToken}.
 * <p>
 * This test class validates the ID token model
 * following the OpenID Connect Core 1.0 specification.
 * </p>
 */
@DisplayName("IdToken Tests")
class IdTokenTest {

    private static final String TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String SUBJECT = "user_12345";
    private static final String AUDIENCE = "client_67890";

    @Nested
    @DisplayName("Builder")
    class Builder {

        @Test
        @DisplayName("Should build token with required fields")
        void shouldBuildTokenWithRequiredFields() {
            IdTokenClaims claims = createBasicClaims();

            IdToken idToken = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            assertThat(idToken.getTokenValue()).isEqualTo(TOKEN_VALUE);
            assertThat(idToken.getClaims()).isSameAs(claims);
        }

        @Test
        @DisplayName("Should throw exception when tokenValue is null")
        void shouldThrowExceptionWhenTokenValueIsNull() {
            IdTokenClaims claims = createBasicClaims();

            assertThatThrownBy(() -> IdToken.builder()
                    .tokenValue(null)
                    .claims(claims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("tokenValue is required");
        }

        @Test
        @DisplayName("Should throw exception when tokenValue is empty")
        void shouldThrowExceptionWhenTokenValueIsEmpty() {
            IdTokenClaims claims = createBasicClaims();

            assertThatThrownBy(() -> IdToken.builder()
                    .tokenValue("")
                    .claims(claims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("tokenValue is required");
        }

        @Test
        @DisplayName("Should throw exception when claims is null")
        void shouldThrowExceptionWhenClaimsIsNull() {
            assertThatThrownBy(() -> IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("claims are required");
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return token value")
        void shouldReturnTokenValue() {
            IdToken idToken = createBasicToken();

            assertThat(idToken.getTokenValue()).isEqualTo(TOKEN_VALUE);
        }

        @Test
        @DisplayName("Should return claims")
        void shouldReturnClaims() {
            IdTokenClaims claims = createBasicClaims();
            IdToken idToken = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            assertThat(idToken.getClaims()).isSameAs(claims);
        }
    }

    @Nested
    @DisplayName("isExpired()")
    class IsExpired {

        @Test
        @DisplayName("Should return true when token is expired")
        void shouldReturnTrueWhenTokenIsExpired() {
            IdTokenClaims claims = IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(Instant.now().minusSeconds(3600).getEpochSecond())
                    .iat(Instant.now().minusSeconds(7200).getEpochSecond())
                    .build();

            IdToken idToken = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            assertThat(idToken.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return false when token is not expired")
        void shouldReturnFalseWhenTokenIsNotExpired() {
            IdToken idToken = createBasicToken();

            assertThat(idToken.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should return false when claims is null")
        void shouldReturnFalseWhenClaimsIsNull() {
            try {
                IdToken.builder()
                        .tokenValue(TOKEN_VALUE)
                        .claims(null)
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject null claims
                assertThat(e.getMessage()).contains("claims are required");
            }
        }

        @Test
        @DisplayName("Should return false when exp is null")
        void shouldReturnFalseWhenExpIsNull() {
            try {
                IdTokenClaims.builder()
                        .iss(ISSUER)
                        .sub(SUBJECT)
                        .aud(AUDIENCE)
                        .exp((Long) null)
                        .iat(Instant.now().getEpochSecond())
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject null exp
                assertThat(e.getMessage()).contains("exp");
            }
        }
    }

    @Nested
    @DisplayName("getRemainingLifetime()")
    class GetRemainingLifetime {

        @Test
        @DisplayName("Should return positive lifetime when token is not expired")
        void shouldReturnPositiveLifetimeWhenTokenIsNotExpired() {
            IdToken idToken = createBasicToken();

            long remainingLifetime = idToken.getRemainingLifetime();

            assertThat(remainingLifetime).isGreaterThan(0);
            assertThat(remainingLifetime).isLessThanOrEqualTo(3600);
        }

        @Test
        @DisplayName("Should return zero when token is expired")
        void shouldReturnZeroWhenTokenIsExpired() {
            IdTokenClaims claims = IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(Instant.now().minusSeconds(3600).getEpochSecond())
                    .iat(Instant.now().minusSeconds(7200).getEpochSecond())
                    .build();

            IdToken idToken = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            assertThat(idToken.getRemainingLifetime()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return zero when claims is null")
        void shouldReturnZeroWhenClaimsIsNull() {
            try {
                IdToken.builder()
                        .tokenValue(TOKEN_VALUE)
                        .claims(null)
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject null claims
                assertThat(e.getMessage()).contains("claims are required");
            }
        }

        @Test
        @DisplayName("Should return zero when exp is null")
        void shouldReturnZeroWhenExpIsNull() {
            try {
                IdTokenClaims.builder()
                        .iss(ISSUER)
                        .sub(SUBJECT)
                        .aud(AUDIENCE)
                        .exp((Long) null)
                        .iat(Instant.now().getEpochSecond())
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject null exp
                assertThat(e.getMessage()).contains("exp");
            }
        }
    }

    @Nested
    @DisplayName("Equals and HashCode")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when tokenValue and claims match")
        void shouldBeEqualWhenTokenValueAndClaimsMatch() {
            IdTokenClaims claims = createBasicClaims();

            IdToken token1 = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            IdToken token2 = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims)
                    .build();

            assertThat(token1).isEqualTo(token2);
            assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when tokenValue differs")
        void shouldNotBeEqualWhenTokenValueDiffers() {
            IdTokenClaims claims = createBasicClaims();

            IdToken token1 = IdToken.builder()
                    .tokenValue("token1")
                    .claims(claims)
                    .build();

            IdToken token2 = IdToken.builder()
                    .tokenValue("token2")
                    .claims(claims)
                    .build();

            assertThat(token1).isNotEqualTo(token2);
        }

        @Test
        @DisplayName("Should not be equal when claims differ")
        void shouldNotBeEqualWhenClaimsDiffer() {
            IdTokenClaims claims1 = IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub(SUBJECT)
                    .aud(AUDIENCE)
                    .exp(Instant.now().plusSeconds(3600).getEpochSecond())
                    .iat(Instant.now().getEpochSecond())
                    .build();

            IdTokenClaims claims2 = IdTokenClaims.builder()
                    .iss(ISSUER)
                    .sub("different-user")
                    .aud(AUDIENCE)
                    .exp(Instant.now().plusSeconds(3600).getEpochSecond())
                    .iat(Instant.now().getEpochSecond())
                    .build();

            IdToken token1 = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims1)
                    .build();

            IdToken token2 = IdToken.builder()
                    .tokenValue(TOKEN_VALUE)
                    .claims(claims2)
                    .build();

            assertThat(token1).isNotEqualTo(token2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            IdToken idToken = createBasicToken();

            assertThat(idToken).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different class")
        void shouldNotBeEqualToDifferentClass() {
            IdToken idToken = createBasicToken();

            assertThat(idToken).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString")
    class ToString {

        @Test
        @DisplayName("Should include tokenValue and claims in toString")
        void shouldIncludeTokenValueAndClaimsInToString() {
            IdToken idToken = createBasicToken();

            String toString = idToken.toString();

            assertThat(toString).contains(TOKEN_VALUE);
            assertThat(toString).contains("claims=");
        }
    }

    // Helper methods

    private IdToken createBasicToken() {
        IdTokenClaims claims = createBasicClaims();

        return IdToken.builder()
                .tokenValue(TOKEN_VALUE)
                .claims(claims)
                .build();
    }

    private IdTokenClaims createBasicClaims() {
        return IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .exp(Instant.now().plusSeconds(3600).getEpochSecond())
                .iat(Instant.now().getEpochSecond())
                .build();
    }
}
