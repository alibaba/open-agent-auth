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
package com.alibaba.openagentauth.core.protocol.oauth2.token.revocation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryTokenRevocationService}.
 */
@DisplayName("InMemoryTokenRevocationService Tests")
class InMemoryTokenRevocationServiceTest {

    private InMemoryTokenRevocationService revocationService;

    @BeforeEach
    void setUp() {
        revocationService = new InMemoryTokenRevocationService();
    }

    @Nested
    @DisplayName("revoke()")
    class RevokeTests {

        @Test
        @DisplayName("Should revoke a token successfully")
        void shouldRevokeTokenSuccessfully() {
            String token = "access-token-123";

            revocationService.revoke(token);

            assertThat(revocationService.isRevoked(token)).isTrue();
        }

        @Test
        @DisplayName("Should be idempotent when revoking same token twice")
        void shouldBeIdempotentWhenRevokingSameTokenTwice() {
            String token = "access-token-123";

            revocationService.revoke(token);
            revocationService.revoke(token);

            assertThat(revocationService.isRevoked(token)).isTrue();
        }

        @Test
        @DisplayName("Should throw NullPointerException when token is null")
        void shouldThrowWhenTokenIsNull() {
            assertThatThrownBy(() -> revocationService.revoke(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Token cannot be null");
        }

        @Test
        @DisplayName("Should revoke multiple different tokens independently")
        void shouldRevokeMultipleTokensIndependently() {
            String token1 = "token-1";
            String token2 = "token-2";
            String token3 = "token-3";

            revocationService.revoke(token1);
            revocationService.revoke(token2);

            assertThat(revocationService.isRevoked(token1)).isTrue();
            assertThat(revocationService.isRevoked(token2)).isTrue();
            assertThat(revocationService.isRevoked(token3)).isFalse();
        }
    }

    @Nested
    @DisplayName("isRevoked()")
    class IsRevokedTests {

        @Test
        @DisplayName("Should return false for non-revoked token")
        void shouldReturnFalseForNonRevokedToken() {
            assertThat(revocationService.isRevoked("unknown-token")).isFalse();
        }

        @Test
        @DisplayName("Should return true for revoked token")
        void shouldReturnTrueForRevokedToken() {
            String token = "revoked-token";
            revocationService.revoke(token);

            assertThat(revocationService.isRevoked(token)).isTrue();
        }

        @Test
        @DisplayName("Should return false when token is null")
        void shouldReturnFalseWhenTokenIsNull() {
            assertThat(revocationService.isRevoked(null)).isFalse();
        }
    }
}
