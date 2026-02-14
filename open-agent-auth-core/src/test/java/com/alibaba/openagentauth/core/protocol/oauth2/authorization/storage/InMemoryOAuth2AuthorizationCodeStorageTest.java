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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryOAuth2AuthorizationCodeStorage}.
 * <p>
 * This test class validates the in-memory storage implementation for OAuth 2.0 authorization codes.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749 - Authorization Code</a>
 */
@DisplayName("InMemoryOAuth2AuthorizationCodeStorage Tests")
class InMemoryOAuth2AuthorizationCodeStorageTest {

    private InMemoryOAuth2AuthorizationCodeStorage storage;

    private static final String TEST_CODE = "auth_code_xyz";
    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_SUBJECT = "user_123";
    private static final String TEST_SCOPE = "read write";
    private static final long DEFAULT_EXPIRATION_SECONDS = 600L;

    @BeforeEach
    void setUp() {
        storage = new InMemoryOAuth2AuthorizationCodeStorage();
    }

    @AfterEach
    void tearDown() {
        if (storage != null) {
            storage.shutdown();
        }
    }

    @Nested
    @DisplayName("store() - Store Authorization Code")
    class StoreAuthorizationCode {

        @Test
        @DisplayName("Should successfully store authorization code")
        void shouldSuccessfullyStoreAuthorizationCode() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();

            // Act
            storage.store(authCode);

            // Assert
            assertThat(storage.size()).isEqualTo(1);
            assertThat(storage.isEmpty()).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when storing null authorization code")
        void shouldThrowExceptionWhenStoringNullAuthorizationCode() {
            // Act & Assert
            assertThatThrownBy(() -> storage.store(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authorization code cannot be null");
        }

        @Test
        @DisplayName("Should overwrite existing authorization code with same code")
        void shouldOverwriteExistingAuthorizationCodeWithSameCode() {
            // Arrange
            AuthorizationCode authCode1 = createValidAuthorizationCode();
            AuthorizationCode authCode2 = AuthorizationCode.builder()
                    .code(TEST_CODE)
                    .clientId("different-client")
                    .redirectUri(TEST_REDIRECT_URI)
                    .subject(TEST_SUBJECT)
                    .scope(TEST_SCOPE)
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                    .used(false)
                    .build();

            // Act
            storage.store(authCode1);
            storage.store(authCode2);

            // Assert
            assertThat(storage.size()).isEqualTo(1);
            AuthorizationCode retrieved = storage.retrieve(TEST_CODE);
            assertThat(retrieved.getClientId()).isEqualTo("different-client");
        }
    }

    @Nested
    @DisplayName("retrieve() - Retrieve Authorization Code")
    class RetrieveAuthorizationCode {

        @Test
        @DisplayName("Should successfully retrieve stored authorization code")
        void shouldSuccessfullyRetrieveStoredAuthorizationCode() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            storage.store(authCode);

            // Act
            AuthorizationCode retrieved = storage.retrieve(TEST_CODE);

            // Assert
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getCode()).isEqualTo(TEST_CODE);
            assertThat(retrieved.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(retrieved.getSubject()).isEqualTo(TEST_SUBJECT);
        }

        @Test
        @DisplayName("Should return null when code does not exist")
        void shouldReturnNullWhenCodeDoesNotExist() {
            // Act
            AuthorizationCode retrieved = storage.retrieve("non_existent_code");

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when code is expired")
        void shouldReturnNullWhenCodeIsExpired() {
            // Arrange
            AuthorizationCode authCode = createExpiredAuthorizationCode();
            storage.store(authCode);

            // Act
            AuthorizationCode retrieved = storage.retrieve(TEST_CODE);

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when code is already used")
        void shouldReturnNullWhenCodeIsAlreadyUsed() {
            // Arrange
            AuthorizationCode authCode = createUsedAuthorizationCode();
            storage.store(authCode);

            // Act
            AuthorizationCode retrieved = storage.retrieve(TEST_CODE);

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> storage.retrieve(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Code cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when code is empty")
        void shouldThrowExceptionWhenCodeIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> storage.retrieve(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Code cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("consume() - Consume Authorization Code")
    class ConsumeAuthorizationCode {

        @Test
        @DisplayName("Should successfully consume authorization code")
        void shouldSuccessfullyConsumeAuthorizationCode() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            storage.store(authCode);

            // Act
            AuthorizationCode consumed = storage.consume(TEST_CODE);

            // Assert
            assertThat(consumed).isNotNull();
            assertThat(consumed.isUsed()).isTrue();
            
            // Verify it cannot be consumed again
            assertThatThrownBy(() -> storage.consume(TEST_CODE))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("Authorization code has already been used");
        }

        @Test
        @DisplayName("Should throw exception when consuming non-existent code")
        void shouldThrowExceptionWhenConsumingNonExistentCode() {
            // Act & Assert
            assertThatThrownBy(() -> storage.consume("non_existent_code"))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("Authorization code not found");
        }

        @Test
        @DisplayName("Should throw exception when consuming expired code")
        void shouldThrowExceptionWhenConsumingExpiredCode() {
            // Arrange
            AuthorizationCode authCode = createExpiredAuthorizationCode();
            storage.store(authCode);

            // Act & Assert
            assertThatThrownBy(() -> storage.consume(TEST_CODE))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("Authorization code has expired");
        }

        @Test
        @DisplayName("Should throw exception when consuming already used code")
        void shouldThrowExceptionWhenConsumingAlreadyUsedCode() {
            // Arrange
            AuthorizationCode authCode = createUsedAuthorizationCode();
            storage.store(authCode);

            // Act & Assert
            assertThatThrownBy(() -> storage.consume(TEST_CODE))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("Authorization code has already been used");
        }

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> storage.consume(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Code cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("delete() - Delete Authorization Code")
    class DeleteAuthorizationCode {

        @Test
        @DisplayName("Should successfully delete authorization code")
        void shouldSuccessfullyDeleteAuthorizationCode() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            storage.store(authCode);
            assertThat(storage.size()).isEqualTo(1);

            // Act
            storage.delete(TEST_CODE);

            // Assert
            assertThat(storage.size()).isEqualTo(0);
            assertThat(storage.retrieve(TEST_CODE)).isNull();
        }

        @Test
        @DisplayName("Should not throw exception when deleting non-existent code")
        void shouldNotThrowExceptionWhenDeletingNonExistentCode() {
            // Act & Assert - Should not throw any exception
            storage.delete("non_existent_code");
        }

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> storage.delete(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Code cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("isValid() - Check Code Validity")
    class IsValid {

        @Test
        @DisplayName("Should return true for valid authorization code")
        void shouldReturnTrueForValidAuthorizationCode() {
            // Arrange
            AuthorizationCode authCode = createValidAuthorizationCode();
            storage.store(authCode);

            // Act
            boolean isValid = storage.isValid(TEST_CODE);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false for non-existent code")
        void shouldReturnFalseForNonExistentCode() {
            // Act
            boolean isValid = storage.isValid("non_existent_code");

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for expired code")
        void shouldReturnFalseForExpiredCode() {
            // Arrange
            AuthorizationCode authCode = createExpiredAuthorizationCode();
            storage.store(authCode);

            // Act
            boolean isValid = storage.isValid(TEST_CODE);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for used code")
        void shouldReturnFalseForUsedCode() {
            // Arrange
            AuthorizationCode authCode = createUsedAuthorizationCode();
            storage.store(authCode);

            // Act
            boolean isValid = storage.isValid(TEST_CODE);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> storage.isValid(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Code cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("cleanupExpired() - Cleanup Expired Codes")
    class CleanupExpired {

        @Test
        @DisplayName("Should remove expired authorization codes")
        void shouldRemoveExpiredAuthorizationCodes() {
            // Arrange - Use different codes to avoid overwriting
            AuthorizationCode validCode = createValidAuthorizationCode();
            AuthorizationCode expiredCode = createExpiredAuthorizationCode("expired_code");
            AuthorizationCode usedCode = createUsedAuthorizationCode("used_code");

            storage.store(validCode);
            storage.store(expiredCode);
            storage.store(usedCode);

            assertThat(storage.size()).isEqualTo(3);

            // Act
            int removedCount = storage.cleanupExpired();

            // Assert
            assertThat(removedCount).isEqualTo(2); // expired and used codes
            assertThat(storage.size()).isEqualTo(1);
            assertThat(storage.retrieve(validCode.getCode())).isNotNull();
        }

        @Test
        @DisplayName("Should return zero when no expired codes")
        void shouldReturnZeroWhenNoExpiredCodes() {
            // Arrange
            AuthorizationCode validCode = createValidAuthorizationCode();
            storage.store(validCode);

            // Act
            int removedCount = storage.cleanupExpired();

            // Assert
            assertThat(removedCount).isEqualTo(0);
            assertThat(storage.size()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Utility Methods")
    class UtilityMethods {

        @Test
        @DisplayName("Should return correct size")
        void shouldReturnCorrectSize() {
            // Arrange
            storage.store(createValidAuthorizationCode());
            storage.store(AuthorizationCode.builder()
                    .code("code_2")
                    .clientId("client_2")
                    .redirectUri(TEST_REDIRECT_URI)
                    .subject("user_2")
                    .scope("read")
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                    .used(false)
                    .build());

            // Act
            int size = storage.size();

            // Assert
            assertThat(size).isEqualTo(2);
        }

        @Test
        @DisplayName("Should return true when storage is empty")
        void shouldReturnTrueWhenStorageIsEmpty() {
            // Act
            boolean isEmpty = storage.isEmpty();

            // Assert
            assertThat(isEmpty).isTrue();
        }

        @Test
        @DisplayName("Should return false when storage is not empty")
        void shouldReturnFalseWhenStorageIsNotEmpty() {
            // Arrange
            storage.store(createValidAuthorizationCode());

            // Act
            boolean isEmpty = storage.isEmpty();

            // Assert
            assertThat(isEmpty).isFalse();
        }
    }

    @Nested
    @DisplayName("shutdown() - Shutdown Storage")
    class Shutdown {

        @Test
        @DisplayName("Should clear storage and shutdown executor")
        void shouldClearStorageAndShutdownExecutor() {
            // Arrange
            storage.store(createValidAuthorizationCode());
            assertThat(storage.size()).isEqualTo(1);

            // Act
            storage.shutdown();

            // Assert
            assertThat(storage.size()).isEqualTo(0);
        }
    }

    // Helper methods

    private AuthorizationCode createValidAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                .used(false)
                .build();
    }

    private AuthorizationCode createExpiredAuthorizationCode() {
        return createExpiredAuthorizationCode(TEST_CODE);
    }

    private AuthorizationCode createExpiredAuthorizationCode(String code) {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(code)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now.minusSeconds(DEFAULT_EXPIRATION_SECONDS * 2))
                .expiresAt(now.minusSeconds(100))
                .used(false)
                .build();
    }

    private AuthorizationCode createUsedAuthorizationCode() {
        return createUsedAuthorizationCode(TEST_CODE);
    }

    private AuthorizationCode createUsedAuthorizationCode(String code) {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(code)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                .used(true)
                .build();
    }
}
