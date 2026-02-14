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
package com.alibaba.openagentauth.core.model.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WorkloadProofToken}.
 * <p>
 * Tests the Workload Proof Token (WPT) model's behavior including:
 * <ul>
 *   <li>Building tokens with all required and optional fields</li>
 *   <li>Getter methods for header, claims, and signature</li>
 *   <li>Token validation (isExpired, isValid)</li>
 *   <li>Builder pattern with validation</li>
 *   <li>Header and Claims inner classes</li>
 *   <li>Token hash handling (wth, ath, tth, oth)</li>
 *   <li>equals, hashCode, and toString methods</li>
 *   <li>Error handling for missing required fields</li>
 * </ul>
 * </p>
 */
@DisplayName("WorkloadProofToken Tests")
class WorkloadProofTokenTest {

    private Date futureExpirationTime;
    private Date pastExpirationTime;
    private WorkloadProofToken.Header validHeader;
    private WorkloadProofToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        // Set up test dates
        futureExpirationTime = new Date(System.currentTimeMillis() + 3600000); // 1 hour from now
        pastExpirationTime = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago

        // Set up valid header
        validHeader = WorkloadProofToken.Header.builder()
                .type(WorkloadProofToken.Header.MEDIA_TYPE)
                .algorithm("ES256")
                .build();

        // Set up valid claims
        validClaims = WorkloadProofToken.Claims.builder()
                .audience("https://resource-server.example.com")
                .expirationTime(futureExpirationTime)
                .jwtId("test-jti-456")
                .workloadTokenHash("abc123def456")
                .accessTokenHash("xyz789uvw012")
                .transactionTokenHash("mno345pqr678")
                .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getHeader()).isEqualTo(validHeader);
            assertThat(token.getClaims()).isEqualTo(validClaims);
            assertThat(token.getSignature()).isEqualTo("test-signature");
            assertThat(token.getJwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should build token with minimal required fields")
        void shouldBuildTokenWithMinimalRequiredFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getHeader()).isEqualTo(validHeader);
            assertThat(token.getClaims()).isEqualTo(validClaims);
            assertThat(token.getSignature()).isNull();
            assertThat(token.getJwtString()).isNull();
        }

        @Test
        @DisplayName("Should build token with only signature")
        void shouldBuildTokenWithOnlySignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature-only")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getSignature()).isEqualTo("signature-only");
            assertThat(token.getJwtString()).isNull();
        }

        @Test
        @DisplayName("Should build token with only jwtString")
        void shouldBuildTokenWithOnlyJwtString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("jwt-string-only")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getSignature()).isNull();
            assertThat(token.getJwtString()).isEqualTo("jwt-string-only");
        }

        @Test
        @DisplayName("Should throw exception when building with null header")
        void shouldThrowExceptionWhenBuildingWithNullHeader() {
            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .header(null)
                    .claims(validClaims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("header is REQUIRED for WPT");
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for WPT");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should get header")
        void shouldGetHeader() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getHeader()).isEqualTo(validHeader);
        }

        @Test
        @DisplayName("Should get claims")
        void shouldGetClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getClaims()).isEqualTo(validClaims);
        }

        @Test
        @DisplayName("Should get signature")
        void shouldGetSignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .build();

            assertThat(token.getSignature()).isEqualTo("test-signature");
        }

        @Test
        @DisplayName("Should return null when signature not set")
        void shouldReturnNullWhenSignatureNotSet() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getSignature()).isNull();
        }

        @Test
        @DisplayName("Should get jwtString")
        void shouldGetJwtString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token.getJwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should return null when jwtString not set")
        void shouldReturnNullWhenJwtStringNotSet() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getJwtString()).isNull();
        }

        @Test
        @DisplayName("Should get audience from claims")
        void shouldGetAudienceFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getAudience()).isEqualTo("https://resource-server.example.com");
        }

        @Test
        @DisplayName("Should return null when audience not set in claims")
        void shouldReturnNullWhenAudienceNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutAudience = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutAudience)
                    .build();

            assertThat(token.getAudience()).isNull();
        }

        @Test
        @DisplayName("Should get expiration time from claims")
        void shouldGetExpirationTimeFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getExpirationTime()).isEqualTo(futureExpirationTime);
        }

        @Test
        @DisplayName("Should return null when expiration time not set in claims")
        void shouldReturnNullWhenExpirationTimeNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutExpiration)
                    .build();

            assertThat(token.getExpirationTime()).isNull();
        }

        @Test
        @DisplayName("Should get JWT ID from claims")
        void shouldGetJwtIdFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getJwtId()).isEqualTo("test-jti-456");
        }

        @Test
        @DisplayName("Should return null when JWT ID not set in claims")
        void shouldReturnNullWhenJwtIdNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutJti = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutJti)
                    .build();

            assertThat(token.getJwtId()).isNull();
        }

        @Test
        @DisplayName("Should get workload token hash from claims")
        void shouldGetWorkloadTokenHashFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getWorkloadTokenHash()).isEqualTo("abc123def456");
        }

        @Test
        @DisplayName("Should get access token hash from claims")
        void shouldGetAccessTokenHashFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getAccessTokenHash()).isEqualTo("xyz789uvw012");
        }

        @Test
        @DisplayName("Should return null when access token hash not set in claims")
        void shouldReturnNullWhenAccessTokenHashNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutAccessTokenHash = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutAccessTokenHash)
                    .build();

            assertThat(token.getAccessTokenHash()).isNull();
        }

        @Test
        @DisplayName("Should get transaction token hash from claims")
        void shouldGetTransactionTokenHashFromClaims() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getTransactionTokenHash()).isEqualTo("mno345pqr678");
        }

        @Test
        @DisplayName("Should return null when transaction token hash not set in claims")
        void shouldReturnNullWhenTransactionTokenHashNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutTransactionTokenHash = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutTransactionTokenHash)
                    .build();

            assertThat(token.getTransactionTokenHash()).isNull();
        }

        @Test
        @DisplayName("Should get other token hashes from claims")
        void shouldGetOtherTokenHashesFromClaims() {
            Map<String, String> otherTokenHashes = new HashMap<>();
            otherTokenHashes.put("custom-token", "hash123");

            WorkloadProofToken.Claims claimsWithOtherHashes = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .otherTokenHashes(otherTokenHashes)
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithOtherHashes)
                    .build();

            assertThat(token.getOtherTokenHashes()).isEqualTo(otherTokenHashes);
        }

        @Test
        @DisplayName("Should return null when other token hashes not set in claims")
        void shouldReturnNullWhenOtherTokenHashesNotSetInClaims() {
            WorkloadProofToken.Claims claimsWithoutOtherHashes = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutOtherHashes)
                    .build();

            assertThat(token.getOtherTokenHashes()).isNull();
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return false for expired token")
        void shouldReturnFalseForExpiredToken() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return false for expired token in isValid")
        void shouldReturnFalseForExpiredTokenInIsValid() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return false when not expired")
        void shouldReturnFalseWhenNotExpired() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should return true for valid token without expiration time")
        void shouldReturnTrueForValidTokenWithoutExpirationTime() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutExpiration)
                    .build();

            assertThat(token.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("Header Tests")
    class HeaderTests {

        @Test
        @DisplayName("Should build header with all fields")
        void shouldBuildHeaderWithAllFields() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header.getType()).isEqualTo(WorkloadProofToken.Header.MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should build header with default type")
        void shouldBuildHeaderWithDefaultType() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .algorithm("RS256")
                    .build();

            assertThat(header.getType()).isEqualTo(WorkloadProofToken.Header.MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should throw exception when building header with null type")
        void shouldThrowExceptionWhenBuildingHeaderWithNullType() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(null)
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wpt+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty type")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyType() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type("")
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wpt+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with null algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithNullAlgorithm() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyAlgorithm() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should implement equals correctly for header")
        void shouldImplementEqualsCorrectlyForHeader() {
            WorkloadProofToken.Header header1 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header2 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header3 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header1).isEqualTo(header2);
            assertThat(header1).isNotEqualTo(header3);
            assertThat(header1).isNotEqualTo(null);
            assertThat(header1).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should implement hashCode correctly for header")
        void shouldImplementHashCodeCorrectlyForHeader() {
            WorkloadProofToken.Header header1 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header2 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header1.hashCode()).isEqualTo(header2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for header")
        void shouldImplementToStringForHeader() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            String toString = header.toString();
            assertThat(toString).contains("wpt+jwt");
            assertThat(toString).contains("ES256");
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            Map<String, String> otherTokenHashes = new HashMap<>();
            otherTokenHashes.put("custom-token", "hash123");

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .jwtId("test-jti")
                    .workloadTokenHash("abc123")
                    .accessTokenHash("xyz789")
                    .transactionTokenHash("mno345")
                    .otherTokenHashes(otherTokenHashes)
                    .build();

            assertThat(claims.getAudience()).isEqualTo("https://resource-server.example.com");
            assertThat(claims.getExpirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.getJwtId()).isEqualTo("test-jti");
            assertThat(claims.getWorkloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.getAccessTokenHash()).isEqualTo("xyz789");
            assertThat(claims.getTransactionTokenHash()).isEqualTo("mno345");
            assertThat(claims.getOtherTokenHashes()).isEqualTo(otherTokenHashes);
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims.getAudience()).isNull();
            assertThat(claims.getExpirationTime()).isNull();
            assertThat(claims.getJwtId()).isNull();
            assertThat(claims.getWorkloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.getAccessTokenHash()).isNull();
            assertThat(claims.getTransactionTokenHash()).isNull();
            assertThat(claims.getOtherTokenHashes()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building claims with null workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithNullWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED according to draft-ietf-wimse-wpt");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptyWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED according to draft-ietf-wimse-wpt");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(expiredClaims.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should check if claims are not expired")
        void shouldCheckIfClaimsAreNotExpired() {
            assertThat(validClaims.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should check if claims are valid")
        void shouldCheckIfClaimsAreValid() {
            assertThat(validClaims.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should check if claims are invalid when expired")
        void shouldCheckIfClaimsAreInvalidWhenExpired() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(expiredClaims.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return true for valid claims without expiration time")
        void shouldReturnTrueForValidClaimsWithoutExpirationTime() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claimsWithoutExpiration.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should implement equals correctly for claims")
        void shouldImplementEqualsCorrectlyForClaims() {
            WorkloadProofToken.Claims claims1 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims2 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims3 = WorkloadProofToken.Claims.builder()
                    .audience("https://other-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims1).isEqualTo(claims2);
            assertThat(claims1).isNotEqualTo(claims3);
        }

        @Test
        @DisplayName("Should implement hashCode correctly for claims")
        void shouldImplementHashCodeCorrectlyForClaims() {
            WorkloadProofToken.Claims claims1 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims2 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims1.hashCode()).isEqualTo(claims2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for claims")
        void shouldImplementToStringForClaims() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            String toString = claims.toString();
            assertThat(toString).contains("Claims");
            assertThat(toString).contains("workloadTokenHash");
        }
    }

    @Nested
    @DisplayName("Token Hash Tests")
    class TokenHashTests {

        @Test
        @DisplayName("Should handle workload token hash")
        void shouldHandleWorkloadTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash-123")
                    .build();

            assertThat(claims.getWorkloadTokenHash()).isEqualTo("wit-hash-123");
        }

        @Test
        @DisplayName("Should handle access token hash")
        void shouldHandleAccessTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .accessTokenHash("at-hash-456")
                    .build();

            assertThat(claims.getAccessTokenHash()).isEqualTo("at-hash-456");
        }

        @Test
        @DisplayName("Should handle transaction token hash")
        void shouldHandleTransactionTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .transactionTokenHash("tt-hash-789")
                    .build();

            assertThat(claims.getTransactionTokenHash()).isEqualTo("tt-hash-789");
        }

        @Test
        @DisplayName("Should handle other token hashes")
        void shouldHandleOtherTokenHashes() {
            Map<String, String> otherTokenHashes = new HashMap<>();
            otherTokenHashes.put("token-type-1", "hash1");
            otherTokenHashes.put("token-type-2", "hash2");

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .otherTokenHashes(otherTokenHashes)
                    .build();

            assertThat(claims.getOtherTokenHashes()).hasSize(2);
            assertThat(claims.getOtherTokenHashes()).containsEntry("token-type-1", "hash1");
            assertThat(claims.getOtherTokenHashes()).containsEntry("token-type-2", "hash2");
        }

        @Test
        @DisplayName("Should handle empty other token hashes map")
        void shouldHandleEmptyOtherTokenHashesMap() {
            Map<String, String> emptyMap = new HashMap<>();

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .otherTokenHashes(emptyMap)
                    .build();

            assertThat(claims.getOtherTokenHashes()).isEmpty();
        }

        @Test
        @DisplayName("Should handle all token hash combinations")
        void shouldHandleAllTokenHashCombinations() {
            Map<String, String> otherTokenHashes = new HashMap<>();
            otherTokenHashes.put("custom", "custom-hash");

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://example.com")
                    .expirationTime(futureExpirationTime)
                    .jwtId("jti-123")
                    .workloadTokenHash("wit-hash")
                    .accessTokenHash("at-hash")
                    .transactionTokenHash("tt-hash")
                    .otherTokenHashes(otherTokenHashes)
                    .build();

            assertThat(claims.getWorkloadTokenHash()).isEqualTo("wit-hash");
            assertThat(claims.getAccessTokenHash()).isEqualTo("at-hash");
            assertThat(claims.getTransactionTokenHash()).isEqualTo("tt-hash");
            assertThat(claims.getOtherTokenHashes()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Equals HashCode ToString Tests")
    class EqualsHashCodeToStringTests {

        @Test
        @DisplayName("Should implement equals correctly")
        void shouldImplementEqualsCorrectly() {
            WorkloadProofToken token1 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadProofToken token2 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadProofToken token3 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature2")
                    .build();

            assertThat(token1).isEqualTo(token2);
            assertThat(token1).isNotEqualTo(token3);
            assertThat(token1).isNotEqualTo(null);
            assertThat(token1).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should implement hashCode correctly")
        void shouldImplementHashCodeCorrectly() {
            WorkloadProofToken token1 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadProofToken token2 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString")
        void shouldImplementToString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .build();

            String toString = token.toString();
            assertThat(toString).isNotNull();
            assertThat(toString.length()).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should have consistent equals and hashCode")
        void shouldHaveConsistentEqualsAndHashCode() {
            WorkloadProofToken token1 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadProofToken token2 = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            assertThat(token1.equals(token2)).isEqualTo(token1.hashCode() == token2.hashCode());
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty audience")
        void shouldHandleEmptyAudience() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("")
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getAudience()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty JWT ID")
        void shouldHandleEmptyJwtId() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .jwtId("")
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getJwtId()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("")
                    .build();

            assertThat(token.getSignature()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty jwtString")
        void shouldHandleEmptyJwtString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("")
                    .build();

            assertThat(token.getJwtString()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle single character workload token hash")
        void shouldHandleSingleCharacterWorkloadTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("a")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getWorkloadTokenHash()).isEqualTo("a");
        }

        @Test
        @DisplayName("Should handle long workload token hash")
        void shouldHandleLongWorkloadTokenHash() {
            String longHash = "a".repeat(1000);
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash(longHash)
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getWorkloadTokenHash()).isEqualTo(longHash);
        }

        @Test
        @DisplayName("Should handle null other token hashes")
        void shouldHandleNullOtherTokenHashes() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .otherTokenHashes(null)
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getOtherTokenHashes()).isNull();
        }

        @Test
        @DisplayName("Should handle claims with only required field")
        void shouldHandleClaimsWithOnlyRequiredField() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("required-only")
                    .build();

            assertThat(claims.getWorkloadTokenHash()).isEqualTo("required-only");
            assertThat(claims.getAudience()).isNull();
            assertThat(claims.getExpirationTime()).isNull();
            assertThat(claims.getJwtId()).isNull();
            assertThat(claims.getAccessTokenHash()).isNull();
            assertThat(claims.getTransactionTokenHash()).isNull();
            assertThat(claims.getOtherTokenHashes()).isNull();
        }
    }
}
