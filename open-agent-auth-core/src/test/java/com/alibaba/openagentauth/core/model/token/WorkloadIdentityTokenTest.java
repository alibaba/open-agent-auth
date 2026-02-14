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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WorkloadIdentityToken}.
 * <p>
 * Tests the Workload Identity Token (WIT) model's behavior including:
 * <ul>
 *   <li>Building tokens with all required and optional fields</li>
 *   <li>Getter methods for header, claims, and signature</li>
 *   <li>Token validation (isExpired, isValid)</li>
 *   <li>Builder pattern with validation</li>
 *   <li>Header and Claims inner classes</li>
 *   <li>Confirmation and JWK handling</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Error handling for missing required fields</li>
 * </ul>
 * </p>
 */
@DisplayName("WorkloadIdentityToken Tests")
class WorkloadIdentityTokenTest {

    private Date futureExpirationTime;
    private Date pastExpirationTime;
    private Jwk testJwk;
    private WorkloadIdentityToken.Header validHeader;
    private WorkloadIdentityToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        // Set up test dates
        futureExpirationTime = new Date(System.currentTimeMillis() + 3600000); // 1 hour from now
        pastExpirationTime = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago

        // Set up test JWK
        testJwk = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .curve(Jwk.Curve.P_256)
                .x("test_x_value")
                .y("test_y_value")
                .build();

        // Set up valid header
        validHeader = WorkloadIdentityToken.Header.builder()
                .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                .algorithm("ES256")
                .build();

        // Set up valid claims
        WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(testJwk)
                .build();

        validClaims = WorkloadIdentityToken.Claims.builder()
                .issuer("https://idp.example.com")
                .subject("spiffe://example.com/workload/my-workload")
                .expirationTime(futureExpirationTime)
                .jwtId("test-jti-123")
                .confirmation(confirmation)
                .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
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
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
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
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
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
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
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
            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .header(null)
                    .claims(validClaims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("header is REQUIRED for WIT");
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for WIT");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should get header")
        void shouldGetHeader() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getHeader()).isEqualTo(validHeader);
        }

        @Test
        @DisplayName("Should get claims")
        void shouldGetClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getClaims()).isEqualTo(validClaims);
        }

        @Test
        @DisplayName("Should get signature")
        void shouldGetSignature() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .build();

            assertThat(token.getSignature()).isEqualTo("test-signature");
        }

        @Test
        @DisplayName("Should return null when signature not set")
        void shouldReturnNullWhenSignatureNotSet() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getSignature()).isNull();
        }

        @Test
        @DisplayName("Should get jwtString")
        void shouldGetJwtString() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token.getJwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should return null when jwtString not set")
        void shouldReturnNullWhenJwtStringNotSet() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getJwtString()).isNull();
        }

        @Test
        @DisplayName("Should get issuer from claims")
        void shouldGetIssuerFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getIssuer()).isEqualTo("https://idp.example.com");
        }

        @Test
        @DisplayName("Should return null when issuer not set in claims")
        void shouldReturnNullWhenIssuerNotSetInClaims() {
            WorkloadIdentityToken.Claims claimsWithoutIssuer = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutIssuer)
                    .build();

            assertThat(token.getIssuer()).isNull();
        }

        @Test
        @DisplayName("Should get subject from claims")
        void shouldGetSubjectFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getSubject()).isEqualTo("spiffe://example.com/workload/my-workload");
        }

        @Test
        @DisplayName("Should get expiration time from claims")
        void shouldGetExpirationTimeFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getExpirationTime()).isEqualTo(futureExpirationTime);
        }

        @Test
        @DisplayName("Should get JWT ID from claims")
        void shouldGetJwtIdFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getJwtId()).isEqualTo("test-jti-123");
        }

        @Test
        @DisplayName("Should return null when JWT ID not set in claims")
        void shouldReturnNullWhenJwtIdNotSetInClaims() {
            WorkloadIdentityToken.Claims claimsWithoutJti = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutJti)
                    .build();

            assertThat(token.getJwtId()).isNull();
        }

        @Test
        @DisplayName("Should get workload identifier from claims")
        void shouldGetWorkloadIdentifierFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getWorkloadIdentifier()).isEqualTo("spiffe://example.com/workload/my-workload");
        }

        @Test
        @DisplayName("Should get confirmation from claims")
        void shouldGetConfirmationFromClaims() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getConfirmation()).isNotNull();
            assertThat(token.getConfirmation().getJwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should return null when confirmation not set in claims")
        void shouldReturnNullWhenConfirmationNotSetInClaims() {
            WorkloadIdentityToken.Claims claimsWithoutConfirmation = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutConfirmation)
                    .build();

            assertThat(token.getConfirmation()).isNull();
        }

        @Test
        @DisplayName("Should get JWK from confirmation")
        void shouldGetJwkFromConfirmation() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.getJwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should return null when JWK not set in confirmation")
        void shouldReturnNullWhenJwkNotSetInConfirmation() {
            WorkloadIdentityToken.Claims claimsWithoutConfirmation = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutConfirmation)
                    .build();

            assertThat(token.getJwk()).isNull();
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return false for expired token")
        void shouldReturnFalseForExpiredToken() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return false for expired token in isValid")
        void shouldReturnFalseForExpiredTokenInIsValid() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return false when not expired")
        void shouldReturnFalseWhenNotExpired() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isExpired()).isFalse();
        }
    }

    @Nested
    @DisplayName("Header Tests")
    class HeaderTests {

        @Test
        @DisplayName("Should build header with all fields")
        void shouldBuildHeaderWithAllFields() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header.getType()).isEqualTo(WorkloadIdentityToken.Header.MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should build header with default type")
        void shouldBuildHeaderWithDefaultType() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .algorithm("RS256")
                    .build();

            assertThat(header.getType()).isEqualTo(WorkloadIdentityToken.Header.MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should throw exception when building header with null type")
        void shouldThrowExceptionWhenBuildingHeaderWithNullType() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type(null)
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wit+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty type")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyType() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type("")
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wit+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with null algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithNullAlgorithm() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyAlgorithm() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should implement equals correctly for header")
        void shouldImplementEqualsCorrectlyForHeader() {
            WorkloadIdentityToken.Header header1 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadIdentityToken.Header header2 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadIdentityToken.Header header3 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
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
            WorkloadIdentityToken.Header header1 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadIdentityToken.Header header2 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header1.hashCode()).isEqualTo(header2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for header")
        void shouldImplementToStringForHeader() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            String toString = header.toString();
            assertThat(toString).contains("wit+jwt");
            assertThat(toString).contains("ES256");
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .jwtId("test-jti")
                    .confirmation(confirmation)
                    .build();

            assertThat(claims.getIssuer()).isEqualTo("https://idp.example.com");
            assertThat(claims.getSubject()).isEqualTo("spiffe://example.com/workload/test");
            assertThat(claims.getExpirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.getJwtId()).isEqualTo("test-jti");
            assertThat(claims.getConfirmation()).isEqualTo(confirmation);
            assertThat(claims.getJwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            assertThat(claims.getIssuer()).isNull();
            assertThat(claims.getSubject()).isEqualTo("spiffe://example.com/workload/test");
            assertThat(claims.getExpirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.getJwtId()).isNull();
            assertThat(claims.getConfirmation()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building claims with null subject")
        void shouldThrowExceptionWhenBuildingClaimsWithNullSubject() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject(null)
                    .expirationTime(futureExpirationTime)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED according to draft-ietf-wimse-workload-creds");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty subject")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptySubject() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject("")
                    .expirationTime(futureExpirationTime)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED according to draft-ietf-wimse-workload-creds");
        }

        @Test
        @DisplayName("Should throw exception when building claims with null expiration time")
        void shouldThrowExceptionWhenBuildingClaimsWithNullExpirationTime() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("expirationTime (exp) is REQUIRED according to draft-ietf-wimse-workload-creds");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
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
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            assertThat(expiredClaims.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return workload identifier")
        void shouldReturnWorkloadIdentifier() {
            assertThat(validClaims.getWorkloadIdentifier()).isEqualTo("spiffe://example.com/workload/my-workload");
        }

        @Test
        @DisplayName("Should implement equals correctly for claims")
        void shouldImplementEqualsCorrectlyForClaims() {
            WorkloadIdentityToken.Claims claims1 = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken.Claims claims2 = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken.Claims claims3 = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://other-idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            assertThat(claims1).isEqualTo(claims2);
            assertThat(claims1).isNotEqualTo(claims3);
        }

        @Test
        @DisplayName("Should implement hashCode correctly for claims")
        void shouldImplementHashCodeCorrectlyForClaims() {
            WorkloadIdentityToken.Claims claims1 = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken.Claims claims2 = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            assertThat(claims1.hashCode()).isEqualTo(claims2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for claims")
        void shouldImplementToStringForClaims() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            String toString = claims.toString();
            assertThat(toString).contains("Claims");
            assertThat(toString).contains("subject");
        }
    }

    @Nested
    @DisplayName("Confirmation Tests")
    class ConfirmationTests {

        @Test
        @DisplayName("Should build confirmation with JWK")
        void shouldBuildConfirmationWithJwk() {
            WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            assertThat(confirmation.getJwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should throw exception when building confirmation with null JWK")
        void shouldThrowExceptionWhenBuildingConfirmationWithNullJwk() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("jwk is REQUIRED in confirmation (cnf) claim");
        }

        @Test
        @DisplayName("Should implement equals correctly for confirmation")
        void shouldImplementEqualsCorrectlyForConfirmation() {
            WorkloadIdentityToken.Claims.Confirmation confirmation1 = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            WorkloadIdentityToken.Claims.Confirmation confirmation2 = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            Jwk differentJwk = Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .x("different_x")
                    .y("different_y")
                    .build();

            WorkloadIdentityToken.Claims.Confirmation confirmation3 = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(differentJwk)
                    .build();

            assertThat(confirmation1).isEqualTo(confirmation2);
            assertThat(confirmation1).isNotEqualTo(confirmation3);
        }

        @Test
        @DisplayName("Should implement hashCode correctly for confirmation")
        void shouldImplementHashCodeCorrectlyForConfirmation() {
            WorkloadIdentityToken.Claims.Confirmation confirmation1 = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            WorkloadIdentityToken.Claims.Confirmation confirmation2 = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            assertThat(confirmation1.hashCode()).isEqualTo(confirmation2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for confirmation")
        void shouldImplementToStringForConfirmation() {
            WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            String toString = confirmation.toString();
            assertThat(toString).contains("Confirmation");
            assertThat(toString).contains("jwk");
        }
    }

    @Nested
    @DisplayName("Equals HashCode ToString Tests")
    class EqualsHashCodeToStringTests {

        @Test
        @DisplayName("Should implement equals correctly")
        void shouldImplementEqualsCorrectly() {
            WorkloadIdentityToken token1 = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadIdentityToken token2 = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadIdentityToken token3 = WorkloadIdentityToken.builder()
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
            WorkloadIdentityToken token1 = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadIdentityToken token2 = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString")
        void shouldImplementToString() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
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
            WorkloadIdentityToken token1 = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature1")
                    .build();

            WorkloadIdentityToken token2 = WorkloadIdentityToken.builder()
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
        @DisplayName("Should handle empty issuer")
        void shouldHandleEmptyIssuer() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer("")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getIssuer()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty JWT ID")
        void shouldHandleEmptyJwtId() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .jwtId("")
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getJwtId()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("")
                    .build();

            assertThat(token.getSignature()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty jwtString")
        void shouldHandleEmptyJwtString() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("")
                    .build();

            assertThat(token.getJwtString()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle SPIFFE format subject")
        void shouldHandleSpiffeFormatSubject() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/ns/default/sa/my-service")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getSubject()).isEqualTo("spiffe://example.com/ns/default/sa/my-service");
        }

        @Test
        @DisplayName("Should handle custom format subject")
        void shouldHandleCustomFormatSubject() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .subject("urn:example:workload:12345")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getSubject()).isEqualTo("urn:example:workload:12345");
        }
    }
}
