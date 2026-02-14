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
package com.alibaba.openagentauth.core.model.evidence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link VerifiableCredential.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * VerifiableCredential, including normal construction, method chaining,
 * optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("VerifiableCredential.Builder Tests")
class VerifiableCredentialTest {

    private static final String JTI = "urn:uuid:123e4567-e89b-12d3-a456-426614174000";
    private static final String ISS = "https://issuer.example";
    private static final String SUB = "user_12345";
    private static final Long IAT = 1704067200L;
    private static final Long EXP = 1704153600L;
    private static final String TYPE = "VerifiableCredential";
    private static final String ISSUER = "https://issuer.example";
    private static final String ISSUANCE_DATE = "2024-01-01T00:00:00Z";
    private static final String EXPIRATION_DATE = "2024-12-31T23:59:59Z";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build credential with all required fields")
        void shouldBuildCredentialWithAllRequiredFields() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getIss()).isEqualTo(ISS);
            assertThat(credential.getSub()).isEqualTo(SUB);
            assertThat(credential.getIat()).isEqualTo(IAT);
            assertThat(credential.getExp()).isEqualTo(EXP);
            assertThat(credential.getType()).isEqualTo(TYPE);
        }

        @Test
        @DisplayName("Should build credential with all fields including optional")
        void shouldBuildCredentialWithAllFieldsIncludingOptional() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .jti(JTI)
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getJti()).isEqualTo(JTI);
            assertThat(credential.getIss()).isEqualTo(ISS);
            assertThat(credential.getSub()).isEqualTo(SUB);
        }

        @Test
        @DisplayName("Should build credential with Instant for iat and exp")
        void shouldBuildCredentialWithInstantForIatAndExp() {
            // Given
            Instant iatInstant = Instant.ofEpochSecond(IAT);
            Instant expInstant = Instant.ofEpochSecond(EXP);
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(iatInstant)
                    .exp(expInstant)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getIat()).isEqualTo(IAT);
            assertThat(credential.getExp()).isEqualTo(EXP);
        }

        @Test
        @DisplayName("Should build credential with Instant for issuanceDate and expirationDate")
        void shouldBuildCredentialWithInstantForIssuanceDateAndExpirationDate() {
            // Given
            Instant issuanceInstant = Instant.parse(ISSUANCE_DATE);
            Instant expirationInstant = Instant.parse(EXPIRATION_DATE);
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(issuanceInstant)
                    .expirationDate(expirationInstant)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getIssuanceDate()).isEqualTo(ISSUANCE_DATE);
            assertThat(credential.getExpirationDate()).isEqualTo(EXPIRATION_DATE);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .jti(JTI)
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getJti()).isEqualTo(JTI);
            assertThat(credential.getIss()).isEqualTo(ISS);
            assertThat(credential.getSub()).isEqualTo(SUB);
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional jti field")
        void shouldAllowNullOptionalJtiField() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getJti()).isNull();
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            VerifiableCredential credential = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential).isInstanceOf(VerifiableCredential.class);
            assertThat(credential.getIss()).isEqualTo(ISS);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            VerifiableCredential.Builder builder = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof);

            // When
            VerifiableCredential credential1 = builder.build();
            builder.sub("different_subject");
            VerifiableCredential credential2 = builder.build();

            // Then
            assertThat(credential1.getSub()).isEqualTo(SUB);
            assertThat(credential2.getSub()).isEqualTo("different_subject");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            VerifiableCredential credential1 = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            VerifiableCredential credential2 = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential1).isEqualTo(credential2);
            assertThat(credential1.hashCode()).isEqualTo(credential2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when subjects differ")
        void shouldNotBeEqualWhenSubjectsDiffer() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            VerifiableCredential credential1 = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            VerifiableCredential credential2 = VerifiableCredential.builder()
                    .iss(ISS)
                    .sub("different_subject")
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // Then
            assertThat(credential1).isNotEqualTo(credential2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp("2024-01-01T00:00:00Z")
                    .build();
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            VerifiableCredential credential = VerifiableCredential.builder()
                    .jti(JTI)
                    .iss(ISS)
                    .sub(SUB)
                    .iat(IAT)
                    .exp(EXP)
                    .type(TYPE)
                    .credentialSubject(credentialSubject)
                    .issuer(ISSUER)
                    .issuanceDate(ISSUANCE_DATE)
                    .expirationDate(EXPIRATION_DATE)
                    .proof(proof)
                    .build();

            // When
            String toString = credential.toString();

            // Then
            assertThat(toString).contains("VerifiableCredential");
            assertThat(toString).contains(JTI);
            assertThat(toString).contains(ISS);
            assertThat(toString).contains(SUB);
            assertThat(toString).contains(TYPE);
        }
    }
}
