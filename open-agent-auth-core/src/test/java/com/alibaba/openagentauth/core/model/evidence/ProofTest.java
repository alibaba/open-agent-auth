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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link Proof}.
 * <p>
 * This test class validates the behavior of the Proof class,
 * which represents cryptographic proof for Verifiable Credentials.
 * </p>
 */
@DisplayName("Proof Tests")
class ProofTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build proof with default type")
        void shouldBuildProofWithDefaultType() {
            // Given
            String created = "2024-01-01T00:00:00Z";
            String verificationMethod = "did:example:123#key-1";

            // When
            Proof proof = Proof.builder()
                    .created(created)
                    .verificationMethod(verificationMethod)
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals("JwtProof2020", proof.getType());
            assertEquals(created, proof.getCreated());
            assertEquals(verificationMethod, proof.getVerificationMethod());
        }

        @Test
        @DisplayName("Should build proof with custom type")
        void shouldBuildProofWithCustomType() {
            // Given
            String type = "RsaSignature2018";
            String created = "2024-01-01T00:00:00Z";
            String verificationMethod = "did:example:456#key-2";

            // When
            Proof proof = Proof.builder()
                    .type(type)
                    .created(created)
                    .verificationMethod(verificationMethod)
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals(type, proof.getType());
            assertEquals(created, proof.getCreated());
            assertEquals(verificationMethod, proof.getVerificationMethod());
        }

        @Test
        @DisplayName("Should build proof with Instant created")
        void shouldBuildProofWithInstantCreated() {
            // Given
            Instant created = Instant.parse("2024-01-01T00:00:00Z");
            String verificationMethod = "did:example:789#key-3";

            // When
            Proof proof = Proof.builder()
                    .created(created)
                    .verificationMethod(verificationMethod)
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals(created.toString(), proof.getCreated());
            assertEquals(verificationMethod, proof.getVerificationMethod());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            // Given
            String type = "EcdsaSecp256k1Signature2019";

            // When
            Proof proof = Proof.builder()
                    .type(type)
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:000#key-0")
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals(type, proof.getType());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return type")
        void shouldReturnType() {
            // Given
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            String type = proof.getType();

            // Then
            assertEquals("JwtProof2020", type);
        }

        @Test
        @DisplayName("Should return created")
        void shouldReturnCreated() {
            // Given
            String created = "2024-01-01T12:30:45Z";
            Proof proof = Proof.builder()
                    .created(created)
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            String result = proof.getCreated();

            // Then
            assertEquals(created, result);
        }

        @Test
        @DisplayName("Should return verification method")
        void shouldReturnVerificationMethod() {
            // Given
            String verificationMethod = "did:example:abc#key-xyz";
            Proof proof = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod(verificationMethod)
                    .build();

            // When
            String result = proof.getVerificationMethod();

            // Then
            assertEquals(verificationMethod, result);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            Proof proof1 = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            Proof proof2 = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertEquals(proof1, proof2);
            assertEquals(proof1.hashCode(), proof2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when types differ")
        void shouldNotBeEqualWhenTypesDiffer() {
            // Given
            Proof proof1 = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            Proof proof2 = Proof.builder()
                    .type("RsaSignature2018")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertNotEquals(proof1, proof2);
        }

        @Test
        @DisplayName("Should not be equal when created timestamps differ")
        void shouldNotBeEqualWhenCreatedTimestampsDiffer() {
            // Given
            Proof proof1 = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            Proof proof2 = Proof.builder()
                    .created("2024-01-02T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertNotEquals(proof1, proof2);
        }

        @Test
        @DisplayName("Should not be equal when verification methods differ")
        void shouldNotBeEqualWhenVerificationMethodsDiffer() {
            // Given
            Proof proof1 = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            Proof proof2 = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:456#key-2")
                    .build();

            // Then
            assertNotEquals(proof1, proof2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            Proof proof = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertEquals(proof, proof);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            Proof proof = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertNotEquals(proof, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            Proof proof = Proof.builder()
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // Then
            assertNotEquals(proof, "string");
        }

        @Test
        @DisplayName("Should have consistent hash code")
        void shouldHaveConsistentHashCode() {
            // Given
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            int hashCode1 = proof.hashCode();
            int hashCode2 = proof.hashCode();

            // Then
            assertEquals(hashCode1, hashCode2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            Proof proof = Proof.builder()
                    .type("JwtProof2020")
                    .created("2024-01-01T00:00:00Z")
                    .verificationMethod("did:example:123#key-1")
                    .build();

            // When
            String result = proof.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("Proof"));
            assertTrue(result.contains("JwtProof2020"));
            assertTrue(result.contains("2024-01-01T00:00:00Z"));
            assertTrue(result.contains("did:example:123#key-1"));
        }
    }

    @Nested
    @DisplayName("Builder Null Values Tests")
    class BuilderNullValuesTests {

        @Test
        @DisplayName("Should build proof with null type")
        void shouldBuildProofWithNullType() {
            // Given
            String created = "2024-01-01T00:00:00Z";
            String verificationMethod = "did:example:123#key-1";

            // When
            Proof proof = Proof.builder()
                    .type(null)
                    .created(created)
                    .verificationMethod(verificationMethod)
                    .build();

            // Then
            assertNotNull(proof);
            assertNull(proof.getType());
            assertEquals(created, proof.getCreated());
            assertEquals(verificationMethod, proof.getVerificationMethod());
        }

        @Test
        @DisplayName("Should build proof with null created")
        void shouldBuildProofWithNullCreated() {
            // Given
            String verificationMethod = "did:example:123#key-1";

            // When - Use explicit type cast to resolve ambiguity
            Proof proof = Proof.builder()
                    .created((String) null)
                    .verificationMethod(verificationMethod)
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals("JwtProof2020", proof.getType());
            assertNull(proof.getCreated());
            assertEquals(verificationMethod, proof.getVerificationMethod());
        }

        @Test
        @DisplayName("Should build proof with null verification method")
        void shouldBuildProofWithNullVerificationMethod() {
            // Given
            String created = "2024-01-01T00:00:00Z";

            // When
            Proof proof = Proof.builder()
                    .created(created)
                    .verificationMethod(null)
                    .build();

            // Then
            assertNotNull(proof);
            assertEquals("JwtProof2020", proof.getType());
            assertEquals(created, proof.getCreated());
            assertNull(proof.getVerificationMethod());
        }
    }
}
