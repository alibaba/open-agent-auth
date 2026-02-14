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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WorkloadInfo}.
 * Tests verify the workload information model following WIMSE protocol.
 */
@DisplayName("WorkloadInfo Tests - WIMSE Workload Model")
class WorkloadInfoTest {

    private static final String WORKLOAD_ID = "workload-001";
    private static final String USER_ID = "user-123";
    private static final String TRUST_DOMAIN = "example.com";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String PUBLIC_KEY = "public-key-jwk";
    private static final String PRIVATE_KEY = "private-key-jwk";
    private static final Instant CREATED_AT = Instant.now();
    private static final Instant EXPIRES_AT = Instant.now().plusSeconds(3600);
    private static final String STATUS = "active";

    private WorkloadInfo workloadInfo;
    private OperationRequestContext context;

    @BeforeEach
    void setUp() {
        context = OperationRequestContext.builder()
                .channel("web")
                .deviceFingerprint("device-001")
                .language("en-US")
                .user(OperationRequestContext.UserContext.builder().id(USER_ID).build())
                .agent(OperationRequestContext.AgentContext.builder()
                        .instance("agent-001")
                        .platform("platform-001")
                        .client("client-001")
                        .build())
                .build();

        workloadInfo = new WorkloadInfo(
                WORKLOAD_ID,
                USER_ID,
                TRUST_DOMAIN,
                ISSUER,
                PUBLIC_KEY,
                PRIVATE_KEY,
                CREATED_AT,
                EXPIRES_AT,
                STATUS,
                context,
                null // metadata
        );
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create workload with all fields")
        void shouldCreateWorkloadWithAllFields() {
            // Then
            assertThat(workloadInfo.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(workloadInfo.getUserId()).isEqualTo(USER_ID);
            assertThat(workloadInfo.getTrustDomain()).isEqualTo(TRUST_DOMAIN);
            assertThat(workloadInfo.getIssuer()).isEqualTo(ISSUER);
            assertThat(workloadInfo.getPublicKey()).isEqualTo(PUBLIC_KEY);
            assertThat(workloadInfo.getPrivateKey()).isEqualTo(PRIVATE_KEY);
            assertThat(workloadInfo.getCreatedAt()).isEqualTo(CREATED_AT);
            assertThat(workloadInfo.getExpiresAt()).isEqualTo(EXPIRES_AT);
            assertThat(workloadInfo.getStatus()).isEqualTo(STATUS);
            assertThat(workloadInfo.getContext()).isEqualTo(context);
        }

        @Test
        @DisplayName("Should create workload without private key (JSON constructor)")
        void shouldCreateWorkloadWithoutPrivateKey() {
            // When
            WorkloadInfo infoWithoutPrivateKey = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    context,
                    null // metadata
            );

            // Then
            assertThat(infoWithoutPrivateKey.getPrivateKey()).isNull();
        }

        @Test
        @DisplayName("Should create workload with null context")
        void shouldCreateWorkloadWithNullContext() {
            // When
            WorkloadInfo infoWithoutContext = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    null,
                    null // metadata
            );

            // Then
            assertThat(infoWithoutContext.getContext()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should get workload ID")
        void shouldGetWorkloadId() {
            assertThat(workloadInfo.getWorkloadId()).isEqualTo(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should get user ID")
        void shouldGetUserId() {
            assertThat(workloadInfo.getUserId()).isEqualTo(USER_ID);
        }

        @Test
        @DisplayName("Should get public key")
        void shouldGetPublicKey() {
            assertThat(workloadInfo.getPublicKey()).isEqualTo(PUBLIC_KEY);
        }

        @Test
        @DisplayName("Should get private key")
        void shouldGetPrivateKey() {
            assertThat(workloadInfo.getPrivateKey()).isEqualTo(PRIVATE_KEY);
        }

        @Test
        @DisplayName("Should get trust domain")
        void shouldGetTrustDomain() {
            assertThat(workloadInfo.getTrustDomain()).isEqualTo(TRUST_DOMAIN);
        }

        @Test
        @DisplayName("Should get issuer")
        void shouldGetIssuer() {
            assertThat(workloadInfo.getIssuer()).isEqualTo(ISSUER);
        }

        @Test
        @DisplayName("Should get created at timestamp")
        void shouldGetCreatedAt() {
            assertThat(workloadInfo.getCreatedAt()).isEqualTo(CREATED_AT);
        }

        @Test
        @DisplayName("Should get expires at timestamp")
        void shouldGetExpiresAt() {
            assertThat(workloadInfo.getExpiresAt()).isEqualTo(EXPIRES_AT);
        }

        @Test
        @DisplayName("Should get status")
        void shouldGetStatus() {
            assertThat(workloadInfo.getStatus()).isEqualTo(STATUS);
        }

        @Test
        @DisplayName("Should get context")
        void shouldGetContext() {
            assertThat(workloadInfo.getContext()).isEqualTo(context);
        }
    }

    @Nested
    @DisplayName("Status Check Tests")
    class StatusCheckTests {

        @Test
        @DisplayName("Should return true when workload is expired")
        void shouldReturnTrueWhenWorkloadIsExpired() {
            // Given
            Instant pastExpiration = Instant.now().minusSeconds(3600);
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    pastExpiration,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            boolean isExpired = expiredWorkload.isExpired();

            // Then
            assertThat(isExpired).isTrue();
        }

        @Test
        @DisplayName("Should return false when workload is not expired")
        void shouldReturnFalseWhenWorkloadIsNotExpired() {
            // When
            boolean isExpired = workloadInfo.isExpired();

            // Then
            assertThat(isExpired).isFalse();
        }

        @Test
        @DisplayName("Should return true when workload is active")
        void shouldReturnTrueWhenWorkloadIsActive() {
            // When
            boolean isActive = workloadInfo.isActive();

            // Then
            assertThat(isActive).isTrue();
        }

        @Test
        @DisplayName("Should return false when workload is inactive due to status")
        void shouldReturnFalseWhenWorkloadIsInactiveDueToStatus() {
            // Given
            WorkloadInfo inactiveWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    "inactive",
                    context,
                    null // metadata
            );

            // When
            boolean isActive = inactiveWorkload.isActive();

            // Then
            assertThat(isActive).isFalse();
        }

        @Test
        @DisplayName("Should return false when workload is inactive due to expiration")
        void shouldReturnFalseWhenWorkloadIsInactiveDueToExpiration() {
            // Given
            Instant pastExpiration = Instant.now().minusSeconds(3600);
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    pastExpiration,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            boolean isActive = expiredWorkload.isActive();

            // Then
            assertThat(isActive).isFalse();
        }

        @Test
        @DisplayName("Should return true when status is active (case insensitive)")
        void shouldReturnTrueWhenStatusIsActiveCaseInsensitive() {
            // Given
            WorkloadInfo uppercaseActiveWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    "ACTIVE",
                    context,
                    null // metadata
            );

            // When
            boolean isActive = uppercaseActiveWorkload.isActive();

            // Then
            assertThat(isActive).isTrue();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should return true when comparing same instance")
        void shouldReturnTrueWhenComparingSameInstance() {
            // When
            boolean isEqual = workloadInfo.equals(workloadInfo);

            // Then
            assertThat(isEqual).isTrue();
        }

        @Test
        @DisplayName("Should return true when comparing equal workloads")
        void shouldReturnTrueWhenComparingEqualWorkloads() {
            // Given
            WorkloadInfo anotherWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            boolean isEqual = workloadInfo.equals(anotherWorkload);

            // Then
            assertThat(isEqual).isTrue();
        }

        @Test
        @DisplayName("Should return false when comparing different workloads")
        void shouldReturnFalseWhenComparingDifferentWorkloads() {
            // Given
            WorkloadInfo differentWorkload = new WorkloadInfo(
                    "workload-002",
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            boolean isEqual = workloadInfo.equals(differentWorkload);

            // Then
            assertThat(isEqual).isFalse();
        }

        @Test
        @DisplayName("Should return false when comparing with null")
        void shouldReturnFalseWhenComparingWithNull() {
            // When
            boolean isEqual = workloadInfo.equals(null);

            // Then
            assertThat(isEqual).isFalse();
        }

        @Test
        @DisplayName("Should return false when comparing with different class")
        void shouldReturnFalseWhenComparingWithDifferentClass() {
            // When
            boolean isEqual = workloadInfo.equals(new Object());

            // Then
            assertThat(isEqual).isFalse();
        }

        @Test
        @DisplayName("Should have same hash code for equal workloads")
        void shouldHaveSameHashCodeForEqualWorkloads() {
            // Given
            WorkloadInfo anotherWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            int hashCode1 = workloadInfo.hashCode();
            int hashCode2 = anotherWorkload.hashCode();

            // Then
            assertThat(hashCode1).isEqualTo(hashCode2);
        }

        @Test
        @DisplayName("Should have different hash codes for different workloads")
        void shouldHaveDifferentHashCodesForDifferentWorkloads() {
            // Given
            WorkloadInfo differentWorkload = new WorkloadInfo(
                    "workload-002",
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    CREATED_AT,
                    EXPIRES_AT,
                    STATUS,
                    context,
                    null // metadata
            );

            // When
            int hashCode1 = workloadInfo.hashCode();
            int hashCode2 = differentWorkload.hashCode();

            // Then
            assertThat(hashCode1).isNotEqualTo(hashCode2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return string representation containing key fields")
        void shouldReturnStringRepresentationContainingKeyFields() {
            // When
            String toString = workloadInfo.toString();

            // Then
            assertThat(toString).contains(WORKLOAD_ID);
            assertThat(toString).contains(USER_ID);
            assertThat(toString).contains(STATUS);
        }

        @Test
        @DisplayName("Should not contain private key in toString")
        void shouldNotContainPrivateKeyInToString() {
            // When
            String toString = workloadInfo.toString();

            // Then
            assertThat(toString).doesNotContain(PRIVATE_KEY);
        }

        @Test
        @DisplayName("Should not contain public key in toString")
        void shouldNotContainPublicKeyInToString() {
            // When
            String toString = workloadInfo.toString();

            // Then
            assertThat(toString).doesNotContain(PUBLIC_KEY);
        }
    }
}
