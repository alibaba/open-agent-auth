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
package com.alibaba.openagentauth.core.model.oauth2.par;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ParJwtClaims.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * ParJwtClaims, including normal construction, method chaining,
 * optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("ParJwtClaims.Builder Tests")
class ParJwtClaimsTest {

    private static final String ISSUER = "https://client.myassistant.example";
    private static final String SUBJECT = "user_12345@myassistant.example";
    private static final String AUDIENCE = "https://as.online-shop.example";
    private static final String JWT_ID = "urn:uuid:123e4567-e89b-12d3-a456-426614174000";
    private static final String STATE = "xyz789";
    private static final String OPERATION_PROPOSAL = "package agent\nallow { input.transaction.amount <= 50.0 }";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build claims with all required fields")
        void shouldBuildClaimsWithAllRequiredFields() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .evidence(evidence)
                    .agentUserBindingProposal(bindingProposal)
                    .operationProposal(OPERATION_PROPOSAL)
                    .context(context)
                    .state(STATE)
                    .build();

            // Then
            assertThat(claims).isNotNull();
            assertThat(claims.getIssuer()).isEqualTo(ISSUER);
            assertThat(claims.getSubject()).isEqualTo(SUBJECT);
            assertThat(claims.getAudience()).isEqualTo(audience);
            assertThat(claims.getIssueTime()).isEqualTo(issueTime);
            assertThat(claims.getExpirationTime()).isEqualTo(expirationTime);
            assertThat(claims.getJwtId()).isEqualTo(JWT_ID);
            assertThat(claims.getEvidence()).isEqualTo(evidence);
            assertThat(claims.getAgentUserBindingProposal()).isEqualTo(bindingProposal);
            assertThat(claims.getOperationProposal()).isEqualTo(OPERATION_PROPOSAL);
            assertThat(claims.getContext()).isEqualTo(context);
            assertThat(claims.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            // Then
            assertThat(claims).isNotNull();
            assertThat(claims.getIssuer()).isEqualTo(ISSUER);
            assertThat(claims.getSubject()).isEqualTo(SUBJECT);
            assertThat(claims.getEvidence()).isNull();
            assertThat(claims.getAgentUserBindingProposal()).isNull();
            assertThat(claims.getOperationProposal()).isNull();
            assertThat(claims.getContext()).isNull();
            assertThat(claims.getState()).isNull();
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .evidence(evidence)
                    .agentUserBindingProposal(bindingProposal)
                    .operationProposal(OPERATION_PROPOSAL)
                    .context(context)
                    .state(STATE)
                    .build();

            // Then
            assertThat(claims).isNotNull();
            assertThat(claims.getIssuer()).isEqualTo(ISSUER);
            assertThat(claims.getSubject()).isEqualTo(SUBJECT);
            assertThat(claims.getAudience()).isEqualTo(audience);
            assertThat(claims.getIssueTime()).isEqualTo(issueTime);
            assertThat(claims.getExpirationTime()).isEqualTo(expirationTime);
            assertThat(claims.getJwtId()).isEqualTo(JWT_ID);
            assertThat(claims.getEvidence()).isEqualTo(evidence);
            assertThat(claims.getOperationProposal()).isEqualTo(OPERATION_PROPOSAL);
            assertThat(claims.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            // Then
            assertThat(claims).isNotNull();
            assertThat(claims.getEvidence()).isNull();
            assertThat(claims.getAgentUserBindingProposal()).isNull();
            assertThat(claims.getOperationProposal()).isNull();
            assertThat(claims.getContext()).isNull();
            assertThat(claims.getState()).isNull();
        }

        @Test
        @DisplayName("Should set optional state field")
        void shouldSetOptionalStateField() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .state(STATE)
                    .build();

            // Then
            assertThat(claims.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should set optional evidence field")
        void shouldSetOptionalEvidenceField() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .evidence(evidence)
                    .build();

            // Then
            assertThat(claims.getEvidence()).isEqualTo(evidence);
        }

        @Test
        @DisplayName("Should set optional operationProposal field")
        void shouldSetOptionalOperationProposalField() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .operationProposal(OPERATION_PROPOSAL)
                    .build();

            // Then
            assertThat(claims.getOperationProposal()).isEqualTo(OPERATION_PROPOSAL);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            // When
            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            // Then
            assertThat(claims).isInstanceOf(ParJwtClaims.class);
            assertThat(claims.getIssuer()).isEqualTo(ISSUER);
            assertThat(claims.getSubject()).isEqualTo(SUBJECT);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            ParJwtClaims.Builder builder = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID);

            // When
            ParJwtClaims claims1 = builder.build();
            builder.subject("different_subject");
            ParJwtClaims claims2 = builder.build();

            // Then
            assertThat(claims1.getSubject()).isEqualTo(SUBJECT);
            assertThat(claims2.getSubject()).isEqualTo("different_subject");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            ParJwtClaims claims1 = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            ParJwtClaims claims2 = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            // Then
            assertThat(claims1).isEqualTo(claims2);
            assertThat(claims1.hashCode()).isEqualTo(claims2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when fields differ")
        void shouldNotBeEqualWhenFieldsDiffer() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            ParJwtClaims claims1 = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            ParJwtClaims claims2 = ParJwtClaims.builder()
                    .issuer("different_issuer")
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .build();

            // Then
            assertThat(claims1).isNotEqualTo(claims2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            Date issueTime = new Date();
            Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
            List<String> audience = List.of(AUDIENCE);

            ParJwtClaims claims = ParJwtClaims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .audience(audience)
                    .issueTime(issueTime)
                    .expirationTime(expirationTime)
                    .jwtId(JWT_ID)
                    .state(STATE)
                    .build();

            // When
            String toString = claims.toString();

            // Then
            assertThat(toString).contains(ISSUER);
            assertThat(toString).contains(SUBJECT);
            assertThat(toString).contains(JWT_ID);
            assertThat(toString).contains(STATE);
        }
    }
}
