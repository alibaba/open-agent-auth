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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.page.PageRequest;
import com.alibaba.openagentauth.core.model.page.PageResponse;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.GetWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.RevokeWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.model.response.WorkloadResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WorkloadController}.
 * &lt;p&gt;
 * Tests the Workload Identity Provider REST controller's behavior including:
 * &lt;ul&gt;
 *   &lt;li&gt;Workload creation endpoint&lt;/li&gt;
 *   &lt;li&gt;WIT issuance endpoints&lt;/li&gt;
 *   &lt;li&gt;Workload revocation endpoint&lt;/li&gt;
 *   &lt;li&gt;Workload information retrieval endpoint&lt;/li&gt;
 *   &lt;li&gt;Error handling and exception scenarios&lt;/li&gt;
 * &lt;/ul&gt;
 * &lt;/p&gt;
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("WorkloadController Tests")
class WorkloadControllerTest {

    @Mock
    private AgentIdentityProvider agentIdentityProvider;

    private WorkloadController controller;

    private static final String WORKLOAD_ID = "workload-123";
    private static final String USER_ID = "user-456";
    private static final String PUBLIC_KEY = "MIIBCgKCAQEA...";
    private static final String JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.id_token";

    @BeforeEach
    void setUp() {
        controller = new WorkloadController(agentIdentityProvider, Optional.empty());
    }

    private WorkloadInfo createTestWorkloadInfo() {
        return new WorkloadInfo(
                WORKLOAD_ID,
                USER_ID,
                "wimse://example.com",
                "https://idp.example.com",
                PUBLIC_KEY,
                null,
                Instant.now(),
                Instant.now().plusSeconds(3600),
                "ACTIVE",
                null,
                null
        );
    }

    private WorkloadIdentityToken createTestWit() {
        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();
        
        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("https://idp.example.com")
                .subject(WORKLOAD_ID)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtId("jwt-123")
                .build();
        
        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("signature-123")
                .jwtString(JWT_TOKEN)
                .build();
    }

    @Nested
    @DisplayName("Issue WIT Endpoint Tests")
    class IssueWitTests {

        @Test
        @DisplayName("Should issue WIT successfully with automatic workload management")
        void shouldIssueWitSuccessfullyWithAutomaticWorkloadManagement() {
            // Given
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .instance("agent-123")
                    .platform("web")
                    .client("client-123")
                    .build();
            
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .agent(agentContext)
                    .build();
            
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();
            
            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId("client-123")
                    .build();

            WorkloadIdentityToken wit = createTestWit();
            when(agentIdentityProvider.issueWit(any(IssueWitRequest.class))).thenReturn(wit);

            // When
            ResponseEntity<IssueWitResponse> response = controller.issue(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getWit()).isEqualTo(JWT_TOKEN);
            assertThat(response.getBody().getError()).isNull();
            
            verify(agentIdentityProvider).issueWit(any(IssueWitRequest.class));
        }

        @Test
        @DisplayName("Should return INTERNAL_SERVER_ERROR when workload creation fails")
        void shouldReturnInternalServerErrorWhenWorkloadCreationFails() {
            // Given
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .instance("agent-123")
                    .platform("web")
                    .client("client-123")
                    .build();
            
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .agent(agentContext)
                    .build();
            
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();
            
            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId("client-123")
                    .build();

            when(agentIdentityProvider.issueWit(any(IssueWitRequest.class)))
                    .thenThrow(new WorkloadCreationException("Failed to create workload"));

            // When
            ResponseEntity<IssueWitResponse> response = controller.issue(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).contains("Failed to create workload");
        }

        @Test
        @DisplayName("Should return INTERNAL_SERVER_ERROR when token generation fails")
        void shouldReturnInternalServerErrorWhenTokenGenerationFails() {
            // Given
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .instance("agent-123")
                    .platform("web")
                    .client("client-123")
                    .build();
            
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .agent(agentContext)
                    .build();
            
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();
            
            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId("client-123")
                    .build();

            when(agentIdentityProvider.issueWit(any(IssueWitRequest.class)))
                    .thenThrow(new FrameworkTokenGenerationException("Token generation failed"));

            // When
            ResponseEntity<IssueWitResponse> response = controller.issue(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).contains("Token generation failed");
        }
    }

    @Nested
    @DisplayName("Revoke Workload Endpoint Tests")
    class RevokeWorkloadTests {

        @Test
        @DisplayName("Should revoke workload successfully")
        void shouldRevokeWorkloadSuccessfully() {
            // Given
            RevokeWorkloadRequest request = RevokeWorkloadRequest.builder()
                    .workloadId(WORKLOAD_ID)
                    .build();

            // When
            ResponseEntity<Void> response = controller.revoke(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            assertThat(response.getBody()).isNull();
            
            verify(agentIdentityProvider).revokeAgentWorkload(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should return NOT_FOUND when revoking non-existent workload")
        void shouldReturnNotFoundWhenRevokingNonExistentWorkload() {
            // Given
            RevokeWorkloadRequest request = RevokeWorkloadRequest.builder()
                    .workloadId(WORKLOAD_ID)
                    .build();

            doThrow(new WorkloadNotFoundException("Workload not found"))
                    .when(agentIdentityProvider).revokeAgentWorkload(WORKLOAD_ID);

            // When
            ResponseEntity<Void> response = controller.revoke(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    @Nested
    @DisplayName("Get Workload Endpoint Tests")
    class GetWorkloadTests {

        @Test
        @DisplayName("Should get workload information successfully")
        void shouldGetWorkloadInformationSuccessfully() {
            // Given
            GetWorkloadRequest request = GetWorkloadRequest.builder()
                    .workloadId(WORKLOAD_ID)
                    .build();

            WorkloadInfo workloadInfo = createTestWorkloadInfo();
            when(agentIdentityProvider.getAgentWorkload(WORKLOAD_ID)).thenReturn(workloadInfo);

            // When
            ResponseEntity<WorkloadResponse> response = controller.get(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(response.getBody().getUserId()).isEqualTo(USER_ID);
            assertThat(response.getBody().getPublicKey()).isEqualTo(PUBLIC_KEY);
            assertThat(response.getBody().getStatus()).isEqualTo("ACTIVE");
            
            verify(agentIdentityProvider).getAgentWorkload(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should return NOT_FOUND when getting non-existent workload")
        void shouldReturnNotFoundWhenGettingNonExistentWorkload() {
            // Given
            GetWorkloadRequest request = GetWorkloadRequest.builder()
                    .workloadId(WORKLOAD_ID)
                    .build();

            when(agentIdentityProvider.getAgentWorkload(WORKLOAD_ID))
                    .thenThrow(new WorkloadNotFoundException("Workload not found"));

            // When
            ResponseEntity<WorkloadResponse> response = controller.get(request);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    @Nested
    @DisplayName("List Workloads with Pagination Tests")
    class ListWorkloadsWithPaginationTests {

        @Mock
        private WorkloadRegistry workloadRegistry;

        private WorkloadController controllerWithRegistry;

        @BeforeEach
        void setUp() {
            controllerWithRegistry = new WorkloadController(agentIdentityProvider, Optional.of(workloadRegistry));
        }

        @Test
        @DisplayName("Should return paginated workloads")
        void shouldReturnPaginatedWorkloads() {
            // Given
            List<WorkloadInfo> workloads = new ArrayList<>();
            workloads.add(new WorkloadInfo(
                    "workload-1", "user-1", "wimse://example.com", "https://idp.example.com",
                    "public-key-1", null, Instant.now(), Instant.now().plusSeconds(3600),
                    "ACTIVE", null, null
            ));
            workloads.add(new WorkloadInfo(
                    "workload-2", "user-2", "wimse://example.com", "https://idp.example.com",
                    "public-key-2", null, Instant.now(), Instant.now().plusSeconds(3600),
                    "ACTIVE", null, null
            ));
            workloads.add(new WorkloadInfo(
                    "workload-3", "user-3", "wimse://example.com", "https://idp.example.com",
                    "public-key-3", null, Instant.now(), Instant.now().plusSeconds(3600),
                    "ACTIVE", null, null
            ));

            when(workloadRegistry.listAll()).thenReturn(workloads);

            PageRequest pageRequest = new PageRequest(1, 2);

            // When
            ResponseEntity<PageResponse<WorkloadResponse>> response = controllerWithRegistry.listWorkloads(pageRequest);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getItems()).hasSize(2);
            assertThat(response.getBody().getTotalItems()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should return SERVICE_UNAVAILABLE when registry is null")
        void shouldReturnServiceUnavailableWhenRegistryIsNull() {
            // Given
            WorkloadController controllerWithoutRegistry = new WorkloadController(agentIdentityProvider, Optional.empty());
            PageRequest pageRequest = new PageRequest(1, 10);

            // When
            ResponseEntity<PageResponse<WorkloadResponse>> response = controllerWithoutRegistry.listWorkloads(pageRequest);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        }

        @Test
        @DisplayName("Should return empty page when no workloads")
        void shouldReturnEmptyPageWhenNoWorkloads() {
            // Given
            when(workloadRegistry.listAll()).thenReturn(Collections.emptyList());
            PageRequest pageRequest = new PageRequest(1, 10);

            // When
            ResponseEntity<PageResponse<WorkloadResponse>> response = controllerWithRegistry.listWorkloads(pageRequest);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getItems()).isEmpty();
        }

        @Test
        @DisplayName("Should return 500 when list fails")
        void shouldReturn500WhenListFails() {
            // Given
            when(workloadRegistry.listAll()).thenThrow(new RuntimeException("error"));
            PageRequest pageRequest = new PageRequest(1, 10);

            // When
            ResponseEntity<PageResponse<WorkloadResponse>> response = controllerWithRegistry.listWorkloads(pageRequest);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}