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
package com.alibaba.openagentauth.core.protocol.wimse.workload.client;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RestWorkloadClient}.
 * <p>
 * This test class validates the HTTP client implementation for Agent Identity Provider
 * services, including workload creation, WIT issuance, and workload revocation.
 * </p>
 */
@DisplayName("RestWorkloadClient Tests")
class RestWorkloadClientTest {

    private RestWorkloadClient client;
    private static final String BASE_URL = "https://agent-idp.example.com";
    private static final String WORKLOAD_ID = "workload-123";
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String PUBLIC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\"}";
    private static final String OAUTH_CLIENT_ID = "client-123";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    @BeforeEach
    void setUp() {
        mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
        when(mockServiceEndpointResolver.resolveConsumer("agent-idp", "workload.issue"))
                .thenReturn(BASE_URL + "/api/v1/workloads/issue");
        when(mockServiceEndpointResolver.resolveConsumer("agent-idp", "workload.revoke"))
                .thenReturn(BASE_URL + "/api/v1/workloads/revoke");
        client = new RestWorkloadClient(mockServiceEndpointResolver);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create client with service endpoint resolver")
        void shouldCreateClientWithServiceEndpointResolver() {
            // Act
            RestWorkloadClient newClient = new RestWorkloadClient(mockServiceEndpointResolver);

            // Assert
            assertThat(newClient).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new RestWorkloadClient((ServiceEndpointResolver) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }
    }

    @Nested
    @DisplayName("issueWit()")
    class IssueWit {

        @Test
        @DisplayName("Should throw WorkloadCreationException on connection failure")
        void shouldThrowWorkloadCreationExceptionOnConnectionFailure() {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .language("en")
                    .build();

            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .oauthClientId(OAUTH_CLIENT_ID)
                    .build();

            // Act & Assert - Using invalid URL to simulate connection failure
            assertThatThrownBy(() -> client.issueWit(request))
                    .isInstanceOf(WorkloadCreationException.class)
                    .hasMessageContaining("Failed to issue WIT");
        }
    }



    @Nested
    @DisplayName("revokeWorkload()")
    class RevokeWorkload {

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.revokeWorkload(null))
                    .isInstanceOf(WorkloadNotFoundException.class)
                    .hasMessageContaining("Failed to revoke workload");
        }

        @Test
        @DisplayName("Should throw WorkloadNotFoundException on connection failure")
        void shouldThrowWorkloadNotFoundExceptionOnConnectionFailure() {
            // Act & Assert - Using invalid URL to simulate connection failure
            assertThatThrownBy(() -> client.revokeWorkload(WORKLOAD_ID))
                    .isInstanceOf(WorkloadNotFoundException.class)
                    .hasMessageContaining("Failed to revoke workload");
        }
    }
}
