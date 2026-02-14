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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitGenerator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.AgentRequestContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAgentIdentityProvider}.
 * <p>
 * This test class validates the Agent IDP orchestration implementation,
 * including workload creation, WIT issuance, and workload management.
 * </p>
 */
@DisplayName("DefaultAgentIdentityProvider Tests")
@ExtendWith(MockitoExtension.class)
class DefaultAgentIdentityProviderTest {

    private DefaultAgentIdentityProvider agentIdentityProvider;
    
    @Mock
    private TokenService mockTokenService;
    
    @Mock
    private IdTokenValidator mockIdTokenValidator;
    
    @Mock
    private WorkloadRegistry mockWorkloadRegistry;
    
    @Mock
    private WitGenerator mockWitGenerator;
    
    @Mock
    private TrustDomain mockTrustDomain;

    private static final String ISSUER = "https://agent-idp.example.com";
    private static final String AGENT_USER_IDP_ISSUER = "https://agent-user-idp.example.com";
    private static final String USER_ID = "user-123";
    private static final String TRUST_DOMAIN = "example.com";
    private static final String WORKLOAD_ID = "wimse://" + TRUST_DOMAIN + "/workload/550e8400-e29b-41d4-a716-446655440000";
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String PUBLIC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\"}";
    private static final String CLIENT_ID = "client-123";

    @BeforeEach
    void setUp() {
        agentIdentityProvider = new DefaultAgentIdentityProvider(
                mockTokenService,
                mockIdTokenValidator,
                ISSUER,
                AGENT_USER_IDP_ISSUER,
                mockWorkloadRegistry
        );
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create provider with valid parameters")
        void shouldCreateProviderWithValidParameters() {
            // Act
            DefaultAgentIdentityProvider provider = new DefaultAgentIdentityProvider(
                    mockTokenService, mockIdTokenValidator,
                    ISSUER, AGENT_USER_IDP_ISSUER, mockWorkloadRegistry);

            // Assert
            assertThat(provider).isNotNull();
            assertThat(provider.getIdTokenValidator()).isEqualTo(mockIdTokenValidator);
        }

        @Test
        @DisplayName("Should throw exception when token service is null")
        void shouldThrowExceptionWhenTokenServiceIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentIdentityProvider(
                    null, mockIdTokenValidator,
                    ISSUER, AGENT_USER_IDP_ISSUER, mockWorkloadRegistry))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token service cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when ID token validator is null")
        void shouldThrowExceptionWhenIdTokenValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentIdentityProvider(
                    mockTokenService, null,
                    ISSUER, AGENT_USER_IDP_ISSUER, mockWorkloadRegistry))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ID Token validator cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentIdentityProvider(
                    mockTokenService, mockIdTokenValidator,
                    null, AGENT_USER_IDP_ISSUER, mockWorkloadRegistry))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when agent user IDP issuer is null")
        void shouldThrowExceptionWhenAgentUserIdpIssuerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentIdentityProvider(
                    mockTokenService, mockIdTokenValidator,
                    ISSUER, null, mockWorkloadRegistry))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent User IDP issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload registry is null")
        void shouldThrowExceptionWhenWorkloadRegistryIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentIdentityProvider(
                    mockTokenService, mockIdTokenValidator,
                    ISSUER, AGENT_USER_IDP_ISSUER, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload store cannot be null");
        }
    }

    @Nested
    @DisplayName("createAgentWorkload()")
    class CreateAgentWorkload {

        @Test
        @DisplayName("Should successfully create agent workload")
        void shouldSuccessfullyCreateAgentWorkload() throws IdTokenException, WorkloadCreationException {
            // Arrange
            // Mock WitGenerator and TrustDomain for generateWorkloadId()
            when(mockTokenService.getWitGenerator()).thenReturn(mockWitGenerator);
            when(mockWitGenerator.getTrustDomain()).thenReturn(mockTrustDomain);
            when(mockTrustDomain.getDomainName()).thenReturn(TRUST_DOMAIN);
            
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .resourceId("resource-123")
                    .prompt("test prompt")
                    .publicKey(PUBLIC_KEY)
                    .clientId(CLIENT_ID)
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);

            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenReturn(idToken);
            
            // Capture the saved workload to verify its properties
            final WorkloadInfo[] capturedWorkload = new WorkloadInfo[1];
            doAnswer(invocation -> {
                capturedWorkload[0] = invocation.getArgument(0);
                return capturedWorkload[0];
            }).when(mockWorkloadRegistry).save(any(WorkloadInfo.class));

            // Act
            WorkloadInfo result = agentIdentityProvider.createAgentWorkload(ID_TOKEN, context);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUserId()).isEqualTo(USER_ID);
            assertThat(result.getPublicKey()).isEqualTo(PUBLIC_KEY);
            assertThat(result.getPrivateKey()).isNull(); // Private key should not be stored
            assertThat(result.getStatus()).isEqualTo("active");
            assertThat(result.getWorkloadId()).startsWith("wimse://" + TRUST_DOMAIN + "/workload/");

            verify(mockIdTokenValidator, times(1)).validate(ID_TOKEN, AGENT_USER_IDP_ISSUER, CLIENT_ID);
            verify(mockWorkloadRegistry, times(1)).save(any(WorkloadInfo.class));
        }

        @Test
        @DisplayName("Should throw exception when ID token is null")
        void shouldThrowExceptionWhenIdTokenIsNull() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .publicKey(PUBLIC_KEY)
                    .clientId(CLIENT_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.createAgentWorkload(null, context))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ID Token cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when ID token is empty")
        void shouldThrowExceptionWhenIdTokenIsEmpty() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .publicKey(PUBLIC_KEY)
                    .clientId(CLIENT_ID)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.createAgentWorkload("   ", context))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ID Token cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.createAgentWorkload(ID_TOKEN, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request context cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when public key is null")
        void shouldThrowExceptionWhenPublicKeyIsNull() throws IdTokenException {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .clientId(CLIENT_ID)
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now())
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);

            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenReturn(idToken);

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.createAgentWorkload(ID_TOKEN, context))
                    .isInstanceOf(WorkloadCreationException.class)
                    .hasMessageContaining("Failed to create workload");
        }

        @Test
        @DisplayName("Should throw exception when ID token validation fails")
        void shouldThrowExceptionWhenIdTokenValidationFails() throws IdTokenException {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .publicKey(PUBLIC_KEY)
                    .clientId(CLIENT_ID)
                    .build();

            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenThrow(new IdTokenException("Invalid ID Token"));

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.createAgentWorkload(ID_TOKEN, context))
                    .isInstanceOf(WorkloadCreationException.class)
                    .hasMessageContaining("Failed to create workload");
        }
    }

    @Nested
    @DisplayName("issueWit(String)")
    class IssueWitByString {

        @Test
        @DisplayName("Should successfully issue WIT")
        void shouldSuccessfullyIssueWit() throws JOSEException, WorkloadNotFoundException, FrameworkTokenGenerationException {
            // Arrange
            WorkloadInfo workload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    null, // Private key is not stored
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    null,
                    null // metadata
            );

            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            AgentIdentity agentIdentity = AgentIdentity.builder()
                    .id(WORKLOAD_ID)
                    .issuedTo(USER_ID)
                    .issuer(ISSUER)
                    .issuanceDate(Instant.now())
                    .validFrom(Instant.now())
                    .expires(Instant.now().plusSeconds(3600))
                    .build();

            when(mockWorkloadRegistry.findById(WORKLOAD_ID))
                    .thenReturn(Optional.of(workload));
            when(mockTokenService.generateWit(anyString(), anyString(), anyLong()))
                    .thenReturn(wit);

            // Act
            WorkloadIdentityToken result = agentIdentityProvider.issueWit(WORKLOAD_ID);

            // Assert
            assertThat(result).isNotNull();

            verify(mockWorkloadRegistry, times(1)).findById(WORKLOAD_ID);
            verify(mockTokenService, times(1)).generateWit(anyString(), eq(PUBLIC_KEY), eq(3600L));
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit((String)null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload not found")
        void shouldThrowExceptionWhenWorkloadNotFound() {
            // Arrange
            when(mockWorkloadRegistry.findById(WORKLOAD_ID))
                    .thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(WORKLOAD_ID))
                    .isInstanceOf(WorkloadNotFoundException.class)
                    .hasMessageContaining("Agent workload not found");
        }
    }

    @Nested
    @DisplayName("issueWit(IssueWitRequest)")
    class IssueWitByRequest {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit((IssueWitRequest)null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("IssueWitRequest cannot be null");
        }

        @Test
        @DisplayName("Should successfully issue WIT with new workload")
        void shouldSuccessfullyIssueWitWithNewWorkload() throws Exception {
            // Arrange
            // Mock WitGenerator and TrustDomain
            when(mockTokenService.getWitGenerator()).thenReturn(mockWitGenerator);
            when(mockWitGenerator.getTrustDomain()).thenReturn(mockTrustDomain);
            when(mockTrustDomain.getDomainName()).thenReturn(TRUST_DOMAIN);

            // Create IssueWitRequest
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .platform("linux")
                    .client("test-client")
                    .instance("instance-123")
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(agentContext)
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .publicKey(PUBLIC_KEY)
                    .oauthClientId(CLIENT_ID)
                    .build();

            // Mock ID Token validation
            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);
            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenReturn(idToken);

            // Mock workload registry - no existing workload
            when(mockWorkloadRegistry.findByWorkloadUniqueKey(anyString()))
                    .thenReturn(Optional.empty());

            // Mock WIT generation
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(mockTokenService.generateWit(anyString(), eq(PUBLIC_KEY), eq(3600L)))
                    .thenReturn(wit);

            // Act
            WorkloadIdentityToken result = agentIdentityProvider.issueWit(request);

            // Assert
            assertThat(result).isNotNull();
            verify(mockWorkloadRegistry, times(1)).save(any(WorkloadInfo.class));
            verify(mockTokenService, times(1)).generateWit(anyString(), eq(PUBLIC_KEY), eq(3600L));
        }

        @Test
        @DisplayName("Should reuse existing active workload")
        void shouldReuseExistingActiveWorkload() throws Exception {
            // Arrange
            // Create IssueWitRequest
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .platform("linux")
                    .client("test-client")
                    .instance("instance-123")
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(agentContext)
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .publicKey(PUBLIC_KEY)
                    .oauthClientId(CLIENT_ID)
                    .build();

            // Mock ID Token validation
            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);
            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenReturn(idToken);

            // Mock existing active workload
            WorkloadInfo existingWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    null,
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    context,
                    null
            );
            when(mockWorkloadRegistry.findByWorkloadUniqueKey(anyString()))
                    .thenReturn(Optional.of(existingWorkload));

            // Mock WIT generation
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(mockTokenService.generateWit(eq(WORKLOAD_ID), eq(PUBLIC_KEY), eq(3600L)))
                    .thenReturn(wit);

            // Act
            WorkloadIdentityToken result = agentIdentityProvider.issueWit(request);

            // Assert
            assertThat(result).isNotNull();
            verify(mockWorkloadRegistry, times(0)).save(any(WorkloadInfo.class)); // Should not create new workload
            verify(mockTokenService, times(1)).generateWit(eq(WORKLOAD_ID), eq(PUBLIC_KEY), eq(3600L));
        }

        @Test
        @DisplayName("Should delete and recreate expired workload")
        void shouldDeleteAndRecreateExpiredWorkload() throws Exception {
            // Arrange
            // Mock WitGenerator and TrustDomain
            when(mockTokenService.getWitGenerator()).thenReturn(mockWitGenerator);
            when(mockWitGenerator.getTrustDomain()).thenReturn(mockTrustDomain);
            when(mockTrustDomain.getDomainName()).thenReturn(TRUST_DOMAIN);

            // Create IssueWitRequest
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .platform("linux")
                    .client("test-client")
                    .instance("instance-123")
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(agentContext)
                    .build();

            AgentUserBindingProposal proposal =
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build();

            IssueWitRequest request = IssueWitRequest.builder()
                    .context(context)
                    .proposal(proposal)
                    .publicKey(PUBLIC_KEY)
                    .oauthClientId(CLIENT_ID)
                    .build();

            // Mock ID Token validation
            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(AGENT_USER_IDP_ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);
            when(mockIdTokenValidator.validate(eq(ID_TOKEN), eq(AGENT_USER_IDP_ISSUER), eq(CLIENT_ID)))
                    .thenReturn(idToken);

            // Mock existing expired workload
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    null,
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600), // Expired
                    "active",
                    context,
                    null
            );
            when(mockWorkloadRegistry.findByWorkloadUniqueKey(anyString()))
                    .thenReturn(Optional.of(expiredWorkload));

            // Mock WIT generation
            WorkloadIdentityToken wit = mock(WorkloadIdentityToken.class);
            when(mockTokenService.generateWit(anyString(), eq(PUBLIC_KEY), eq(3600L)))
                    .thenReturn(wit);

            // Act
            WorkloadIdentityToken result = agentIdentityProvider.issueWit(request);

            // Assert
            assertThat(result).isNotNull();
            verify(mockWorkloadRegistry, times(1)).delete(WORKLOAD_ID); // Should delete expired workload
            verify(mockWorkloadRegistry, times(1)).save(any(WorkloadInfo.class)); // Should create new workload
            verify(mockTokenService, times(1)).generateWit(anyString(), eq(PUBLIC_KEY), eq(3600L));
        }

        @Test
        @DisplayName("Should throw exception when proposal is null")
        void shouldThrowExceptionWhenProposalIsNull() {
            // Arrange
            IssueWitRequest request = mock(IssueWitRequest.class);
            when(request.getContext()).thenReturn(
                OperationRequestContext.builder()
                    .agent(OperationRequestContext.AgentContext.builder()
                            .client(CLIENT_ID)
                            .build())
                    .build()
            );
            when(request.getProposal()).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent user binding proposal cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            // Arrange
            IssueWitRequest request = mock(IssueWitRequest.class);
            when(request.getContext()).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Operation request context cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when agent context is null")
        void shouldThrowExceptionWhenAgentContextIsNull() {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(null)
                    .build();

            IssueWitRequest request = mock(IssueWitRequest.class);
            when(request.getContext()).thenReturn(context);
            when(request.getProposal()).thenReturn(
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build()
            );

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent context cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Arrange
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .client(null)
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(agentContext)
                    .build();

            IssueWitRequest request = mock(IssueWitRequest.class);
            when(request.getContext()).thenReturn(context);
            when(request.getProposal()).thenReturn(
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build()
            );

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when public key is null")
        void shouldThrowExceptionWhenPublicKeyIsNull() {
            // Arrange
            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .client(CLIENT_ID)
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .agent(agentContext)
                    .build();

            IssueWitRequest request = mock(IssueWitRequest.class);
            when(request.getContext()).thenReturn(context);
            when(request.getProposal()).thenReturn(
                AgentUserBindingProposal.builder()
                    .userIdentityToken(ID_TOKEN)
                    .build()
            );
            when(request.getPublicKey()).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.issueWit(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Public key cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("revokeAgentWorkload()")
    class RevokeAgentWorkload {

        @Test
        @DisplayName("Should successfully revoke agent workload")
        void shouldSuccessfullyRevokeAgentWorkload() throws WorkloadNotFoundException {
            // Arrange
            when(mockWorkloadRegistry.exists(WORKLOAD_ID)).thenReturn(true);

            // Act
            agentIdentityProvider.revokeAgentWorkload(WORKLOAD_ID);

            // Assert
            verify(mockWorkloadRegistry, times(1)).delete(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.revokeAgentWorkload(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload not found")
        void shouldThrowExceptionWhenWorkloadNotFound() {
            // Arrange
            when(mockWorkloadRegistry.exists(WORKLOAD_ID)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.revokeAgentWorkload(WORKLOAD_ID))
                    .isInstanceOf(WorkloadNotFoundException.class)
                    .hasMessageContaining("Agent workload not found");
        }
    }

    @Nested
    @DisplayName("getAgentWorkload()")
    class GetAgentWorkload {

        @Test
        @DisplayName("Should successfully get agent workload")
        void shouldSuccessfullyGetAgentWorkload() throws WorkloadNotFoundException {
            // Arrange
            WorkloadInfo workload = new WorkloadInfo(
                    WORKLOAD_ID,
                    USER_ID,
                    TRUST_DOMAIN,
                    ISSUER,
                    PUBLIC_KEY,
                    null, // Private key is not stored
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    null,
                    null // metadata
            );

            when(mockWorkloadRegistry.findById(WORKLOAD_ID))
                    .thenReturn(Optional.of(workload));

            // Act
            WorkloadInfo result = agentIdentityProvider.getAgentWorkload(WORKLOAD_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(result.getUserId()).isEqualTo(USER_ID);

            verify(mockWorkloadRegistry, times(1)).findById(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.getAgentWorkload(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload not found")
        void shouldThrowExceptionWhenWorkloadNotFound() {
            // Arrange
            when(mockWorkloadRegistry.findById(WORKLOAD_ID))
                    .thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> agentIdentityProvider.getAgentWorkload(WORKLOAD_ID))
                    .isInstanceOf(WorkloadNotFoundException.class)
                    .hasMessageContaining("Agent workload not found");
        }
    }
}