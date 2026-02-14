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
package com.alibaba.openagentauth.framework.executor.impl;

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.vc.VcSigner;
import com.alibaba.openagentauth.core.protocol.vc.chain.PromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionResult;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.alibaba.openagentauth.framework.executor.strategy.DeviceFingerprintStrategy;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.alibaba.openagentauth.framework.executor.strategy.StateGenerationStrategy;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.ParSubmissionRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.response.RequestAuthUrlResponse;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken.Header;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAgentAapExecutor}.
 * <p>
 * This test class validates the Agent AAP Executor implementation,
 * including authorization URL requests, workload context creation,
 * evidence building, and exception handling.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DefaultAgentAapExecutor Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultAgentAapExecutorTest {

    private DefaultAgentAapExecutor executor;
    
    @Mock
    private Agent mockAgent;
    
    @Mock
    private VcSigner mockVcSigner;
    
    @Mock
    private PolicyBuilder mockPolicyBuilder;
    
    @Mock
    private AgentAapExecutorConfig mockConfig;
    
    @Mock
    private StateGenerationStrategy mockStateGenerationStrategy;
    
    @Mock
    private DeviceFingerprintStrategy mockDeviceFingerprintStrategy;
    
    @Mock
    private PromptProtectionChain mockPromptProtectionChain;
    
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String STATE = "test-state-123";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:test";
    private static final String AUTH_URL = "http://auth-server/auth?request_uri=" + REQUEST_URI;
    private static final String USER_IDENTITY_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String USER_ORIGINAL_INPUT = "I want to buy winter clothes";
    private static final String SESSION_ID = "session-123";
    private static final String WORKLOAD_ID = "workload-123";
    private static final String USER_ID = "user-123";
    private static final String OPERATION_TYPE = "query";
    private static final String RESOURCE_ID = "product-catalog";
    private static final String POLICY = "allow: read product-catalog";

    @BeforeEach
    void setUp() {
        // Setup config behavior
        when(mockConfig.getClientId()).thenReturn(CLIENT_ID);
        when(mockConfig.getRedirectUri()).thenReturn(REDIRECT_URI);
        when(mockConfig.getChannel()).thenReturn("web");
        when(mockConfig.getLanguage()).thenReturn("zh-CN");
        when(mockConfig.getPlatform()).thenReturn("test-platform");
        when(mockConfig.getAgentClient()).thenReturn("test-agent-client");
        when(mockConfig.getExpirationSeconds()).thenReturn(3600);
        when(mockConfig.getIssuer()).thenReturn("test-issuer");
        when(mockConfig.getPromptProtectionEnabled()).thenReturn(false);
        when(mockConfig.getSanitizationLevel()).thenReturn("MEDIUM");
        when(mockConfig.getRequireUserInteraction()).thenReturn(false);
        when(mockConfig.getEncryptionEnabled()).thenReturn(false);
        
        // Setup strategy mocks using separate mock objects
        when(mockConfig.getStateGenerationStrategy()).thenReturn(mockStateGenerationStrategy);
        when(mockConfig.getDeviceFingerprintStrategy()).thenReturn(mockDeviceFingerprintStrategy);
        when(mockStateGenerationStrategy.generate(anyString())).thenReturn(STATE);
        when(mockDeviceFingerprintStrategy.generate(anyString())).thenReturn("device-fingerprint-123");
        
        // Setup policy builder
        when(mockPolicyBuilder.buildPolicy(any(RequestAuthUrlRequest.class))).thenReturn(POLICY);
        
        // Setup agent behavior
        when(mockAgent.issueWorkloadIdentityToken(any(IssueWitRequest.class)))
                .thenReturn(createMockWorkloadContext());
        when(mockAgent.registerOAuthClient(any(WorkloadContext.class)))
                .thenReturn(createMockDcrResponse());
        when(mockAgent.submitParRequest(any(ParSubmissionRequest.class)))
                .thenReturn(createMockParResponse());
        when(mockAgent.generateAuthorizationUrl(anyString(), anyString()))
                .thenReturn(AUTH_URL);
        
        executor = new DefaultAgentAapExecutor(mockAgent, mockVcSigner, mockPolicyBuilder, mockPromptProtectionChain, mockConfig);
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create executor with valid parameters")
        void shouldCreateExecutorWithValidParameters() {
            // Act
            DefaultAgentAapExecutor executor = new DefaultAgentAapExecutor(
                    mockAgent, mockVcSigner, mockPolicyBuilder, mockPromptProtectionChain, mockConfig);

            // Assert
            assertThat(executor).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when agent is null")
        void shouldThrowExceptionWhenAgentIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentAapExecutor(
                    null, mockVcSigner, mockPolicyBuilder, mockPromptProtectionChain, mockConfig))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when policyBuilder is null")
        void shouldThrowExceptionWhenPolicyBuilderIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentAapExecutor(
                    mockAgent, mockVcSigner, null, mockPromptProtectionChain, mockConfig))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PolicyBuilder cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when config is null")
        void shouldThrowExceptionWhenConfigIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAgentAapExecutor(
                    mockAgent, mockVcSigner, mockPolicyBuilder, mockPromptProtectionChain, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AgentAapExecutorConfig cannot be null");
        }

        @Test
        @DisplayName("Should allow null vcSigner for fallback to raw evidence")
        void shouldAllowNullVcSigner() {
            // Act
            DefaultAgentAapExecutor executor = new DefaultAgentAapExecutor(
                    mockAgent, null, mockPolicyBuilder, mockPromptProtectionChain, mockConfig);

            // Assert
            assertThat(executor).isNotNull();
        }
    }

    @Nested
    @DisplayName("requestAuthUrl()")
    class RequestAuthUrlTests {

        @Test
        @DisplayName("Should successfully request authorization URL")
        void shouldSuccessfullyRequestAuthorizationUrl() throws FrameworkAuthorizationException {
            // Arrange
            RequestAuthUrlRequest request = createValidRequest();

            // Act
            RequestAuthUrlResponse response = executor.requestAuthUrl(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationUrl()).isEqualTo(AUTH_URL);
            assertThat(response.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(response.getState()).isEqualTo(STATE);
            assertThat(response.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(response.getWorkloadContext()).isNotNull();

            // Verify interactions
            verify(mockAgent, times(1)).issueWorkloadIdentityToken(any(IssueWitRequest.class));
            verify(mockAgent, times(1)).registerOAuthClient(any(WorkloadContext.class));
            verify(mockAgent, times(1)).submitParRequest(any(ParSubmissionRequest.class));
            verify(mockAgent, times(1)).generateAuthorizationUrl(anyString(), eq(STATE));
            verify(mockPolicyBuilder, times(1)).buildPolicy(request);
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> executor.requestAuthUrl(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw FrameworkAuthorizationException when agent.issueWorkloadIdentityToken fails")
        void shouldThrowExceptionWhenIssueWorkloadIdentityTokenFails() {
            // Arrange
            RequestAuthUrlRequest request = createValidRequest();
            when(mockAgent.issueWorkloadIdentityToken(any(IssueWitRequest.class)))
                    .thenThrow(new RuntimeException("Workload identity token issuance failed"));

            // Act & Assert
            assertThatThrownBy(() -> executor.requestAuthUrl(request))
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .hasMessageContaining("Failed to request authorization URL")
                    .hasCauseInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should throw FrameworkAuthorizationException when PAR submission fails")
        void shouldThrowExceptionWhenParSubmissionFails() {
            // Arrange
            RequestAuthUrlRequest request = createValidRequest();
            when(mockAgent.submitParRequest(any(ParSubmissionRequest.class)))
                    .thenThrow(new RuntimeException("PAR submission failed"));

            // Act & Assert
            assertThatThrownBy(() -> executor.requestAuthUrl(request))
                    .isInstanceOf(FrameworkAuthorizationException.class)
                    .hasMessageContaining("Failed to request authorization URL")
                    .hasCauseInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should use raw evidence when vcSigner is null")
        void shouldUseRawEvidenceWhenVcSignerIsNull() throws FrameworkAuthorizationException {
            // Arrange
            DefaultAgentAapExecutor executorWithoutVcSigner = new DefaultAgentAapExecutor(
                    mockAgent, null, mockPolicyBuilder, mockPromptProtectionChain, mockConfig);
            RequestAuthUrlRequest request = createValidRequest();

            // Act
            RequestAuthUrlResponse response = executorWithoutVcSigner.requestAuthUrl(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationUrl()).isEqualTo(AUTH_URL);
            
            // Verify that VC signer was never called
            try {
                verify(mockVcSigner, times(0)).sign(any(VerifiableCredential.class));
            } catch (Exception e) {
                // Ignore verification exceptions
            }
        }

        @Test
        @DisplayName("Should fallback to raw evidence when VC signing fails")
        void shouldFallbackToRawEvidenceWhenVcSigningFails() throws Exception {
            // Arrange
            when(mockVcSigner.sign(any()))
                    .thenThrow(new RuntimeException("VC signing failed"));
            RequestAuthUrlRequest request = createValidRequest();

            // Act
            RequestAuthUrlResponse response = executor.requestAuthUrl(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationUrl()).isEqualTo(AUTH_URL);
            
            // Verify that VC signer was called but execution continued
            verify(mockVcSigner, times(1)).sign(any());
        }

        @Test
        @DisplayName("Should use original prompt when promptProtectionChain is null")
        void shouldUseOriginalPromptWhenPromptProtectionChainIsNull() throws FrameworkAuthorizationException {
            // Arrange
            DefaultAgentAapExecutor executorWithoutProtectionChain = new DefaultAgentAapExecutor(
                    mockAgent, mockVcSigner, mockPolicyBuilder, null, mockConfig);
            RequestAuthUrlRequest request = createValidRequest();

            // Act
            RequestAuthUrlResponse response = executorWithoutProtectionChain.requestAuthUrl(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationUrl()).isEqualTo(AUTH_URL);
        }

        @Test
        @DisplayName("Should use original prompt when prompt protection fails")
        void shouldUseOriginalPromptWhenPromptProtectionFails() {
            // Arrange
            when(mockPromptProtectionChain.protect(any(ProtectionContext.class)))
                    .thenReturn(new ProtectionResult("Protection failed"));
            // Enable prompt protection for this test
            when(mockConfig.getPromptProtectionEnabled()).thenReturn(true);
            RequestAuthUrlRequest request = createValidRequest();

            // Act
            RequestAuthUrlResponse response = executor.requestAuthUrl(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationUrl()).isEqualTo(AUTH_URL);
            
            // Verify that prompt protection was called
            verify(mockPromptProtectionChain, times(1)).protect(any(ProtectionContext.class));
        }
    }

    @Nested
    @DisplayName("initiateUserAuth()")
    class InitiateUserAuthTests {

        @Test
        @DisplayName("Should successfully initiate user authorization")
        void shouldSuccessfullyInitiateUserAuthorization() {
            // Arrange
            InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
                    .redirectUri(REDIRECT_URI)
                    .state(STATE)
                    .build();
            String expectedAuthUrl = "http://auth-server/auth?request_uri=test";
            when(mockAgent.initiateAuthorization(request)).thenReturn(expectedAuthUrl);

            // Act
            String result = executor.initiateUserAuth(request);

            // Assert
            assertThat(result).isEqualTo(expectedAuthUrl);
            verify(mockAgent, times(1)).initiateAuthorization(request);
        }
    }

    @Nested
    @DisplayName("exchangeUserIdToken()")
    class ExchangeUserIdTokenTests {

        @Test
        @DisplayName("Should successfully exchange user ID token")
        void shouldSuccessfullyExchangeUserIdToken() {
            // Arrange
            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code("auth-code-123")
                    .state(STATE)
                    .clientId(CLIENT_ID)
                    .build();

            // Act
            DefaultAgentAapExecutor result = (DefaultAgentAapExecutor) executor.exchangeUserIdToken(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(executor);
            verify(mockAgent, times(1)).exchangeCodeForToken(request);
        }
    }

    @Nested
    @DisplayName("exchangeAgentAuthToken()")
    class ExchangeAgentAuthTokenTests {

        @Test
        @DisplayName("Should successfully exchange agent authorization token")
        void shouldSuccessfullyExchangeAgentAuthToken() {
            // Arrange
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .authorizationCode("auth-code-123")
                    .state(STATE)
                    .build();
            AgentOperationAuthToken expectedToken = AgentOperationAuthToken.builder()
                    .header(AgentOperationAuthToken.Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("test-issuer")
                            .subject("test-subject")
                            .audience("test-audience")
                            .expirationTime(java.time.Instant.now().plusSeconds(3600))
                            .issuedAt(java.time.Instant.now())
                            .jwtId("test-jti")
                            .agentIdentity(AgentIdentity.builder().id("test-agent").build())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId("test-policy").build())
                            .build())
                    .build();
            when(mockAgent.handleAuthorizationCallback(response)).thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = executor.exchangeAgentAuthToken(response);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getClaims().getSubject()).isEqualTo("test-subject");
            verify(mockAgent, times(1)).handleAuthorizationCallback(response);
        }
    }

    @Nested
    @DisplayName("buildAuthContext()")
    class BuildAuthContextTests {

        @Test
        @DisplayName("Should successfully build authorization context")
        void shouldSuccessfullyBuildAuthorizationContext() {
            // Arrange
            AgentOperationAuthToken aoat = AgentOperationAuthToken.builder()
                    .header(Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("test-issuer")
                            .subject("test-subject")
                            .audience("test-audience")
                            .expirationTime(java.time.Instant.now().plusSeconds(3600))
                            .issuedAt(java.time.Instant.now())
                            .jwtId("test-jti")
                            .agentIdentity(AgentIdentity.builder().id("test-agent").build())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId("test-policy").build())
                            .build())
                    .build();
            PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                    .workloadContext(createMockWorkloadContext())
                    .aoat(aoat)
                    .build();
            AgentAuthorizationContext expectedContext = AgentAuthorizationContext.builder()
                    .wit("test-wit")
                    .wpt("test-wpt")
                    .aoat("test-aoat")
                    .build();
            when(mockAgent.prepareAuthorizationContext(request)).thenReturn(expectedContext);

            // Act
            AgentAuthorizationContext result = executor.buildAuthContext(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getWit()).isEqualTo("test-wit");
            verify(mockAgent, times(1)).prepareAuthorizationContext(request);
        }
    }

    @Nested
    @DisplayName("getWorkloadContext()")
    class GetWorkloadContextTests {

        @Test
        @DisplayName("Should return current workload context after requestAuthUrl")
        void shouldReturnCurrentWorkloadContext() throws FrameworkAuthorizationException {
            // Arrange
            RequestAuthUrlRequest request = createValidRequest();
            WorkloadContext expectedContext = createMockWorkloadContext();

            // Act
            executor.requestAuthUrl(request);
            WorkloadContext result = executor.getWorkloadContext();

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getWorkloadId()).isEqualTo(expectedContext.getWorkloadId());
            assertThat(result.getUserId()).isEqualTo(expectedContext.getUserId());
        }
    }

    @Nested
    @DisplayName("cleanup()")
    class CleanupTests {

        @Test
        @DisplayName("Should successfully cleanup authorization context")
        void shouldSuccessfullyCleanupAuthorizationContext() throws FrameworkAuthorizationException {
            // Arrange
            RequestAuthUrlRequest request = createValidRequest();
            executor.requestAuthUrl(request);
            WorkloadContext workloadContext = executor.getWorkloadContext();

            // Act
            executor.cleanup(workloadContext);

            // Assert
            verify(mockAgent, times(1)).clearAuthorizationContext(workloadContext);
        }
    }

    // ===== Helper Methods =====

    private RequestAuthUrlRequest createValidRequest() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("key1", "value1");
        
        WorkloadRequestContext workloadContext = 
            WorkloadRequestContext.builder()
                .operationType(OPERATION_TYPE)
                .resourceId(RESOURCE_ID)
                .metadata(metadata)
                .build();
        
        return RequestAuthUrlRequest.builder()
                .userIdentityToken(USER_IDENTITY_TOKEN)
                .userOriginalInput(USER_ORIGINAL_INPUT)
                .workloadContext(workloadContext)
                .sessionId(SESSION_ID)
                .build();
    }

    private WorkloadContext createMockWorkloadContext() {
        return WorkloadContext.builder()
                .workloadId(WORKLOAD_ID)
                .userId(USER_ID)
                .wit("test-wit")
                .publicKey("test-public-key")
                .privateKey("test-private-key")
                .expiresAt(java.time.Instant.now().plusSeconds(3600))
                .build();
    }

    private DcrResponse createMockDcrResponse() {
        return DcrResponse.builder()
                .clientId(CLIENT_ID)
                .clientSecret("secret-123")
                .clientSecretExpiresAt(0L)
                .build();
    }

    private ParResponse createMockParResponse() {
        return ParResponse.success(REQUEST_URI, 600);
    }
}