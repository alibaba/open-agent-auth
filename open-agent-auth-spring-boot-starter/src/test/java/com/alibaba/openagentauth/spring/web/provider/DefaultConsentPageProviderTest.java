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
package com.alibaba.openagentauth.spring.web.provider;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.ModelAndView;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for DefaultConsentPageProvider.
 * <p>
 * This test class verifies the functionality of rendering consent pages.
 * </p>
 */
@DisplayName("DefaultConsentPageProvider Tests")
@ExtendWith(MockitoExtension.class)
class DefaultConsentPageProviderTest {

    @Mock
    private HttpServletRequest request;

    private DefaultConsentPageProvider provider;

    @BeforeEach
    void setUp() {
        provider = new DefaultConsentPageProvider();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create provider with default view name")
        void shouldCreateProviderWithDefaultViewName() {
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with custom view name")
        void shouldCreateProviderWithCustomViewName() {
            DefaultConsentPageProvider customProvider = new DefaultConsentPageProvider("custom-consent");

            assertThat(customProvider).isNotNull();
        }
    }

    @Nested
    @DisplayName("Render Consent Page Tests")
    class RenderConsentPageTests {

        @Test
        @DisplayName("Should render consent page with basic parameters")
        void shouldRenderConsentPageWithBasicParameters() {
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            String subject = "user123";
            String clientId = "agent-client";
            String scopes = "openid profile email";

            ModelAndView mv = provider.renderConsentPage(request, requestUri, subject, clientId, scopes);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            assertThat(mv.getModel()).containsEntry("requestUri", requestUri);
            assertThat(mv.getModel()).containsEntry("subject", subject);
            assertThat(mv.getModel()).containsEntry("clientId", clientId);
            assertThat(mv.getModel()).containsEntry("scopes", scopes);
        }

        @Test
        @DisplayName("Should render consent page with PAR claims")
        void shouldRenderConsentPageWithParClaims() {
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            String subject = "user123";
            String clientId = "agent-client";
            String scopes = "openid profile email";

            ParJwtClaims parClaims = createTestParClaims();

            ModelAndView mv = provider.renderConsentPage(request, requestUri, subject, clientId, scopes, parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            assertThat(mv.getModel()).containsEntry("requestUri", requestUri);
            assertThat(mv.getModel()).containsEntry("subject", subject);
            assertThat(mv.getModel()).containsEntry("clientId", clientId);
            assertThat(mv.getModel()).containsEntry("scopes", scopes);
            assertThat(mv.getModel()).containsKey("parClaims");
            assertThat(mv.getModel()).containsKey("evidence");
            assertThat(mv.getModel()).containsKey("operationProposal");
            assertThat(mv.getModel()).containsKey("context");
        }

        @Test
        @DisplayName("Should handle null PAR claims")
        void shouldHandleNullParClaims() {
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            String subject = "user123";
            String clientId = "agent-client";
            String scopes = "openid profile email";

            ModelAndView mv = provider.renderConsentPage(request, requestUri, subject, clientId, scopes, null);

            assertThat(mv).isNotNull();
            assertThat(mv.getModel()).doesNotContainKey("parClaims");
            assertThat(mv.getModel()).doesNotContainKey("evidence");
            assertThat(mv.getModel()).doesNotContainKey("operationProposal");
        }

        @Test
        @DisplayName("Should render traditional consent page")
        void shouldRenderTraditionalConsentPage() {
            String subject = "user123";
            String clientId = "agent-client";
            String redirectUri = "https://app.example.com/callback";
            String state = "xyz789";
            String scopes = "openid profile email";

            ModelAndView mv = provider.renderConsentPageTraditional(request, subject, clientId, redirectUri, state, scopes);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            assertThat(mv.getModel()).containsEntry("subject", subject);
            assertThat(mv.getModel()).containsEntry("clientId", clientId);
            assertThat(mv.getModel()).containsEntry("redirectUri", redirectUri);
            assertThat(mv.getModel()).containsEntry("state", state);
            assertThat(mv.getModel()).containsEntry("scopes", scopes);
            assertThat(mv.getModel()).containsEntry("requestUri", null);
        }
    }

    @Nested
    @DisplayName("Handle Consent Response Tests")
    class HandleConsentResponseTests {

        @Test
        @DisplayName("Should return true when action is approve")
        void shouldReturnTrueWhenActionIsApprove() {
            when(request.getParameter("action")).thenReturn("approve");

            boolean approved = provider.handleConsentResponse(request);

            assertThat(approved).isTrue();
        }

        @Test
        @DisplayName("Should return true when action is APPROVE (uppercase)")
        void shouldReturnTrueWhenActionIsApproveUppercase() {
            when(request.getParameter("action")).thenReturn("APPROVE");

            boolean approved = provider.handleConsentResponse(request);

            assertThat(approved).isTrue();
        }

        @Test
        @DisplayName("Should return false when action is deny")
        void shouldReturnFalseWhenActionIsDeny() {
            when(request.getParameter("action")).thenReturn("deny");

            boolean approved = provider.handleConsentResponse(request);

            assertThat(approved).isFalse();
        }

        @Test
        @DisplayName("Should return false when action is null")
        void shouldReturnFalseWhenActionIsNull() {
            when(request.getParameter("action")).thenReturn(null);

            boolean approved = provider.handleConsentResponse(request);

            assertThat(approved).isFalse();
        }

        @Test
        @DisplayName("Should return false when action is empty")
        void shouldReturnFalseWhenActionIsEmpty() {
            when(request.getParameter("action")).thenReturn("");

            boolean approved = provider.handleConsentResponse(request);

            assertThat(approved).isFalse();
        }
    }

    @Nested
    @DisplayName("Is Consent Required Tests")
    class IsConsentRequiredTests {

        @Test
        @DisplayName("Should always return true by default")
        void shouldAlwaysReturnTrueByDefault() {
            boolean required = provider.isConsentRequired(request, "user123", "agent-client", "openid");

            assertThat(required).isTrue();
        }
    }

    private ParJwtClaims createTestParClaims() {
        // Create evidence
        Evidence evidence = Evidence.builder()
                .sourcePromptCredential("source-prompt-credential-jwt")
                .build();
        
        // Create operation proposal
        String operationProposal = "package agent\nallow {\n  input.operationType == \"read\"\n}";
        
        // Create context
        OperationRequestContext.UserContext userContext = OperationRequestContext.UserContext.builder()
                .id("user123")
                .build();
        
        OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                .instance("agent-instance-1")
                .platform("web")
                .client("agent-client")
                .build();
        
        OperationRequestContext context = OperationRequestContext.builder()
                .channel("web")
                .deviceFingerprint("device-123")
                .language("en-US")
                .user(userContext)
                .agent(agentContext)
                .build();
        
        // Create binding proposal (using minimal constructor)
        AgentUserBindingProposal bindingProposal = new AgentUserBindingProposal(
                "user-id-token",
                "agent-workload-token",
                "device-fingerprint"
        );
        
        // Create PAR claims
        return ParJwtClaims.builder()
                .issuer("https://client.example.com")
                .subject("user123")
                .audience(java.util.Arrays.asList("https://as.example.com"))
                .issueTime(new java.util.Date())
                .expirationTime(new java.util.Date(System.currentTimeMillis() + 3600000))
                .jwtId("jti-123")
                .evidence(evidence)
                .agentUserBindingProposal(bindingProposal)
                .operationProposal(operationProposal)
                .context(context)
                .state("state-123")
                .build();
    }
}
