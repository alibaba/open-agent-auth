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

import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.ModelAndView;

import java.util.LinkedHashMap;
import java.util.Map;

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

    @Mock
    private JweDecoder jweDecoder;

    @Mock
    private OperationTextRenderer operationTextRenderer;

    private PromptDecryptionService promptDecryptionService;

    private DefaultConsentPageProvider provider;

    @BeforeEach
    void setUp() {
        promptDecryptionService = new PromptDecryptionService(jweDecoder, true);
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

        @Test
        @DisplayName("Should create provider with PromptDecryptionService")
        void shouldCreateProviderWithPromptDecryptionService() {
            DefaultConsentPageProvider providerWithService = 
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);

            assertThat(providerWithService).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with null PromptDecryptionService")
        void shouldCreateProviderWithNullPromptDecryptionService() {
            DefaultConsentPageProvider providerWithNull = 
                new DefaultConsentPageProvider("consent", "Test IDP", null);

            assertThat(providerWithNull).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with OperationTextRenderer")
        void shouldCreateProviderWithOperationTextRenderer() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP",
                        promptDecryptionService, operationTextRenderer);

            assertThat(providerWithRenderer).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with null OperationTextRenderer")
        void shouldCreateProviderWithNullOperationTextRenderer() {
            DefaultConsentPageProvider providerWithNullRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP",
                        promptDecryptionService, null);

            assertThat(providerWithNullRenderer).isNotNull();
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

        @Test
        @DisplayName("Should render consent page with decoded user prompt from JWT-VC")
        void shouldRenderConsentPageWithDecodedUserPrompt() {
            // Setup provider with PromptDecryptionService (enabled=true, but JWT-VC is not JWE format)
            DefaultConsentPageProvider providerWithService = 
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);
            
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            String subject = "user123";
            String clientId = "agent-client";
            String scopes = "openid profile email";

            // JWT-VC is 3-segment (not JWE), so PromptDecryptionService will pass it through
            String testJwtVc = createTestJwtVcString();

            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();

            ParJwtClaims parClaims = createTestParClaims(evidence);

            ModelAndView mv = providerWithService.renderConsentPage(
                request, requestUri, subject, clientId, scopes, parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            assertThat(mv.getModel()).containsKey("decodedCredential");
            assertThat(mv.getModel()).containsKey("originalUserPrompt");
            assertThat(mv.getModel()).containsKey("inputChannel");
            assertThat(mv.getModel()).containsKey("inputTimestamp");
            assertThat(mv.getModel().get("originalUserPrompt")).isEqualTo("Test user prompt");
        }

        @Test
        @DisplayName("Should handle JWT-VC decoding failure gracefully")
        void shouldHandleJwtVcDecodingFailureGracefully() {
            // Setup provider with PromptDecryptionService
            DefaultConsentPageProvider providerWithService = 
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);

            // "invalid-jwt-vc-string" has 0 dots, so PromptDecryptionService passes it through
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("invalid-jwt-vc-string")
                    .build();

            ParJwtClaims parClaims = createTestParClaims(evidence);

            // Should not throw exception, but render the page gracefully
            ModelAndView mv = providerWithService.renderConsentPage(
                request, "urn:req:1", "user123", "agent-client", "openid profile email", parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            assertThat(mv.getModel()).containsKey("evidence");
            assertThat(mv.getModel()).doesNotContainKey("decodedCredential");
            assertThat(mv.getModel()).doesNotContainKey("originalUserPrompt");
        }

        @Test
        @DisplayName("Should handle null PromptDecryptionService gracefully")
        void shouldHandleNullPromptDecryptionServiceGracefully() {
            // Setup provider with null PromptDecryptionService
            DefaultConsentPageProvider providerWithNullService = 
                new DefaultConsentPageProvider("consent", "Test IDP", null);
            
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            String subject = "user123";
            String clientId = "agent-client";
            String scopes = "openid profile email";

            // Create a minimal valid JWT-VC string for testing
            String testJwtVc = createTestJwtVcString();

            // Create evidence with valid JWT-VC
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();

            ParJwtClaims parClaims = createTestParClaims(evidence);

            // Should not throw exception even with null PromptDecryptionService
            ModelAndView mv = providerWithNullService.renderConsentPage(
                request, requestUri, subject, clientId, scopes, parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getViewName()).isEqualTo("consent");
            // The model should still contain the decoded credential
            // because the JWT-VC is not encrypted, so decryption is not needed
            assertThat(mv.getModel()).containsKey("decodedCredential");
            assertThat(mv.getModel()).containsKey("originalUserPrompt");
        }

        @Test
        @DisplayName("Should decrypt JWE-encrypted prompt inside JWT-VC credential subject")
        void shouldDecryptJweEncryptedPromptInsideJwtVc() throws Exception {
            DefaultConsentPageProvider providerWithService =
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);

            // Build a JWT-VC whose credentialSubject.prompt is a JWE string (5 dot-separated segments)
            String jweEncryptedPrompt = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
                    + ".encryptedKey.iv.ciphertext.tag";
            String testJwtVc = createTestJwtVcStringWithPrompt(jweEncryptedPrompt);

            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            // Inner decryption: the prompt field IS JWE (4 dots), so jweDecoder will be called
            when(jweDecoder.decryptToString(jweEncryptedPrompt))
                    .thenReturn("buy some programming books");

            ModelAndView mv = providerWithService.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv.getModel().get("originalUserPrompt"))
                    .isEqualTo("buy some programming books");
        }

        @Test
        @DisplayName("Should not set originalUserPrompt when inner JWE decryption fails")
        void shouldNotSetOriginalUserPromptWhenInnerJweDecryptionFails() throws Exception {
            DefaultConsentPageProvider providerWithService =
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);

            String jweEncryptedPrompt = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
                    + ".encryptedKey.iv.ciphertext.tag";
            String testJwtVc = createTestJwtVcStringWithPrompt(jweEncryptedPrompt);

            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            // Inner: jweDecoder throws, so tryDecryptOrPassthrough returns the JWE unchanged
            when(jweDecoder.decryptToString(jweEncryptedPrompt))
                    .thenThrow(new JOSEException("Decryption key not found"));

            ModelAndView mv = providerWithService.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            // The prompt is still JWE after failed decryption, so originalUserPrompt should NOT be set
            assertThat(mv.getModel()).doesNotContainKey("originalUserPrompt");
        }

        @Test
        @DisplayName("Should format ISO 8601 timestamp into human-readable format")
        void shouldFormatTimestampIntoHumanReadableFormat() {
            DefaultConsentPageProvider providerWithNullService =
                new DefaultConsentPageProvider("consent", "Test IDP", null);

            // JWT-VC with a known ISO timestamp
            String testJwtVc = createTestJwtVcString(); // timestamp = "2024-01-01T00:00:00Z"

            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            ModelAndView mv = providerWithNullService.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            // The timestamp "2024-01-01T00:00:00Z" should be formatted
            String formattedTimestamp = (String) mv.getModel().get("inputTimestamp");
            assertThat(formattedTimestamp).isNotNull();
            assertThat(formattedTimestamp).contains("Jan");
            assertThat(formattedTimestamp).contains("2024");
            assertThat(formattedTimestamp).contains("UTC");
        }

        @Test
        @DisplayName("Should handle null evidence sourcePromptCredential gracefully")
        void shouldHandleNullSourcePromptCredentialGracefully() {
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(null)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            ModelAndView mv = provider.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getModel()).doesNotContainKey("decodedCredential");
            assertThat(mv.getModel()).doesNotContainKey("originalUserPrompt");
        }

        @Test
        @DisplayName("Should handle empty evidence sourcePromptCredential gracefully")
        void shouldHandleEmptySourcePromptCredentialGracefully() {
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("")
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            ModelAndView mv = provider.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getModel()).doesNotContainKey("decodedCredential");
            assertThat(mv.getModel()).doesNotContainKey("originalUserPrompt");
        }

        @Test
        @DisplayName("Should skip decoding when sourcePromptCredential is still JWE after decryption attempt")
        void shouldSkipDecodingWhenStillJweAfterDecryptionAttempt() throws Exception {
            DefaultConsentPageProvider providerWithService =
                new DefaultConsentPageProvider("consent", "Test IDP", promptDecryptionService);

            // A JWE string (5 dot-separated segments)
            String jweString = "header.encryptedKey.iv.ciphertext.tag";

            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(jweString)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            // jweDecoder returns the same JWE string (simulating decryption that yields another JWE)
            when(jweDecoder.decryptToString(jweString)).thenReturn(jweString);

            ModelAndView mv = providerWithService.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv.getModel()).doesNotContainKey("decodedCredential");
            assertThat(mv.getModel()).doesNotContainKey("originalUserPrompt");
        }
    }

    @Nested
    @DisplayName("Operation Text Rendering Tests")
    class OperationTextRenderingTests {

        @Test
        @DisplayName("Should add rendered operation text when renderer is configured")
        void shouldAddRenderedOperationTextWhenRendererConfigured() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            OperationTextRenderResult renderResult = new OperationTextRenderResult(
                    "The agent can search for programming books.", SemanticExpansionLevel.MEDIUM);
            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenReturn(renderResult);

            ParJwtClaims parClaims = createTestParClaims();

            ModelAndView mv = providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv.getModel()).containsEntry("renderedOperationText",
                    "The agent can search for programming books.");
            assertThat(mv.getModel()).containsEntry("semanticExpansionLevel", "medium");
        }

        @Test
        @DisplayName("Should not add rendered text when renderer is null")
        void shouldNotAddRenderedTextWhenRendererIsNull() {
            DefaultConsentPageProvider providerWithoutRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, null);

            ParJwtClaims parClaims = createTestParClaims();

            ModelAndView mv = providerWithoutRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv.getModel()).doesNotContainKey("renderedOperationText");
            assertThat(mv.getModel()).doesNotContainKey("semanticExpansionLevel");
        }

        @Test
        @DisplayName("Should handle renderer exception gracefully")
        void shouldHandleRendererExceptionGracefully() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenThrow(new RuntimeException("LLM call failed"));

            ParJwtClaims parClaims = createTestParClaims();

            ModelAndView mv = providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv).isNotNull();
            assertThat(mv.getModel()).doesNotContainKey("renderedOperationText");
            assertThat(mv.getModel()).doesNotContainKey("semanticExpansionLevel");
        }

        @Test
        @DisplayName("Should pass operation proposal to render context")
        void shouldPassOperationProposalToRenderContext() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            OperationTextRenderResult renderResult = new OperationTextRenderResult(
                    "Rendered text", SemanticExpansionLevel.LOW);
            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenReturn(renderResult);

            ParJwtClaims parClaims = createTestParClaims();

            providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            verify(operationTextRenderer).render(argThat(context ->
                    context.getOperationProposal() != null
                    && context.getOperationProposal().contains("input.operationType")));
        }

        @Test
        @DisplayName("Should pass request context to render context")
        void shouldPassRequestContextToRenderContext() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            OperationTextRenderResult renderResult = new OperationTextRenderResult(
                    "Rendered text", SemanticExpansionLevel.MEDIUM);
            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenReturn(renderResult);

            ParJwtClaims parClaims = createTestParClaims();

            providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            verify(operationTextRenderer).render(argThat(context ->
                    context.getRequestContext() != null
                    && "web".equals(context.getRequestContext().getChannel())));
        }

        @Test
        @DisplayName("Should not call renderer when PAR claims are null")
        void shouldNotCallRendererWhenParClaimsAreNull() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            ModelAndView mv = providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", null);

            verifyNoInteractions(operationTextRenderer);
            assertThat(mv.getModel()).doesNotContainKey("renderedOperationText");
        }

        @Test
        @DisplayName("Should pass decoded user prompt to render context when available")
        void shouldPassDecodedUserPromptToRenderContextWhenAvailable() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            OperationTextRenderResult renderResult = new OperationTextRenderResult(
                    "Rendered text", SemanticExpansionLevel.MEDIUM);
            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenReturn(renderResult);

            String testJwtVc = createTestJwtVcString();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(testJwtVc)
                    .build();
            ParJwtClaims parClaims = createTestParClaims(evidence);

            providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            verify(operationTextRenderer).render(argThat(context ->
                    "Test user prompt".equals(context.getOriginalPrompt())));
        }

        @Test
        @DisplayName("Should render with HIGH expansion level")
        void shouldRenderWithHighExpansionLevel() {
            DefaultConsentPageProvider providerWithRenderer =
                new DefaultConsentPageProvider("consent", "Test IDP", null, operationTextRenderer);

            OperationTextRenderResult renderResult = new OperationTextRenderResult(
                    "High expansion text", SemanticExpansionLevel.HIGH);
            when(operationTextRenderer.render(any(OperationTextRenderContext.class)))
                    .thenReturn(renderResult);

            ParJwtClaims parClaims = createTestParClaims();

            ModelAndView mv = providerWithRenderer.renderConsentPage(
                    request, "urn:req:1", "user1", "client1", "openid", parClaims);

            assertThat(mv.getModel()).containsEntry("renderedOperationText", "High expansion text");
            assertThat(mv.getModel()).containsEntry("semanticExpansionLevel", "high");
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

    private ParJwtClaims createTestParClaims(Evidence evidence) {
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

    /**
     * Creates a signed JWT-VC string for testing.
     * Uses RS256 signing so that SignedJWT.parse() in JwtVcDecoder.decode() can parse it.
     */
    private String createTestJwtVcString() {
        return createTestJwtVcStringWithPrompt("Test user prompt");
    }

    /**
     * Creates a signed JWT-VC string with a custom prompt value in the credentialSubject.
     * Used to test scenarios where the prompt field itself is JWE-encrypted.
     */
    private String createTestJwtVcStringWithPrompt(String promptValue) {
        try {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                    .keyID("test-vc-key")
                    .generate();

            Map<String, Object> credentialSubject = new LinkedHashMap<>();
            credentialSubject.put("type", "UserInputEvidence");
            credentialSubject.put("prompt", promptValue);
            credentialSubject.put("timestamp", "2024-01-01T00:00:00Z");
            credentialSubject.put("channel", "web");

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject("test-sub")
                    .claim("credentialSubject", credentialSubject)
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.getKeyID())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(new RSASSASigner(rsaKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test JWT-VC", e);
        }
    }
}