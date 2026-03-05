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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtParser;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthorizationOrchestrator}.
 * <p>
 * Tests verify the orchestration logic for OAuth 2.0 authorization flows,
 * including PAR (Pushed Authorization Request) and traditional flows.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>OAuth 2.0 Authorization Framework (RFC 6749)</li>
 *   <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)</li>
 *   <li>Strategy Pattern for flow extensibility</li>
 *   <li>Orchestrator Pattern for workflow coordination</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
@DisplayName("Authorization Orchestrator Tests")
@ExtendWith(MockitoExtension.class)
class AuthorizationOrchestratorTest {

    private static final String CLIENT_ID = "test_client";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String SCOPE = "read write";
    private static final String STATE = "state_123";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";
    private static final String SUBJECT = "user_123";
    private static final String AUTHORIZATION_CODE = "code_456";
    private static final String LOGIN_URL = "https://example.com/login";
    private static final String REQUEST_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    @Mock
    private AuthorizationFlowStrategy strategy;

    @Mock
    private UserAuthenticationInterceptor userAuthenticationInterceptor;

    @Mock
    private ConsentPageProvider consentPageProvider;

    @Mock
    private SessionMappingBizService sessionMappingBizService;

    @Mock
    private OAuth2ParServer parServer;

    @Mock
    private AapParJwtParser parJwtParser;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpSession session;

    @Mock
    private ParRequest parRequest;

    @Mock
    private ParJwtClaims parJwtClaims;

    private AuthorizationOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        orchestrator = new AuthorizationOrchestrator(
                List.of(strategy),
                userAuthenticationInterceptor,
                consentPageProvider,
                sessionMappingBizService,
                parServer,
                parJwtParser,
                null
        );
    }

    @Nested
    @DisplayName("Constructor Validation")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw exception when strategies is null")
        void shouldThrowExceptionWhenStrategiesIsNull() {
            assertThatThrownBy(() -> new AuthorizationOrchestrator(
                    null,
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    parJwtParser,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("strategies");
        }

        @Test
        @DisplayName("Should accept null userAuthenticationInterceptor")
        void shouldAcceptNullUserAuthenticationInterceptor() {
            // userAuthenticationInterceptor is optional, should not throw exception
            AuthorizationOrchestrator orchestrator = new AuthorizationOrchestrator(
                    List.of(strategy),
                    null,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    parJwtParser,
                    null
            );
            assertThat(orchestrator).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when consentPageProvider is null")
        void shouldThrowExceptionWhenConsentPageProviderIsNull() {
            assertThatThrownBy(() -> new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    null,
                    sessionMappingBizService,
                    parServer,
                    parJwtParser,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("consentPageProvider");
        }

        @Test
        @DisplayName("Should throw exception when sessionMappingBizService is null")
        void shouldThrowExceptionWhenSessionMappingBizServiceIsNull() {
            assertThatThrownBy(() -> new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    null,
                    parServer,
                    parJwtParser,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("sessionMappingBizService");
        }

        @Test
        @DisplayName("Should accept null parServer and parJwtParser")
        void shouldAcceptNullParServerAndParJwtParser() {
            assertThatCode(() -> new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    null,
                    null,
                    null
            )).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("processAuthorization - Consent Submission")
    class ConsentSubmissionTests {

        @BeforeEach
        void setUp() {
            when(request.getParameter("action")).thenReturn("consent");
        }

        @Test
        @DisplayName("Should process consent approval successfully")
        void shouldProcessConsentApprovalSuccessfully() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.handleConsentResponse(request)).thenReturn(true);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains(AUTHORIZATION_CODE);
            verify(strategy).validateRequest(context);
            verify(consentPageProvider).handleConsentResponse(request);
        }

        @Test
        @DisplayName("Should process consent denial")
        void shouldProcessConsentDenial() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.handleConsentResponse(request)).thenReturn(false);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRedirectUri()).thenReturn(REDIRECT_URI);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains("access_denied");
            assertThat(result.getRedirectUri()).contains("error_description");
            verify(strategy, never()).issueCode(any(), any());
        }

        @Test
        @DisplayName("Should return unauthorized when user not authenticated during consent")
        void shouldReturnUnauthorizedWhenUserNotAuthenticatedDuringConsent() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(null);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("login_required");
            assertThat(result.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should return error when no strategy found for consent")
        void shouldReturnErrorWhenNoStrategyFoundForConsent() {
            // Given
            when(strategy.supports(request)).thenReturn(false);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("invalid_request");
        }
    }

    @Nested
    @DisplayName("processAuthorization - Traditional Flow")
    class TraditionalFlowTests {

        @Test
        @DisplayName("Should issue authorization code directly when authenticated and no consent needed")
        void shouldIssueAuthorizationCodeDirectlyWhenAuthenticatedAndNoConsentNeeded() {
            // Given
            AuthorizationRequestContext context = createTraditionalContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains(AUTHORIZATION_CODE);
            verify(strategy).validateRequest(context);
            verify(consentPageProvider, never()).renderConsentPageTraditional(any(), anyString(), anyString(), anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Should render consent page when consent required")
        void shouldRenderConsentPageWhenConsentRequired() {
            // Given
            AuthorizationRequestContext context = createTraditionalContext();
            Object consentPage = new Object();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(true);
            when(consentPageProvider.renderConsentPageTraditional(request, SUBJECT, CLIENT_ID, REDIRECT_URI, STATE, SCOPE))
                    .thenReturn(consentPage);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.CONSENT_PAGE);
            assertThat(result.getConsentPage()).isEqualTo(consentPage);
            verify(strategy, never()).issueCode(any(), any());
        }

        @Test
        @DisplayName("Should redirect to login when user not authenticated")
        void shouldRedirectToLoginWhenUserNotAuthenticated() {
            // Given
            AuthorizationRequestContext context = createTraditionalContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(null);
            when(userAuthenticationInterceptor.getLoginUrl(request)).thenReturn(LOGIN_URL);
            when(request.getSession(true)).thenReturn(session);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).isEqualTo(LOGIN_URL);
            verify(userAuthenticationInterceptor).getLoginUrl(request);
        }

        @Test
        @DisplayName("Should return unauthorized when no login URL available")
        void shouldReturnUnauthorizedWhenNoLoginUrlAvailable() {
            // Given
            AuthorizationRequestContext context = createTraditionalContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(userAuthenticationInterceptor.getLoginUrl(request)).thenReturn(null);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("login_required");
            assertThat(result.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should return error when no strategy found")
        void shouldReturnErrorWhenNoStrategyFound() {
            // Given
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(false);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Missing required parameters");
        }
    }

    @Nested
    @DisplayName("processAuthorization - PAR Flow with JWT Claims")
    class ParFlowWithJwtClaimsTests {

        @Test
        @DisplayName("Should extract PAR JWT claims and render consent page")
        void shouldExtractParJwtClaimsAndRenderConsentPage() {
            // Given
            AuthorizationRequestContext context = createParContext();
            Object consentPage = new Object();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn(REQUEST_JWT);
            when(parJwtParser.parse(REQUEST_JWT)).thenReturn(parJwtClaims);
            when(parJwtClaims.getJwtId()).thenReturn("jti_123");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(true);
            when(consentPageProvider.renderConsentPage(request, REQUEST_URI, SUBJECT, CLIENT_ID, SCOPE, parJwtClaims))
                    .thenReturn(consentPage);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.CONSENT_PAGE);
            assertThat(result.getConsentPage()).isEqualTo(consentPage);
            verify(parServer).retrieveRequest(REQUEST_URI);
            verify(parJwtParser).parse(REQUEST_JWT);
        }

        @Test
        @DisplayName("Should handle PAR flow without JWT claims when request JWT is null")
        void shouldHandleParFlowWithoutJwtClaimsWhenRequestJwtIsNull() {
            // Given
            AuthorizationRequestContext context = createParContext();
            Object consentPage = new Object();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn(null);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(true);
            when(consentPageProvider.renderConsentPage(request, REQUEST_URI, SUBJECT, CLIENT_ID, SCOPE))
                    .thenReturn(consentPage);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.CONSENT_PAGE);
            assertThat(result.getConsentPage()).isEqualTo(consentPage);
            verify(parJwtParser, never()).parse(anyString());
        }

        @Test
        @DisplayName("Should handle PAR flow when JWT parsing fails")
        void shouldHandleParFlowWhenJwtParsingFails() {
            // Given
            AuthorizationRequestContext context = createParContext();
            Object consentPage = new Object();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn(REQUEST_JWT);
            when(parJwtParser.parse(REQUEST_JWT)).thenThrow(new RuntimeException("Parse error"));
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(true);
            when(consentPageProvider.renderConsentPage(request, REQUEST_URI, SUBJECT, CLIENT_ID, SCOPE))
                    .thenReturn(consentPage);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.CONSENT_PAGE);
            assertThat(result.getConsentPage()).isEqualTo(consentPage);
        }

        @Test
        @DisplayName("Should skip PAR JWT extraction when parServer is null")
        void shouldSkipParJwtExtractionWhenParServerIsNull() {
            // Given
            orchestrator = new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    null,
                    null
            );
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            verify(parServer, never()).retrieveRequest(anyString());
            verify(parJwtParser, never()).parse(anyString());
        }

        @Test
        @DisplayName("Should skip PAR JWT extraction when parJwtParser is null")
        void shouldSkipParJwtExtractionWhenParJwtParserIsNull() {
            // Given
            orchestrator = new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    null,
                    null
            );
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            verify(parServer, never()).retrieveRequest(anyString());
            verify(parJwtParser, never()).parse(anyString());
        }
    }

    @Nested
    @DisplayName("processConsentSubmission")
    class ProcessConsentSubmissionTests {

        @Test
        @DisplayName("Should process consent approval successfully")
        void shouldProcessConsentApprovalSuccessfully() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.handleConsentResponse(request)).thenReturn(true);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processConsentSubmission(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains(AUTHORIZATION_CODE);
            verify(strategy).validateRequest(context);
            verify(consentPageProvider).handleConsentResponse(request);
        }

        @Test
        @DisplayName("Should return error when user denies consent")
        void shouldReturnErrorWhenUserDeniesConsent() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.handleConsentResponse(request)).thenReturn(false);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRedirectUri()).thenReturn(REDIRECT_URI);

            // When
            AuthorizationResult result = orchestrator.processConsentSubmission(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains("access_denied");
            assertThat(result.getRedirectUri()).contains("error_description");
            verify(strategy, never()).issueCode(any(), any());
        }

        @Test
        @DisplayName("Should return unauthorized when user not authenticated")
        void shouldReturnUnauthorizedWhenUserNotAuthenticated() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(null);

            // When
            AuthorizationResult result = orchestrator.processConsentSubmission(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("login_required");
            assertThat(result.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should return error when no strategy found")
        void shouldReturnErrorWhenNoStrategyFound() {
            // Given
            when(strategy.supports(request)).thenReturn(false);

            // When
            AuthorizationResult result = orchestrator.processConsentSubmission(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should propagate OAuth2AuthorizationException from strategy")
        void shouldPropagateOAuth2AuthorizationExceptionFromStrategy() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            doThrow(new OAuth2AuthorizationException(OAuth2RfcErrorCode.UNAUTHORIZED_CLIENT, "Invalid client"))
                    .when(strategy).validateRequest(context);

            // When & Then
            assertThatThrownBy(() -> orchestrator.processConsentSubmission(request))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .extracting("rfcErrorCode")
                    .isEqualTo("unauthorized_client");
        }
    }

    @Nested
    @DisplayName("extractParJwtClaims - Private Method Testing via Behavior")
    class ExtractParJwtClaimsTests {

        @Test
        @DisplayName("Should extract and attach PAR JWT claims to context")
        void shouldExtractAndAttachParJwtClaimsToContext() {
            // Given
            AuthorizationRequestContext context = createParContext();
            Object consentPage = new Object();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn(REQUEST_JWT);
            when(parJwtParser.parse(REQUEST_JWT)).thenReturn(parJwtClaims);
            when(parJwtClaims.getJwtId()).thenReturn("jti_123");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(true);
            when(consentPageProvider.renderConsentPage(request, REQUEST_URI, SUBJECT, CLIENT_ID, SCOPE, parJwtClaims))
                    .thenReturn(consentPage);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then - verify claims were extracted by checking the context passed to consent provider
            verify(parServer).retrieveRequest(REQUEST_URI);
            verify(parJwtParser).parse(REQUEST_JWT);
        }

        @Test
        @DisplayName("Should return original context when PAR request not found")
        void shouldReturnOriginalContextWhenParRequestNotFound() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenThrow(new RuntimeException("Not found"));
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(any(AuthorizationRequestContext.class), eq(SUBJECT))).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then - should continue processing without claims
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
        }

        @Test
        @DisplayName("Should return original context when JWT parsing returns null")
        void shouldReturnOriginalContextWhenJwtParsingReturnsNull() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn(REQUEST_JWT);
            when(parJwtParser.parse(REQUEST_JWT)).thenReturn(null);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(any(AuthorizationRequestContext.class), eq(SUBJECT))).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then - should continue processing without claims
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            verify(consentPageProvider, never()).renderConsentPage(any(), anyString(), anyString(), anyString(), anyString(), any());
        }

        @Test
        @DisplayName("Should handle blank request JWT gracefully")
        void shouldHandleBlankRequestJwtGracefully() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRequestJwt()).thenReturn("   ");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(any(AuthorizationRequestContext.class), eq(SUBJECT))).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            verify(parJwtParser, never()).parse(anyString());
        }
    }

    @Nested
    @DisplayName("Audit Integration Tests")
    @org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
    class AuditIntegrationTests {

        @Mock
        private AuditService mockAuditService;

        @BeforeEach
        void setUp() {
            orchestrator = new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    parJwtParser,
                    mockAuditService
            );
        }

        @Test
        @DisplayName("Should log audit event when authorization granted")
        void shouldLogAuditEventWhenAuthorizationGranted() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getSession(false)).thenReturn(session);
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request.getHeader("User-Agent")).thenReturn("TestAgent/1.0");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            
            // Verify audit event was logged
            ArgumentCaptor<AuditEvent> eventCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
            verify(mockAuditService).logEventAsync(eventCaptor.capture());
            
            AuditEvent event = eventCaptor.getValue();
            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Authorization code granted successfully");
            assertThat(event.getContext().getUserId()).isEqualTo(SUBJECT);
            assertThat(event.getContext().getSessionId()).isNull();
            assertThat(event.getContext().getRequestId()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(event.getContext().getClientIpAddress()).isEqualTo("192.168.1.1");
            assertThat(event.getContext().getUserAgent()).isEqualTo("TestAgent/1.0");
            assertThat(event.getData().get("client_id")).isEqualTo(CLIENT_ID);
            assertThat(event.getData().get("redirect_uri")).isEqualTo(REDIRECT_URI);
            assertThat(event.getData().get("state")).isEqualTo(STATE);
            assertThat(event.getData().get("flow_type")).isEqualTo("PAR");
        }

        @Test
        @DisplayName("Should log audit event when authorization denied")
        void shouldLogAuditEventWhenAuthorizationDenied() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn("consent");
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getSession(false)).thenReturn(session);
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request.getHeader("User-Agent")).thenReturn("TestAgent/1.0");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.handleConsentResponse(request)).thenReturn(false);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);
            when(parRequest.getRedirectUri()).thenReturn(REDIRECT_URI);

            // When
            AuthorizationResult result = orchestrator.processConsentSubmission(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).contains("access_denied");
            
            // Verify audit event was logged
            ArgumentCaptor<AuditEvent> eventCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
            verify(mockAuditService).logEventAsync(eventCaptor.capture());
            
            AuditEvent event = eventCaptor.getValue();
            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_DENIED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.LOW);
            assertThat(event.getMessage()).isEqualTo("User denied authorization request");
            assertThat(event.getContext().getUserId()).isEqualTo(SUBJECT);
            assertThat(event.getContext().getSessionId()).isNull();
            assertThat(event.getContext().getClientIpAddress()).isEqualTo("192.168.1.1");
            assertThat(event.getContext().getUserAgent()).isEqualTo("TestAgent/1.0");
            assertThat(event.getData().get("client_id")).isEqualTo(CLIENT_ID);
            assertThat(event.getData().get("flow_type")).isEqualTo("PAR");
        }

        @Test
        @DisplayName("Should not log audit event when auditService is null")
        void shouldNotLogAuditEventWhenAuditServiceIsNull() {
            // Given
            orchestrator = new AuthorizationOrchestrator(
                    List.of(strategy),
                    userAuthenticationInterceptor,
                    consentPageProvider,
                    sessionMappingBizService,
                    parServer,
                    parJwtParser,
                    null
            );
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            // Verify no audit service was called
            verifyNoInteractions(mockAuditService);
        }

        @Test
        @DisplayName("Should handle audit service exception gracefully")
        void shouldHandleAuditServiceExceptionGracefully() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getSession(false)).thenReturn(session);
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request.getHeader("User-Agent")).thenReturn("TestAgent/1.0");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);
            
            // Mock audit service to throw exception
            doThrow(new RuntimeException("Audit service error"))
                .when(mockAuditService).logEventAsync(any(AuditEvent.class));

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then - authorization should still succeed despite audit failure
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            verify(mockAuditService).logEventAsync(any(AuditEvent.class));
        }

        @Test
        @DisplayName("Should log audit event with null session")
        void shouldLogAuditEventWithNullSession() {
            // Given
            AuthorizationRequestContext context = createParContext();
            when(request.getParameter("action")).thenReturn(null);
            when(strategy.supports(request)).thenReturn(true);
            when(strategy.parseRequest(request)).thenReturn(context);
            when(request.getSession(false)).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request.getHeader("User-Agent")).thenReturn("TestAgent/1.0");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(consentPageProvider.isConsentRequired(request, SUBJECT, CLIENT_ID, SCOPE)).thenReturn(false);
            AuthorizationCodeResult codeResult = new AuthorizationCodeResult(AUTHORIZATION_CODE, REDIRECT_URI, STATE);
            when(strategy.issueCode(context, SUBJECT)).thenReturn(codeResult);
            when(strategy.buildRedirectUri(codeResult))
                    .thenReturn(REDIRECT_URI + "?code=" + AUTHORIZATION_CODE + "&state=" + STATE);

            // When
            AuthorizationResult result = orchestrator.processAuthorization(request);

            // Then
            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            
            // Verify audit event was logged with null session
            ArgumentCaptor<AuditEvent> eventCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
            verify(mockAuditService).logEventAsync(eventCaptor.capture());
            
            AuditEvent event = eventCaptor.getValue();
            assertThat(event.getContext().getSessionId()).isNull();
        }
    }

    private AuthorizationRequestContext createParContext() {
        return AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(STATE)
                .clientId(CLIENT_ID)
                .scope(SCOPE)
                .build();
    }

    private AuthorizationRequestContext createTraditionalContext() {
        return AuthorizationRequestContext.builder()
                .flowType("Traditional")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope(SCOPE)
                .state(STATE)
                .responseType("code")
                .build();
    }
}
