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

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.interceptor.LocalUserAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2ConsentController}.
 * <p>
 * This test class verifies the OAuth 2.0 consent page functionality,
 * including consent page display and consent form submission handling.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2ConsentController Tests")
class OAuth2ConsentControllerTest {

    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:test123";
    private static final String CLIENT_ID = "test-client";
    private static final String SCOPE = "openid profile email";
    private static final String SUBJECT = "user123";
    private static final String ACTION_APPROVE = "approve";
    private static final String ACTION_DENY = "deny";

    @Mock
    private LocalUserAuthenticationInterceptor userAuthenticationInterceptor;

    @Mock
    private ConsentPageProvider consentPageProvider;

    @Mock
    private OAuth2ParServer parServer;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private OAuth2ConsentController controller;

    private ParRequest mockParRequest;
    private ParJwtClaims mockParJwtClaims;

    @BeforeEach
    void setUp() {
        mockParRequest = ParRequest.builder()
                .requestJwt("mock-jwt")
                .clientId(CLIENT_ID)
                .redirectUri("https://example.com/callback")
                .responseType("code")
                .state("state123")
                .build();

        mockParJwtClaims = ParJwtClaims.builder()
                .jwtId("jti123")
                .issuer(CLIENT_ID)
                .subject(SUBJECT)
                .state("state123")
                .build();

        lenient().when(request.getRequestURI()).thenReturn("/oauth2/consent");
    }

    @Nested
    @DisplayName("GET /oauth2/consent - Consent Page Display")
    class ConsentPageDisplayTests {

        @Test
        @DisplayName("Should display consent page with PAR claims when authenticated")
        void shouldDisplayConsentPageWithParClaimsWhenAuthenticated() {
            // Arrange
            ModelAndView mockModelAndView = new ModelAndView("consent");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(mockParRequest);
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    eq(CLIENT_ID),
                    anyString(),
                    eq(mockParJwtClaims)
            )).thenReturn(mockModelAndView);

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getViewName()).isEqualTo("consent");
            verify(userAuthenticationInterceptor).authenticate(request);
            verify(parServer).retrieveRequest(REQUEST_URI);
        }

        @Test
        @DisplayName("Should display consent page without PAR claims when authenticated")
        void shouldDisplayConsentPageWithoutParClaimsWhenAuthenticated() {
            // Arrange
            ModelAndView mockModelAndView = new ModelAndView("consent");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(mockParRequest);
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    eq(CLIENT_ID),
                    anyString()
            )).thenReturn(mockModelAndView);

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getViewName()).isEqualTo("consent");
        }

        @Test
        @DisplayName("Should redirect to login when user is not authenticated")
        void shouldRedirectToLoginWhenUserIsNotAuthenticated() {
            // Arrange
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(null);

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getView()).isInstanceOf(RedirectView.class);
            RedirectView redirectView = (RedirectView) result.getView();
            assertThat(redirectView.getUrl()).contains("/login");
            assertThat(redirectView.getUrl()).contains(REQUEST_URI);
        }

        @Test
        @DisplayName("Should handle error when retrieving PAR request")
        void shouldHandleErrorWhenRetrievingParRequest() {
            // Arrange
            ModelAndView mockModelAndView = new ModelAndView("consent");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenThrow(new RuntimeException("PAR request not found"));
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    isNull(),
                    isNull()
            )).thenReturn(mockModelAndView);

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getViewName()).isEqualTo("consent");
        }

        @Test
        @DisplayName("Should handle null PAR request gracefully")
        void shouldHandleNullParRequestGracefully() {
            // Arrange
            ModelAndView mockModelAndView = new ModelAndView("consent");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(null);
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    isNull(),
                    isNull()
            )).thenReturn(mockModelAndView);

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getViewName()).isEqualTo("consent");
        }

        @Test
        @DisplayName("Should return default consent page when provider returns non-ModelAndView")
        void shouldReturnDefaultConsentPageWhenProviderReturnsNonModelAndView() {
            // Arrange
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(mockParRequest);
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    eq(CLIENT_ID),
                    anyString()
            )).thenReturn("custom-consent-view");

            // Act
            ModelAndView result = controller.consentPage(request, REQUEST_URI);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getViewName()).isEqualTo("consent");
        }
    }

    @Nested
    @DisplayName("POST /oauth2/consent - Consent Submission")
    class ConsentSubmissionTests {

        @Test
        @DisplayName("Should redirect to authorization endpoint with approve action")
        void shouldRedirectToAuthorizationEndpointWithApproveAction() {
            // Act
            RedirectView result = controller.handleConsent(REQUEST_URI, ACTION_APPROVE);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUrl()).contains("/oauth2/authorize");
            assertThat(result.getUrl()).contains("request_uri=" + REQUEST_URI);
            assertThat(result.getUrl()).contains("action=" + ACTION_APPROVE);
        }

        @Test
        @DisplayName("Should redirect to authorization endpoint with deny action")
        void shouldRedirectToAuthorizationEndpointWithDenyAction() {
            // Act
            RedirectView result = controller.handleConsent(REQUEST_URI, ACTION_DENY);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUrl()).contains("/oauth2/authorize");
            assertThat(result.getUrl()).contains("request_uri=" + REQUEST_URI);
            assertThat(result.getUrl()).contains("action=" + ACTION_DENY);
        }

        @Test
        @DisplayName("Should handle custom action parameter")
        void shouldHandleCustomActionParameter() {
            // Arrange
            String customAction = "custom";

            // Act
            RedirectView result = controller.handleConsent(REQUEST_URI, customAction);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUrl()).contains("/oauth2/authorize");
            assertThat(result.getUrl()).contains("request_uri=" + REQUEST_URI);
            assertThat(result.getUrl()).contains("action=" + customAction);
        }

        @Test
        @DisplayName("Should URL encode request URI in redirect")
        void shouldUrlEncodeRequestUriInRedirect() {
            // Arrange
            String encodedRequestUri = "urn:ietf:params:oauth:request_uri:encoded%20value";

            // Act
            RedirectView result = controller.handleConsent(encodedRequestUri, ACTION_APPROVE);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUrl()).contains(encodedRequestUri);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle null request URI gracefully")
        void shouldHandleNullRequestUriGracefully() {
            // Act
            ModelAndView result = controller.consentPage(request, null);

            // Assert
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle authentication interceptor exception")
        void shouldHandleAuthenticationInterceptorException() {
            // Arrange
            when(userAuthenticationInterceptor.authenticate(request)).thenThrow(new RuntimeException("Auth error"));

            // Act & Assert
            assertThatThrownBy(() -> controller.consentPage(request, REQUEST_URI))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Auth error");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should successfully handle complete consent flow")
        void shouldSuccessfullyHandleCompleteConsentFlow() {
            // Arrange - Display consent page
            ModelAndView mockModelAndView = new ModelAndView("consent");
            when(userAuthenticationInterceptor.authenticate(request)).thenReturn(SUBJECT);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(mockParRequest);
            lenient().when(consentPageProvider.renderConsentPage(
                    eq(request),
                    eq(REQUEST_URI),
                    eq(SUBJECT),
                    eq(CLIENT_ID),
                    anyString(),
                    eq(mockParJwtClaims)
            )).thenReturn(mockModelAndView);

            // Act - Display consent page
            ModelAndView consentPageResult = controller.consentPage(request, REQUEST_URI);
            assertThat(consentPageResult.getViewName()).isEqualTo("consent");

            // Act - Submit consent
            RedirectView redirectResult = controller.handleConsent(REQUEST_URI, ACTION_APPROVE);

            // Assert
            assertThat(redirectResult.getUrl()).contains("/oauth2/authorize");
            assertThat(redirectResult.getUrl()).contains(ACTION_APPROVE);
        }
    }
}
