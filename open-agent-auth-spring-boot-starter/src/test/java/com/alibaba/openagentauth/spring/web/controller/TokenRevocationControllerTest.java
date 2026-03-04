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

import com.alibaba.openagentauth.core.protocol.oauth2.token.revocation.TokenRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("TokenRevocationController Tests")
class TokenRevocationControllerTest {

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private HttpServletRequest request;

    private TokenRevocationController controller;

    @BeforeEach
    void setUp() {
        controller = new TokenRevocationController(tokenRevocationService);
    }

    @Nested
    @DisplayName("POST /oauth2/revoke - Success Scenarios")
    class SuccessScenarios {

        @Test
        @DisplayName("Should return 200 when token is revoked successfully")
        void shouldReturn200WhenTokenRevokedSuccessfully() {
            when(request.getParameter("token")).thenReturn("valid-access-token");
            when(request.getParameter("token_type_hint")).thenReturn("access_token");

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            verify(tokenRevocationService).revoke("valid-access-token");
        }

        @Test
        @DisplayName("Should return 200 without token_type_hint")
        void shouldReturn200WithoutTokenTypeHint() {
            when(request.getParameter("token")).thenReturn("valid-access-token");
            when(request.getParameter("token_type_hint")).thenReturn(null);

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            verify(tokenRevocationService).revoke("valid-access-token");
        }

        @Test
        @DisplayName("Should return 200 for idempotent revocation per RFC 7009")
        void shouldReturn200ForIdempotentRevocation() {
            when(request.getParameter("token")).thenReturn("already-revoked-token");
            when(request.getParameter("token_type_hint")).thenReturn(null);

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Nested
    @DisplayName("POST /oauth2/revoke - Error Scenarios")
    class ErrorScenarios {

        @Test
        @DisplayName("Should return 400 when token parameter is missing")
        void shouldReturn400WhenTokenMissing() {
            when(request.getParameter("token")).thenReturn(null);

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
        }

        @Test
        @DisplayName("Should return 400 when token parameter is empty")
        void shouldReturn400WhenTokenEmpty() {
            when(request.getParameter("token")).thenReturn("");

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
        }

        @Test
        @DisplayName("Should return 400 when token parameter is blank")
        void shouldReturn400WhenTokenBlank() {
            when(request.getParameter("token")).thenReturn("   ");

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
        }

        @Test
        @DisplayName("Should return 500 when service throws exception")
        void shouldReturn500WhenServiceThrowsException() {
            when(request.getParameter("token")).thenReturn("valid-token");
            when(request.getParameter("token_type_hint")).thenReturn(null);
            doThrow(new RuntimeException("Storage error")).when(tokenRevocationService).revoke("valid-token");

            ResponseEntity<Map<String, Object>> response = controller.revoke(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).containsEntry("error", "server_error");
        }
    }
}
