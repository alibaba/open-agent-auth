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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.model.oidc.UserInfo;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DefaultUserInfoProvider}.
 */
@DisplayName("DefaultUserInfoProvider Tests")
class DefaultUserInfoProviderTest {

    private static final String SUBJECT = "user123";
    private static final String ACCESS_TOKEN = "valid-access-token";
    private static final String VALID_SUBJECT = "user123";
    private static final String DIFFERENT_SUBJECT = "user456";

    private HttpServer testServer;
    private DefaultUserInfoProvider userInfoProvider;
    private String testServerUrl;

    @BeforeEach
    void setUp() throws IOException {
        // Start a test HTTP server
        testServer = HttpServer.create(new InetSocketAddress(0), 0);
        testServerUrl = "http://localhost:" + testServer.getAddress().getPort() + "/userinfo";
        userInfoProvider = new DefaultUserInfoProvider(testServerUrl);
    }

    @AfterEach
    void tearDown() {
        if (testServer != null) {
            testServer.stop(0);
        }
    }

    @Test
    @DisplayName("Should successfully retrieve user info")
    void testGetUserInfoSuccess() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": "John Doe",
                "email": "john@example.com",
                "email_verified": true
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            // Verify authorization header
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            assertThat(authHeader).isEqualTo("Bearer " + ACCESS_TOKEN);
            assertThat(exchange.getRequestHeaders().getFirst("Accept")).isEqualTo("application/json");
            
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        assertThat(userInfo.getName()).isEqualTo("John Doe");
        assertThat(userInfo.getEmail()).isEqualTo("john@example.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should retrieve user info with all fields")
    void testGetUserInfoWithAllFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": "John Doe",
                "given_name": "John",
                "family_name": "Doe",
                "middle_name": "William",
                "nickname": "Johnny",
                "preferred_username": "johndoe",
                "profile": "https://example.com/john",
                "picture": "https://example.com/john.jpg",
                "website": "https://example.com",
                "email": "john@example.com",
                "email_verified": true,
                "gender": "male",
                "birthdate": "1990-01-01",
                "zoneinfo": "America/New_York",
                "locale": "en-US",
                "phone_number": "+1-555-1234",
                "phone_number_verified": true,
                "updated_at": 1234567890,
                "address": {
                    "formatted": "123 Main St, New York, NY 10001",
                    "street_address": "123 Main St",
                    "locality": "New York",
                    "region": "NY",
                    "postal_code": "10001",
                    "country": "US"
                }
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        assertThat(userInfo.getName()).isEqualTo("John Doe");
        assertThat(userInfo.getGivenName()).isEqualTo("John");
        assertThat(userInfo.getFamilyName()).isEqualTo("Doe");
        assertThat(userInfo.getMiddleName()).isEqualTo("William");
        assertThat(userInfo.getNickname()).isEqualTo("Johnny");
        assertThat(userInfo.getPreferredUsername()).isEqualTo("johndoe");
        assertThat(userInfo.getProfile()).isEqualTo("https://example.com/john");
        assertThat(userInfo.getPicture()).isEqualTo("https://example.com/john.jpg");
        assertThat(userInfo.getWebsite()).isEqualTo("https://example.com");
        assertThat(userInfo.getEmail()).isEqualTo("john@example.com");
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getGender()).isEqualTo("male");
        assertThat(userInfo.getBirthdate()).isEqualTo("1990-01-01");
        assertThat(userInfo.getZoneinfo()).isEqualTo("America/New_York");
        assertThat(userInfo.getLocale()).isEqualTo("en-US");
        assertThat(userInfo.getPhoneNumber()).isEqualTo("+1-555-1234");
        assertThat(userInfo.getPhoneNumberVerified()).isTrue();
        assertThat(userInfo.getUpdatedAt()).isEqualTo(1234567890L);
        
        assertThat(userInfo.getAddress()).isNotNull();
        assertThat(userInfo.getAddress().getFormatted()).isEqualTo("123 Main St, New York, NY 10001");
        assertThat(userInfo.getAddress().getStreetAddress()).isEqualTo("123 Main St");
        assertThat(userInfo.getAddress().getLocality()).isEqualTo("New York");
        assertThat(userInfo.getAddress().getRegion()).isEqualTo("NY");
        assertThat(userInfo.getAddress().getPostalCode()).isEqualTo("10001");
        assertThat(userInfo.getAddress().getCountry()).isEqualTo("US");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should retrieve user info with minimal fields")
    void testGetUserInfoWithMinimalFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123"
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        assertThat(userInfo.getName()).isNull();
        assertThat(userInfo.getEmail()).isNull();
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should validate subject when provided")
    void testGetUserInfoWithSubjectValidation() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": "John Doe"
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN, VALID_SUBJECT);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should throw exception when subject mismatch")
    void testGetUserInfoWithSubjectMismatch() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": "John Doe"
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN, DIFFERENT_SUBJECT))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Subject mismatch");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should throw exception when subject is missing")
    void testGetUserInfoWithoutSubject() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "name": "John Doe",
                "email": "john@example.com"
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Subject (sub) claim is missing");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should throw exception when access token is null")
    void testGetUserInfoWithNullAccessToken() {
        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Access token");
    }

    @Test
    @DisplayName("Should throw exception when endpoint URL is null")
    void testConstructorWithNullEndpoint() {
        // Act & Assert
        assertThatThrownBy(() -> new DefaultUserInfoProvider(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UserInfo endpoint");
    }

    @Test
    @DisplayName("Should handle HTTP 401 error")
    void testGetUserInfoWithUnauthorizedError() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 401, "Unauthorized");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Invalid access token");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle HTTP 403 error")
    void testGetUserInfoWithForbiddenError() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 403, "Forbidden");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Access denied");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle other HTTP errors")
    void testGetUserInfoWithOtherHttpError() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 500, "Internal Server Error");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Failed to retrieve user information");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle JSON parsing error")
    void testGetUserInfoWithInvalidJson() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, "invalid json {{{");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Failed to parse UserInfo response");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle network error")
    void testGetUserInfoWithNetworkError() throws Exception {
        // Arrange - Create provider with non-existent endpoint
        DefaultUserInfoProvider provider = new DefaultUserInfoProvider("http://localhost:9999/userinfo");

        // Act & Assert
        assertThatThrownBy(() -> provider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Failed to retrieve user information");
    }

    @Test
    @DisplayName("Should parse optional boolean fields correctly")
    void testParseBooleanFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "email_verified": true,
                "phone_number_verified": false
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getEmailVerified()).isTrue();
        assertThat(userInfo.getPhoneNumberVerified()).isFalse();
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should parse optional long fields correctly")
    void testParseLongFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "updated_at": 1234567890
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getUpdatedAt()).isEqualTo(1234567890L);
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle null optional fields")
    void testHandleNullOptionalFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": null,
                "email": null
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        assertThat(userInfo.getName()).isNull();
        assertThat(userInfo.getEmail()).isNull();
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle empty access token")
    void testGetUserInfoWithEmptyAccessToken() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 401, "Unauthorized");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(""))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Invalid access token");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should create provider with valid endpoint")
    void testConstructorWithValidEndpoint() {
        // Act & Assert
        DefaultUserInfoProvider provider = new DefaultUserInfoProvider("https://example.com/userinfo");
        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("Should handle malformed JSON response")
    void testGetUserInfoWithMalformedJson() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, "{invalid json}");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Failed to parse UserInfo response");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle JSON response with extra fields")
    void testGetUserInfoWithExtraFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "name": "John Doe",
                "custom_field": "custom_value",
                "another_custom_field": 123
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getSub()).isEqualTo("user123");
        assertThat(userInfo.getName()).isEqualTo("John Doe");
        // Extra fields should be ignored
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should parse address field")
    void testParseAddressField() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "address": {
                    "formatted": "123 Main St",
                    "street_address": "123 Main St",
                    "locality": "New York",
                    "region": "NY",
                    "postal_code": "10001",
                    "country": "US"
                }
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getAddress()).isNotNull();
        assertThat(userInfo.getAddress().getFormatted()).isEqualTo("123 Main St");
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle partial address fields")
    void testParsePartialAddressFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
                "sub": "user123",
                "address": {
                    "formatted": "123 Main St",
                    "country": "US"
                }
            }
            """;
        
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, jsonResponse);
            latch.countDown();
        });
        testServer.start();

        // Act
        UserInfo userInfo = userInfoProvider.getUserInfo(ACCESS_TOKEN);

        // Assert
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getAddress()).isNotNull();
        assertThat(userInfo.getAddress().getFormatted()).isEqualTo("123 Main St");
        assertThat(userInfo.getAddress().getStreetAddress()).isNull();
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle empty response body")
    void testGetUserInfoWithEmptyResponseBody() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            sendResponse(exchange, 200, "");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo(ACCESS_TOKEN))
                .isInstanceOf(IdTokenException.class);
        latch.await(5, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Should handle whitespace access token")
    void testGetUserInfoWithWhitespaceAccessToken() throws Exception {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        testServer.createContext("/userinfo", exchange -> {
            // Verify the whitespace token is sent as-is
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            assertThat(authHeader).isEqualTo("Bearer   ");
            sendResponse(exchange, 401, "Unauthorized");
            latch.countDown();
        });
        testServer.start();

        // Act & Assert
        assertThatThrownBy(() -> userInfoProvider.getUserInfo("   "))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("Failed to retrieve user information");
        latch.await(5, TimeUnit.SECONDS);
    }

    // Helper method to send HTTP response
    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
}