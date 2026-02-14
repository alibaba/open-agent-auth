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

import com.alibaba.openagentauth.core.model.oidc.UserInfo;
import com.alibaba.openagentauth.core.protocol.oidc.api.UserInfoProvider;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Default implementation of {@link UserInfoProvider}.
 * <p>
 * This implementation retrieves user information from the UserInfo Endpoint
 * according to the OpenID Connect Core 1.0 specification. It makes authenticated
 * requests using the access token and parses the JSON response.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Supports HTTPS requests</li>
 *   <li>Bearer token authentication</li>
 *   <li>JSON response parsing</li>
 *   <li>Error handling</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 - UserInfo</a>
 * @since 1.0
 */
public class DefaultUserInfoProvider implements UserInfoProvider {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultUserInfoProvider.class);

    /**
     * The ObjectMapper for parsing JSON.
     */
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * The UserInfo Endpoint URL.
     */
    private final String userInfoEndpoint;

    /**
     * The HTTP client for making requests.
     */
    private final HttpClient httpClient;

    /**
     * Creates a new DefaultUserInfoProvider.
     *
     * @param userInfoEndpoint the UserInfo Endpoint URL
     */
    public DefaultUserInfoProvider(String userInfoEndpoint) {

        // Validate parameters
        this.userInfoEndpoint = ValidationUtils.validateNotNull(userInfoEndpoint, "UserInfo endpoint");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        
        logger.info("DefaultUserInfoProvider initialized with endpoint: {}", userInfoEndpoint);
    }

    /**
     * Retrieves user information from the UserInfo Endpoint.
     *
     * @param accessToken the access token
     * @return the user information
     * @throws IdTokenException if retrieval fails
     */
    @Override
    public UserInfo getUserInfo(String accessToken) {
        return getUserInfo(accessToken, null);
    }

    /**
     * Retrieves user information from the UserInfo Endpoint.
     *
     * @param accessToken the access token
     * @param subject the expected subject identifier, or null
     * @return the user information
     * @throws IdTokenException if retrieval fails
     */
    @Override
    public UserInfo getUserInfo(String accessToken, String subject) {

        // Validate parameters
        ValidationUtils.validateNotNull(accessToken, "Access token");
        logger.debug("Retrieving user information from UserInfo Endpoint");

        try {
            // Build the HTTP request
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(userInfoEndpoint))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30));

            HttpRequest request = requestBuilder.build();
            logger.debug("Sending GET request to UserInfo Endpoint");

            // Send the request
            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            // Handle the response
            return switch (response.statusCode()) {
                case 200 -> {
                    logger.debug("Successfully retrieved user information");
                    yield parseUserInfoResponse(response.body(), subject);
                }
                case 401 -> throw new IdTokenException("Invalid access token");
                case 403 -> throw new IdTokenException("Access denied");
                default -> throw new IdTokenException(String.format(
                        "Failed to retrieve user information: HTTP %d - %s",
                        response.statusCode(), response.body())
                );
            };

        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to retrieve user information", e);
            throw new IdTokenException("Failed to retrieve user information: " + e.getMessage(), e);
        }
    }

    /**
     * Parses the UserInfo response.
     * <p>
     * This method parses the JSON response from the UserInfo Endpoint and
     * creates a UserInfo object.
     * </p>
     *
     * @param responseBody the JSON response body
     * @param expectedSubject the expected subject identifier, or null
     * @return the UserInfo object
     * @throws IdTokenException if parsing fails
     */
    private UserInfo parseUserInfoResponse(String responseBody, String expectedSubject) {
        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);

            // Extract the subject
            String sub = rootNode.path("sub").asText();
            if (ValidationUtils.isNullOrEmpty(sub)) {
                throw new IdTokenException("Subject (sub) claim is missing from UserInfo response");
            }

            // Validate subject if expected
            if (expectedSubject != null && !expectedSubject.equals(sub)) {
                throw new IdTokenException(String.format(
                        "Subject mismatch: expected '%s', got '%s'", expectedSubject, sub));
            }

            // Build UserInfo object
            UserInfo.Builder builder = UserInfo.builder()
                    .sub(sub)
                    .name(getOptionalText(rootNode, "name"))
                    .givenName(getOptionalText(rootNode, "given_name"))
                    .familyName(getOptionalText(rootNode, "family_name"))
                    .middleName(getOptionalText(rootNode, "middle_name"))
                    .nickname(getOptionalText(rootNode, "nickname"))
                    .preferredUsername(getOptionalText(rootNode, "preferred_username"))
                    .profile(getOptionalText(rootNode, "profile"))
                    .picture(getOptionalText(rootNode, "picture"))
                    .website(getOptionalText(rootNode, "website"))
                    .email(getOptionalText(rootNode, "email"))
                    .emailVerified(getOptionalBoolean(rootNode, "email_verified"))
                    .gender(getOptionalText(rootNode, "gender"))
                    .birthdate(getOptionalText(rootNode, "birthdate"))
                    .zoneinfo(getOptionalText(rootNode, "zoneinfo"))
                    .locale(getOptionalText(rootNode, "locale"))
                    .phoneNumber(getOptionalText(rootNode, "phone_number"))
                    .phoneNumberVerified(getOptionalBoolean(rootNode, "phone_number_verified"))
                    .updatedAt(getOptionalLong(rootNode, "updated_at"));

            // Parse address if present
            JsonNode addressNode = rootNode.path("address");
            if (!addressNode.isMissingNode()) {
                UserInfo.Address address = new UserInfo.Address(
                        getOptionalText(addressNode, "formatted"),
                        getOptionalText(addressNode, "street_address"),
                        getOptionalText(addressNode, "locality"),
                        getOptionalText(addressNode, "region"),
                        getOptionalText(addressNode, "postal_code"),
                        getOptionalText(addressNode, "country")
                );
                builder.address(address);
            }

            logger.info("Successfully parsed user information for subject: {}", sub);
            return builder.build();

        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to parse UserInfo response", e);
            throw new IdTokenException("Failed to parse UserInfo response: " + e.getMessage(), e);
        }
    }

    /**
     * Gets an optional text field from a JSON node.
     *
     * @param node the JSON node
     * @param fieldName the field name
     * @return the text value, or null if not present
     */
    private String getOptionalText(JsonNode node, String fieldName) {
        JsonNode fieldNode = node.path(fieldName);
        if (fieldNode.isMissingNode() || fieldNode.isNull()) {
            return null;
        }
        return fieldNode.asText();
    }

    /**
     * Gets an optional boolean field from a JSON node.
     *
     * @param node the JSON node
     * @param fieldName the field name
     * @return the boolean value, or null if not present
     */
    private Boolean getOptionalBoolean(JsonNode node, String fieldName) {
        JsonNode fieldNode = node.path(fieldName);
        if (fieldNode.isMissingNode() || fieldNode.isNull()) {
            return null;
        }
        return fieldNode.asBoolean();
    }

    /**
     * Gets an optional long field from a JSON node.
     *
     * @param node the JSON node
     * @param fieldName the field name
     * @return the long value, or null if not present
     */
    private Long getOptionalLong(JsonNode node, String fieldName) {
        JsonNode fieldNode = node.path(fieldName);
        if (fieldNode.isMissingNode() || fieldNode.isNull()) {
            return null;
        }
        return fieldNode.asLong();
    }



}