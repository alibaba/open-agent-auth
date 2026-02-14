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
package com.alibaba.openagentauth.core.exception;

/**
 * HTTP status codes enumeration.
 * <p>
 * This enum provides standard HTTP status codes used throughout the Open Agent Auth framework.
 * It mirrors the standard HTTP status codes defined in RFC 7231.
 * </p>
 *
 * @since 1.0
 */
public enum HttpStatus {

    // 2xx Success
    /**
     * 200 OK
     */
    OK(200, "OK"),

    /**
     * 201 Created
     */
    CREATED(201, "Created"),

    /**
     * 202 Accepted
     */
    ACCEPTED(202, "Accepted"),

    /**
     * 204 No Content
     */
    NO_CONTENT(204, "No Content"),

    // 3xx Redirection
    /**
     * 301 Moved Permanently
     */
    MOVED_PERMANENTLY(301, "Moved Permanently"),

    /**
     * 302 Found
     */
    FOUND(302, "Found"),

    /**
     * 304 Not Modified
     */
    NOT_MODIFIED(304, "Not Modified"),

    // 4xx Client Error
    /**
     * 400 Bad Request
     */
    BAD_REQUEST(400, "Bad Request"),

    /**
     * 401 Unauthorized
     */
    UNAUTHORIZED(401, "Unauthorized"),

    /**
     * 403 Forbidden
     */
    FORBIDDEN(403, "Forbidden"),

    /**
     * 404 Not Found
     */
    NOT_FOUND(404, "Not Found"),

    /**
     * 405 Method Not Allowed
     */
    METHOD_NOT_ALLOWED(405, "Method Not Allowed"),

    /**
     * 409 Conflict
     */
    CONFLICT(409, "Conflict"),

    /**
     * 422 Unprocessable Entity
     */
    UNPROCESSABLE_ENTITY(422, "Unprocessable Entity"),

    /**
     * 429 Too Many Requests
     */
    TOO_MANY_REQUESTS(429, "Too Many Requests"),

    // 5xx Server Error
    /**
     * 500 Internal Server Error
     */
    INTERNAL_SERVER_ERROR(500, "Internal Server Error"),

    /**
     * 501 Not Implemented
     */
    NOT_IMPLEMENTED(501, "Not Implemented"),

    /**
     * 502 Bad Gateway
     */
    BAD_GATEWAY(502, "Bad Gateway"),

    /**
     * 503 Service Unavailable
     */
    SERVICE_UNAVAILABLE(503, "Service Unavailable"),

    /**
     * 504 Gateway Timeout
     */
    GATEWAY_TIMEOUT(504, "Gateway Timeout");

    private final int value;
    private final String reasonPhrase;

    /**
     * Creates a new HTTP status.
     *
     * @param value the status code value
     * @param reasonPhrase the reason phrase
     */
    HttpStatus(int value, String reasonPhrase) {
        this.value = value;
        this.reasonPhrase = reasonPhrase;
    }

    /**
     * Gets the integer value of this status code.
     *
     * @return the status code value
     */
    public int value() {
        return value;
    }

    /**
     * Gets the reason phrase of this status code.
     *
     * @return the reason phrase
     */
    public String getReasonPhrase() {
        return reasonPhrase;
    }

    /**
     * Returns the HttpStatus enum constant for the given integer value.
     *
     * @param status the integer value
     * @return the HttpStatus enum constant
     * @throws IllegalArgumentException if the value is not a valid HTTP status code
     */
    public static HttpStatus valueOf(int status) {
        for (HttpStatus httpStatus : values()) {
            if (httpStatus.value == status) {
                return httpStatus;
            }
        }
        throw new IllegalArgumentException("No matching constant for [" + status + "]");
    }

    /**
     * Returns whether this status code is in the 2xx range.
     *
     * @return true if the status code is 2xx
     */
    public boolean is2xxSuccessful() {
        return value >= 200 && value < 300;
    }

    /**
     * Returns whether this status code is in the 3xx range.
     *
     * @return true if the status code is 3xx
     */
    public boolean is3xxRedirection() {
        return value >= 300 && value < 400;
    }

    /**
     * Returns whether this status code is in the 4xx range.
     *
     * @return true if the status code is 4xx
     */
    public boolean is4xxClientError() {
        return value >= 400 && value < 500;
    }

    /**
     * Returns whether this status code is in the 5xx range.
     *
     * @return true if the status code is 5xx
     */
    public boolean is5xxServerError() {
        return value >= 500 && value < 600;
    }

    /**
     * Returns whether this status code is an error (4xx or 5xx).
     *
     * @return true if the status code is an error
     */
    public boolean isError() {
        return is4xxClientError() || is5xxServerError();
    }

    @Override
    public String toString() {
        return value + " " + reasonPhrase;
    }
}
