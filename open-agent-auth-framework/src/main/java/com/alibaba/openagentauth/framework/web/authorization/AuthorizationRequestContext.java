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

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Objects;

/**
 * Authorization request context.
 * <p>
 * This class encapsulates all authorization request parameters as a data transfer object.
 * It follows the Single Responsibility Principle by only holding request data.
 * </p>
 * <p>
 * <b>Thread Safety:</b> This class is immutable and therefore thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class AuthorizationRequestContext {

    private final String flowType;
    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final String state;
    private final String responseType;
    private final String requestUri;
    private final ParJwtClaims parJwtClaims;

    private AuthorizationRequestContext(Builder builder) {
        this.flowType = builder.flowType;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scope = builder.scope;
        this.state = builder.state;
        this.responseType = builder.responseType;
        this.requestUri = builder.requestUri;
        this.parJwtClaims = builder.parJwtClaims;
    }

    /**
     * Creates a new builder for constructing AuthorizationRequestContext.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    public String getFlowType() {
        return flowType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public ParJwtClaims getParJwtClaims() {
        return parJwtClaims;
    }

    /**
     * Builder for AuthorizationRequestContext.
     * <p>
     * Follows the Builder Pattern for flexible object construction.
     * </p>
     */
    public static final class Builder {
        private String flowType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String responseType;
        private String requestUri;
        private ParJwtClaims parJwtClaims;

        private Builder() {
        }

        public Builder flowType(String flowType) {
            this.flowType = flowType;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public Builder requestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }

        public Builder parJwtClaims(ParJwtClaims parJwtClaims) {
            this.parJwtClaims = parJwtClaims;
            return this;
        }

        /**
         * Builds the AuthorizationRequestContext instance.
         *
         * @return the constructed context
         * @throws IllegalStateException if required fields are missing
         */
        public AuthorizationRequestContext build() {
            if (ValidationUtils.isNullOrEmpty(flowType)) {
                throw new IllegalStateException("flowType is required");
            }
            return new AuthorizationRequestContext(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationRequestContext that = (AuthorizationRequestContext) o;
        return Objects.equals(flowType, that.flowType)
                && Objects.equals(clientId, that.clientId)
                && Objects.equals(redirectUri, that.redirectUri)
                && Objects.equals(scope, that.scope)
                && Objects.equals(state, that.state)
                && Objects.equals(responseType, that.responseType)
                && Objects.equals(requestUri, that.requestUri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(flowType, clientId, redirectUri, scope, state, responseType, requestUri);
    }

    @Override
        public String toString() {
            return "AuthorizationRequestContext{" +
                    "flowType='" + flowType + '\'' +
                    ", clientId='" + clientId + '\'' +
                    ", redirectUri='" + redirectUri + '\'' +
                    ", scope='" + scope + '\'' +
                    ", state='" + state + '\'' +
                    ", responseType='" + responseType + '\'' +
                    ", requestUri='" + requestUri + '\'' +
                    ", parJwtClaims=" + parJwtClaims +
                    '}';
        }
}
