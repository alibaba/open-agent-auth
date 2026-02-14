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
package com.alibaba.openagentauth.core.model.context;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents the context claim in an Agent Operation Authorization Token.
 * This provides contextual information for policy evaluation, including
 * rendered text that describes the authorized operation.
 * <p>
 * According to draft-liu-agent-operation-authorization-01, this contains
 * at least the renderedText field, which describes the operation in a
 * human-readable format as presented to the user during consent.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenAuthorizationContext {

    /**
     * The rendered text describing the authorized operation.
     * <p>
     * This field contains the human-readable representation of the operation as shown
     * to the user during the consent process. According to draft-liu-agent-operation-authorization-01,
     * this field is REQUIRED.
     * </p>
     */
    @JsonProperty("rendered_text")
    private final String renderedText;

    private TokenAuthorizationContext(Builder builder) {
        this.renderedText = builder.renderedText;
    }

    /**
     * Gets the rendered text describing the authorized operation.
     * This is the human-readable representation of the operation as shown
     * to the user during the consent process.
     *
     * @return the rendered text
     */
    public String getRenderedText() {
        return renderedText;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenAuthorizationContext that = (TokenAuthorizationContext) o;
        return Objects.equals(renderedText, that.renderedText);
    }

    @Override
    public int hashCode() {
        return Objects.hash(renderedText);
    }

    @Override
    public String toString() {
        return "TokenAuthorizationContext{" +
                "renderedText='" + renderedText + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link TokenAuthorizationContext}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link TokenAuthorizationContext}.
     */
    public static class Builder {
        private String renderedText;

        /**
         * Sets the rendered text.
         *
         * @param renderedText the rendered text
         * @return this builder instance
         */
        public Builder renderedText(String renderedText) {
            this.renderedText = renderedText;
            return this;
        }

        /**
         * Builds the {@link TokenAuthorizationContext}.
         *
         * @return the built context
         */
        public TokenAuthorizationContext build() {
            return new TokenAuthorizationContext(this);
        }
    }
}