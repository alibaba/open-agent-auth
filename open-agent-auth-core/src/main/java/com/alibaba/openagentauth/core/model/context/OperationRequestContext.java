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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents contextual information for policy evaluation.
 * This includes user and agent identity attributes, device characteristics, channel, and locale.
 * Serves as input data for Open Policy Agent (OPA) enforcement decisions.
 * <p>
 * The context provides comprehensive information about the request environment,
 * enabling fine-grained authorization decisions based on various factors.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-00</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OperationRequestContext {

    /**
     * The channel through which the request was made.
     * <p>
     * This field identifies the communication channel (e.g., web, mobile, API).
     * </p>
     */
    @JsonProperty("channel")
    private final String channel;

    /**
     * The device fingerprint.
     * <p>
     * This field contains a unique identifier for the device making the request.
     * </p>
     */
    @JsonProperty("device_fingerprint")
    private final String deviceFingerprint;

    /**
     * The language/locale of the request.
     * <p>
     * This field specifies the language or locale (e.g., "en-US", "zh-CN").
     * </p>
     */
    @JsonProperty("language")
    private final String language;

    /**
     * The user-specific context information.
     * <p>
     * This field contains user identity and attributes for policy evaluation.
     * </p>
     */
    @JsonProperty("user")
    private final UserContext user;

    /**
     * The agent-specific context information.
     * <p>
     * This field contains agent instance, platform, and attributes for policy evaluation.
     * </p>
     */
    @JsonProperty("agent")
    private final AgentContext agent;

    private OperationRequestContext(Builder builder) {
        this.channel = builder.channel;
        this.deviceFingerprint = builder.deviceFingerprint;
        this.language = builder.language;
        this.user = builder.user;
        this.agent = builder.agent;
    }

    /**
     * Constructor with all parameters.
     *
     * @param channel the channel through which the request was made
     * @param deviceFingerprint the device fingerprint
     * @param language the language/locale of the request
     * @param user the user-specific context information
     * @param agent the agent-specific context information
     */
    @JsonCreator
    public OperationRequestContext(
            @JsonProperty("channel") String channel,
            @JsonProperty("device_fingerprint") String deviceFingerprint,
            @JsonProperty("language") String language,
            @JsonProperty("user") UserContext user,
            @JsonProperty("agent") AgentContext agent
    ) {
        this.channel = channel;
        this.deviceFingerprint = deviceFingerprint;
        this.language = language;
        this.user = user;
        this.agent = agent;
    }

    /**
     * Gets the channel through which the request was made.
     *
     * @return the channel
     */
    public String getChannel() {
        return channel;
    }

    /**
     * Gets the device fingerprint.
     *
     * @return the device fingerprint
     */
    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    /**
     * Gets the language/locale.
     *
     * @return the language
     */
    public String getLanguage() {
        return language;
    }

    /**
     * Gets the user context.
     *
     * @return the user context
     */
    public UserContext getUser() {
        return user;
    }

    /**
     * Gets the agent context.
     *
     * @return the agent context
     */
    public AgentContext getAgent() {
        return agent;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OperationRequestContext requestContext = (OperationRequestContext) o;
        return Objects.equals(channel, requestContext.channel) &&
               Objects.equals(deviceFingerprint, requestContext.deviceFingerprint) &&
               Objects.equals(language, requestContext.language) &&
               Objects.equals(user, requestContext.user) &&
               Objects.equals(agent, requestContext.agent);
    }

    @Override
    public int hashCode() {
        return Objects.hash(channel, deviceFingerprint, language, user, agent);
    }

    @Override
    public String toString() {
        return "Context{" +
                "channel='" + channel + '\'' +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                ", language='" + language + '\'' +
                ", user=" + user +
                ", agent=" + agent +
                '}';
    }

    /**
     * Creates a new builder for {@link OperationRequestContext}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Represents user-specific context information.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class UserContext {

        /**
         * The user ID.
         * <p>
         * This field contains the unique identifier for the user.
         * </p>
         */
        @JsonProperty("id")
        private final String id;

        private UserContext(Builder builder) {
            this.id = builder.id;
        }

        /**
         * Constructor with all parameters.
         *
         * @param id the user ID
         */
        @JsonCreator
        public UserContext(
                @JsonProperty("id") String id
        ) {
            this.id = id;
        }

        /**
         * Gets the user ID.
         *
         * @return the user ID
         */
        public String getId() {
            return id;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            UserContext that = (UserContext) o;
            return Objects.equals(id, that.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }

        @Override
        public String toString() {
            return "UserContext{" +
                    "id='" + id + '\'' +
                    '}';
        }

        /**
         * Creates a new builder for {@link UserContext}.
         *
         * @return a new builder instance
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Builder for {@link UserContext}.
         */
        public static class Builder {
            private String id;

            /**
             * Sets the user ID.
             *
             * @param id the user ID
             * @return this builder instance
             */
            public Builder id(String id) {
                this.id = id;
                return this;
            }

            /**
             * Builds the {@link UserContext}.
             *
             * @return the built user context
             */
            public UserContext build() {
                return new UserContext(this);
            }
        }
    }

    /**
     * Represents agent-specific context information.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AgentContext {

        /**
         * The agent instance identifier.
         * <p>
         * This field contains the unique identifier for the agent instance.
         * </p>
         */
        @JsonProperty("instance")
        private final String instance;

        /**
         * The platform identifier.
         * <p>
         * This field identifies the platform where the agent is deployed.
         * </p>
         */
        @JsonProperty("platform")
        private final String platform;

        /**
         * The client identifier.
         * <p>
         * This field identifies the client application or service.
         * </p>
         */
        @JsonProperty("client")
        private final String client;

        private AgentContext(Builder builder) {
            this.instance = builder.instance;
            this.platform = builder.platform;
            this.client = builder.client;
        }

        /**
         * Constructor with all parameters.
         *
         * @param instance the agent instance identifier
         * @param platform the platform identifier
         * @param client the client identifier
         */
        @JsonCreator
        public AgentContext(
                @JsonProperty("instance") String instance,
                @JsonProperty("platform") String platform,
                @JsonProperty("client") String client
        ) {
            this.instance = instance;
            this.platform = platform;
            this.client = client;
        }

        /**
         * Gets the agent instance.
         *
         * @return the instance
         */
        public String getInstance() {
            return instance;
        }

        /**
         * Gets the platform.
         *
         * @return the platform
         */
        public String getPlatform() {
            return platform;
        }

        /**
         * Gets the client.
         *
         * @return the client
         */
        public String getClient() {
            return client;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AgentContext that = (AgentContext) o;
            return Objects.equals(instance, that.instance) &&
                   Objects.equals(platform, that.platform) &&
                   Objects.equals(client, that.client);
        }

        @Override
        public int hashCode() {
            return Objects.hash(instance, platform, client);
        }

        @Override
        public String toString() {
            return "AgentContext{" +
                    "instance='" + instance + '\'' +
                    ", platform='" + platform + '\'' +
                    ", client='" + client + '\'' +
                    '}';
        }

        /**
         * Creates a new builder for {@link AgentContext}.
         *
         * @return a new builder instance
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Builder for {@link AgentContext}.
         */
        public static class Builder {
            private String instance;
            private String platform;
            private String client;

            /**
             * Sets the instance.
             *
             * @param instance the instance
             * @return this builder instance
             */
            public Builder instance(String instance) {
                this.instance = instance;
                return this;
            }

            /**
             * Sets the platform.
             *
             * @param platform the platform
             * @return this builder instance
             */
            public Builder platform(String platform) {
                this.platform = platform;
                return this;
            }

            /**
             * Sets the client.
             *
             * @param client the client
             * @return this builder instance
             */
            public Builder client(String client) {
                this.client = client;
                return this;
            }

            /**
             * Builds the {@link AgentContext}.
             *
             * @return the built agent context
             */
            public AgentContext build() {
                return new AgentContext(this);
            }
        }
    }

    /**
     * Builder for {@link OperationRequestContext}.
     */
    public static class Builder {
        private String channel;
        private String deviceFingerprint;
        private String language;
        private UserContext user;
        private AgentContext agent;

        /**
         * Sets the channel.
         *
         * @param channel the channel
         * @return this builder instance
         */
        public Builder channel(String channel) {
            this.channel = channel;
            return this;
        }

        /**
         * Sets the device fingerprint.
         *
         * @param deviceFingerprint the device fingerprint
         * @return this builder instance
         */
        public Builder deviceFingerprint(String deviceFingerprint) {
            this.deviceFingerprint = deviceFingerprint;
            return this;
        }

        /**
         * Sets the language.
         *
         * @param language the language
         * @return this builder instance
         */
        public Builder language(String language) {
            this.language = language;
            return this;
        }

        /**
         * Sets the user context.
         *
         * @param user the user context
         * @return this builder instance
         */
        public Builder user(UserContext user) {
            this.user = user;
            return this;
        }

        /**
         * Sets the agent context.
         *
         * @param agent the agent context
         * @return this builder instance
         */
        public Builder agent(AgentContext agent) {
            this.agent = agent;
            return this;
        }

        /**
         * Builds the {@link OperationRequestContext}.
         *
         * @return the built context
         */
        public OperationRequestContext build() {
            return new OperationRequestContext(this);
        }
    }
}