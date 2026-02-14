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
package com.alibaba.openagentauth.core.model.evidence;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents the credential subject of a User Input Evidence Verifiable Credential.
 * This captures the user's original natural-language input and provides context
 * for the evidence.
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4.2, the credential
 * subject contains the following fields:
 * </p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>type</td><td>Type - the evidence type</td><td>REQUIRED</td></tr>
 *   <tr><td>prompt</td><td>Prompt - the user's original natural-language input</td><td>REQUIRED</td></tr>
 *   <tr><td>timestamp</td><td>Timestamp - when the input was received</td><td>REQUIRED</td></tr>
 *   <tr><td>channel</td><td>Channel - the channel through which the input was received</td><td>OPTIONAL</td></tr>
 *   <tr><td>deviceFingerprint</td><td>Device Fingerprint - the device fingerprint</td><td>OPTIONAL</td></tr>
 * </table>
 * <p>
 * The evidence includes the user's prompt, timestamp, channel information,
 * and device fingerprint to establish a complete audit trail.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInputEvidence {

    @JsonProperty("type")
    private final String type;

    @JsonProperty("prompt")
    private final String prompt;

    @JsonProperty("timestamp")
    private final String timestamp;

    @JsonProperty("channel")
    private final String channel;

    @JsonProperty("deviceFingerprint")
    private final String deviceFingerprint;

    /**
     * Private constructor for Builder pattern.
     */
    private UserInputEvidence(Builder builder) {
        this.type = builder.type;
        this.prompt = builder.prompt;
        this.timestamp = builder.timestamp;
        this.channel = builder.channel;
        this.deviceFingerprint = builder.deviceFingerprint;
    }

    /**
     * JSON creator for Jackson deserialization.
     */
    @com.fasterxml.jackson.annotation.JsonCreator
    private UserInputEvidence(
            @com.fasterxml.jackson.annotation.JsonProperty("type") String type,
            @com.fasterxml.jackson.annotation.JsonProperty("prompt") String prompt,
            @com.fasterxml.jackson.annotation.JsonProperty("timestamp") String timestamp,
            @com.fasterxml.jackson.annotation.JsonProperty("channel") String channel,
            @com.fasterxml.jackson.annotation.JsonProperty("deviceFingerprint") String deviceFingerprint) {
        this.type = type;
        this.prompt = prompt;
        this.timestamp = timestamp;
        this.channel = channel;
        this.deviceFingerprint = deviceFingerprint;
    }

    /**
     * Type field.
     * <p>
     * Identifies the type of the evidence.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * </p>
     *
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * Prompt field.
     * <p>
     * Contains the user's original natural-language input.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * This is the core evidence that proves the user's original intent.
     * </p>
     *
     * @return the prompt
     */
    public String getPrompt() {
        return prompt;
    }

    /**
     * Timestamp field.
     * <p>
     * Identifies when the input was received.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * The value MUST conform to ISO 8601 UTC format.
     * </p>
     *
     * @return the timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Channel field.
     * <p>
     * Identifies the channel through which the input was received.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is OPTIONAL.
     * </p>
     *
     * @return the channel
     */
    public String getChannel() {
        return channel;
    }

    /**
     * Device Fingerprint field.
     * <p>
     * Identifies the device fingerprint.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is OPTIONAL.
     * </p>
     *
     * @return the device fingerprint
     */
    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserInputEvidence that = (UserInputEvidence) o;
        return Objects.equals(type, that.type)
                && Objects.equals(prompt, that.prompt)
                && Objects.equals(timestamp, that.timestamp)
                && Objects.equals(channel, that.channel)
                && Objects.equals(deviceFingerprint, that.deviceFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, prompt, timestamp, channel, deviceFingerprint);
    }

    @Override
    public String toString() {
        return "UserInputEvidence{" +
                "type='" + type + '\'' +
                ", prompt='" + prompt + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", channel='" + channel + '\'' +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link UserInputEvidence}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link UserInputEvidence}.
     */
    public static class Builder {
        private String type = "UserInputEvidence";
        private String prompt;
        private String timestamp;
        private String channel = "web";
        private String deviceFingerprint;

        /**
         * Sets the evidence type.
         *
         * @param type the type
         * @return this builder instance
         */
        public Builder type(String type) {
            this.type = type;
            return this;
        }

        /**
         * Sets the user's prompt.
         *
         * @param prompt the prompt
         * @return this builder instance
         */
        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        /**
         * Sets the timestamp.
         *
         * @param timestamp the timestamp
         * @return this builder instance
         */
        public Builder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        /**
         * Sets the timestamp from an Instant.
         *
         * @param timestamp the timestamp
         * @return this builder instance
         */
        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp.toString();
            return this;
        }

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
         * Builds the {@link UserInputEvidence}.
         *
         * @return the built evidence
         */
        public UserInputEvidence build() {
            return new UserInputEvidence(this);
        }
    }
}
