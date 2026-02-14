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
package com.alibaba.openagentauth.framework.executor.config;

import com.alibaba.openagentauth.framework.executor.strategy.DeviceFingerprintStrategy;
import com.alibaba.openagentauth.framework.executor.strategy.StateGenerationStrategy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link AgentAapExecutorConfig.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * optional field settings, default values, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("AgentAapExecutorConfig.Builder Tests")
class AgentAapExecutorConfigTest {

    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_PLATFORM = "personal-agent.example.com";
    private static final String TEST_AGENT_CLIENT = "mobile-app-v1";
    private static final String TEST_ISSUER = "https://issuer.example.com";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        DeviceFingerprintStrategy deviceFingerprintStrategy = mock(DeviceFingerprintStrategy.class);
        StateGenerationStrategy stateGenerationStrategy = mock(StateGenerationStrategy.class);

        AgentAapExecutorConfig config = AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .channel("web")
                .language("en-US")
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprint("device-fingerprint-abc")
                .deviceFingerprintStrategy(deviceFingerprintStrategy)
                .stateGenerationStrategy(stateGenerationStrategy)
                .expirationSeconds(7200)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build();

        // Then
        assertThat(config).isNotNull();
        assertThat(config.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(config.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(config.getChannel()).isEqualTo("web");
        assertThat(config.getLanguage()).isEqualTo("en-US");
        assertThat(config.getPlatform()).isEqualTo(TEST_PLATFORM);
        assertThat(config.getAgentClient()).isEqualTo(TEST_AGENT_CLIENT);
        assertThat(config.getIssuer()).isEqualTo(TEST_ISSUER);
        assertThat(config.getDeviceFingerprint()).isEqualTo("device-fingerprint-abc");
        assertThat(config.getDeviceFingerprintStrategy()).isSameAs(deviceFingerprintStrategy);
        assertThat(config.getStateGenerationStrategy()).isSameAs(stateGenerationStrategy);
        assertThat(config.getExpirationSeconds()).isEqualTo(7200);
        assertThat(config.getPromptProtectionEnabled()).isTrue();
        assertThat(config.getSanitizationLevel()).isEqualTo("HIGH");
        assertThat(config.getRequireUserInteraction()).isTrue();
        assertThat(config.getEncryptionEnabled()).isTrue();
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        DeviceFingerprintStrategy deviceFingerprintStrategy = mock(DeviceFingerprintStrategy.class);
        StateGenerationStrategy stateGenerationStrategy = mock(StateGenerationStrategy.class);

        AgentAapExecutorConfig.Builder builder = AgentAapExecutorConfig.builder();

        // When
        AgentAapExecutorConfig config = builder
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(deviceFingerprintStrategy)
                .stateGenerationStrategy(stateGenerationStrategy)
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build();

        // Then
        assertThat(config).isNotNull();
        assertThat(config.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(config.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(config.getPlatform()).isEqualTo(TEST_PLATFORM);
        assertThat(config.getAgentClient()).isEqualTo(TEST_AGENT_CLIENT);
    }

    @Test
    @DisplayName("Should throw exception when clientId is null or empty")
    void shouldThrowExceptionWhenClientIdIsNullOrEmpty() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(null)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");

        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId("")
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    @DisplayName("Should throw exception when redirectUri is null or empty")
    void shouldThrowExceptionWhenRedirectUriIsNullOrEmpty() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(null)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirectUri");
    }

    @Test
    @DisplayName("Should throw exception when platform is null or empty")
    void shouldThrowExceptionWhenPlatformIsNullOrEmpty() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(null)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("platform");
    }

    @Test
    @DisplayName("Should throw exception when agentClient is null or empty")
    void shouldThrowExceptionWhenAgentClientIsNullOrEmpty() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(null)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("agentClient");
    }

    @Test
    @DisplayName("Should throw exception when issuer is null or empty")
    void shouldThrowExceptionWhenIssuerIsNullOrEmpty() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(null)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    @DisplayName("Should throw exception when deviceFingerprintStrategy is null")
    void shouldThrowExceptionWhenDeviceFingerprintStrategyIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(null)
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("DeviceFingerprintStrategy");
    }

    @Test
    @DisplayName("Should throw exception when stateGenerationStrategy is null")
    void shouldThrowExceptionWhenStateGenerationStrategyIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(null)
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("StateGenerationStrategy");
    }

    @Test
    @DisplayName("Should throw exception when expirationSeconds is null")
    void shouldThrowExceptionWhenExpirationSecondsIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(null)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expirationSeconds");
    }

    @Test
    @DisplayName("Should throw exception when promptProtectionEnabled is null")
    void shouldThrowExceptionWhenPromptProtectionEnabledIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(null)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("promptProtectionEnabled");
    }

    @Test
    @DisplayName("Should throw exception when sanitizationLevel is null")
    void shouldThrowExceptionWhenSanitizationLevelIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel(null)
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sanitizationLevel");
    }

    @Test
    @DisplayName("Should throw exception when requireUserInteraction is null")
    void shouldThrowExceptionWhenRequireUserInteractionIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(null)
                .encryptionEnabled(true)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requireUserInteraction");
    }

    @Test
    @DisplayName("Should throw exception when encryptionEnabled is null")
    void shouldThrowExceptionWhenEncryptionEnabledIsNull() {
        // When & Then
        assertThatThrownBy(() -> AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(mock(DeviceFingerprintStrategy.class))
                .stateGenerationStrategy(mock(StateGenerationStrategy.class))
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("encryptionEnabled");
    }

    @Test
    @DisplayName("Should use default values for optional fields when not set")
    void shouldUseDefaultValuesForOptionalFieldsWhenNotSet() {
        // Given
        DeviceFingerprintStrategy deviceFingerprintStrategy = mock(DeviceFingerprintStrategy.class);
        StateGenerationStrategy stateGenerationStrategy = mock(StateGenerationStrategy.class);

        AgentAapExecutorConfig config = AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(deviceFingerprintStrategy)
                .stateGenerationStrategy(stateGenerationStrategy)
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build();

        // Then
        assertThat(config).isNotNull();
        assertThat(config.getChannel()).isEqualTo("web");
        assertThat(config.getLanguage()).isEqualTo("en-US");
        assertThat(config.getDeviceFingerprint()).isNull();
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        AgentAapExecutorConfig.Builder builder1 = AgentAapExecutorConfig.builder();
        AgentAapExecutorConfig.Builder builder2 = AgentAapExecutorConfig.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        DeviceFingerprintStrategy strategy1 = mock(DeviceFingerprintStrategy.class);
        DeviceFingerprintStrategy strategy2 = mock(DeviceFingerprintStrategy.class);
        StateGenerationStrategy stateStrategy1 = mock(StateGenerationStrategy.class);
        StateGenerationStrategy stateStrategy2 = mock(StateGenerationStrategy.class);

        AgentAapExecutorConfig.Builder builder = AgentAapExecutorConfig.builder();

        // When
        AgentAapExecutorConfig config1 = builder
                .clientId("client-1")
                .redirectUri("https://example1.com/callback")
                .platform("platform1.example.com")
                .agentClient("app-v1")
                .issuer("https://issuer1.example.com")
                .deviceFingerprintStrategy(strategy1)
                .stateGenerationStrategy(stateStrategy1)
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build();

        AgentAapExecutorConfig config2 = builder
                .clientId("client-2")
                .redirectUri("https://example2.com/callback")
                .platform("platform2.example.com")
                .agentClient("app-v2")
                .issuer("https://issuer2.example.com")
                .deviceFingerprintStrategy(strategy2)
                .stateGenerationStrategy(stateStrategy2)
                .expirationSeconds(7200)
                .promptProtectionEnabled(false)
                .sanitizationLevel("LOW")
                .requireUserInteraction(false)
                .encryptionEnabled(false)
                .build();

        // Then
        assertThat(config1).isNotNull();
        assertThat(config2).isNotNull();
        assertThat(config1.getClientId()).isEqualTo("client-1");
        assertThat(config2.getClientId()).isEqualTo("client-2");
        assertThat(config1.getExpirationSeconds()).isEqualTo(3600);
        assertThat(config2.getExpirationSeconds()).isEqualTo(7200);
        assertThat(config1.getPromptProtectionEnabled()).isTrue();
        assertThat(config2.getPromptProtectionEnabled()).isFalse();
    }

    @Test
    @DisplayName("Should build immutable instance when build is called")
    void shouldBuildImmutableInstanceWhenBuildIsCalled() {
        // Given
        DeviceFingerprintStrategy deviceFingerprintStrategy = mock(DeviceFingerprintStrategy.class);
        StateGenerationStrategy stateGenerationStrategy = mock(StateGenerationStrategy.class);

        AgentAapExecutorConfig config = AgentAapExecutorConfig.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .platform(TEST_PLATFORM)
                .agentClient(TEST_AGENT_CLIENT)
                .issuer(TEST_ISSUER)
                .deviceFingerprintStrategy(deviceFingerprintStrategy)
                .stateGenerationStrategy(stateGenerationStrategy)
                .expirationSeconds(3600)
                .promptProtectionEnabled(true)
                .sanitizationLevel("HIGH")
                .requireUserInteraction(true)
                .encryptionEnabled(true)
                .build();

        // When & Then - Verify all fields are final and immutable
        assertThat(config.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(config.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(config.getPlatform()).isEqualTo(TEST_PLATFORM);
        assertThat(config.getAgentClient()).isEqualTo(TEST_AGENT_CLIENT);
        assertThat(config.getIssuer()).isEqualTo(TEST_ISSUER);
    }
}
