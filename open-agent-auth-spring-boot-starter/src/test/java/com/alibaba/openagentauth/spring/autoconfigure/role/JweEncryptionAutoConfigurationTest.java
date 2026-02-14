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
package com.alibaba.openagentauth.spring.autoconfigure.role;

import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweDecoder;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweEncoder;
import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptEncryptionService;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JweEncryptionAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of JweEncryptionAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("JweEncryptionAutoConfiguration Tests")
class JweEncryptionAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            JweEncryptionAutoConfiguration.class
        ))
        .withUserConfiguration(TestKeyManagerConfiguration.class)
        .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain");

    @Configuration
    static class TestKeyManagerConfiguration {
        @Bean
        public KeyManager keyManager() throws KeyManagementException {
            KeyManager keyManager = new DefaultKeyManager(new InMemoryKeyStore());
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-id");
            return keyManager;
        }
    }

    @Nested
    @DisplayName("JweEncoder Bean Tests")
    class JweEncoderBeanTests {

        @Test
        @DisplayName("Should create JweEncoder bean when prompt encryption is enabled")
        void shouldCreateJweEncoderBeanWhenPromptEncryptionIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    JweEncoder encoder = context.getBean(JweEncoder.class);
                    assertThat(encoder).isInstanceOf(NimbusJweEncoder.class);
                });
        }

        @Test
        @DisplayName("Should not create JweEncoder bean when prompt encryption is disabled")
        void shouldNotCreateJweEncoderBeanWhenPromptEncryptionIsDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=false"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(JweEncoder.class);
                });
        }

        @Test
        @DisplayName("Should depend on KeyManager bean")
        void shouldDependOnKeyManagerBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    assertThat(context).hasSingleBean(KeyManager.class);
                });
        }
    }

    @Nested
    @DisplayName("JweDecoder Bean Tests")
    class JweDecoderBeanTests {

        @Test
        @DisplayName("Should create JweDecoder bean when prompt encryption is enabled")
        void shouldCreateJweDecoderBeanWhenPromptEncryptionIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweDecoder.class);
                    JweDecoder decoder = context.getBean(JweDecoder.class);
                    assertThat(decoder).isInstanceOf(NimbusJweDecoder.class);
                });
        }

        @Test
        @DisplayName("Should depend on KeyManager bean")
        void shouldDependOnKeyManagerBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweDecoder.class);
                    assertThat(context).hasSingleBean(KeyManager.class);
                });
        }
    }

    @Nested
    @DisplayName("PromptEncryptionService Bean Tests")
    class PromptEncryptionServiceBeanTests {

        @Test
        @DisplayName("Should create PromptEncryptionService bean when prompt encryption is enabled")
        void shouldCreatePromptEncryptionServiceBeanWhenPromptEncryptionIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptEncryptionService.class);
                    PromptEncryptionService service = context.getBean(PromptEncryptionService.class);
                    assertThat(service).isNotNull();
                });
        }

        @Test
        @DisplayName("Should not create PromptEncryptionService bean when prompt encryption is disabled")
        void shouldNotCreatePromptEncryptionServiceBeanWhenPromptEncryptionIsDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=false"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(PromptEncryptionService.class);
                });
        }

        @Test
        @DisplayName("Should depend on JweEncoder bean")
        void shouldDependOnJweEncoderBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptEncryptionService.class);
                    assertThat(context).hasSingleBean(JweEncoder.class);
                });
        }
    }

    @Nested
    @DisplayName("PromptDecryptionService Bean Tests")
    class PromptDecryptionServiceBeanTests {

        @Test
        @DisplayName("Should create PromptDecryptionService bean when prompt encryption is enabled")
        void shouldCreatePromptDecryptionServiceBeanWhenPromptEncryptionIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptDecryptionService.class);
                    PromptDecryptionService service = context.getBean(PromptDecryptionService.class);
                    assertThat(service).isNotNull();
                });
        }

        @Test
        @DisplayName("Should not create PromptDecryptionService bean when prompt encryption is disabled")
        void shouldNotCreatePromptDecryptionServiceBeanWhenPromptEncryptionIsDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=false"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(PromptDecryptionService.class);
                });
        }

        @Test
        @DisplayName("Should depend on JweDecoder bean")
        void shouldDependOnJweDecoderBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptDecryptionService.class);
                    assertThat(context).hasSingleBean(JweDecoder.class);
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when prompt encryption is enabled")
        void shouldLoadWhenPromptEncryptionIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    assertThat(context).hasSingleBean(JweDecoder.class);
                    assertThat(context).hasSingleBean(PromptEncryptionService.class);
                    assertThat(context).hasSingleBean(PromptDecryptionService.class);
                });
        }

        @Test
        @DisplayName("Should not load when prompt encryption is disabled")
        void shouldNotLoadWhenPromptEncryptionIsDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=false"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(JweEncoder.class);
                    assertThat(context).doesNotHaveBean(JweDecoder.class);
                    assertThat(context).doesNotHaveBean(PromptEncryptionService.class);
                    assertThat(context).doesNotHaveBean(PromptDecryptionService.class);
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind AuthorizationServerProperties correctly")
        void shouldBindAuthorizationServerPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    assertThat(context).hasSingleBean(JweDecoder.class);
                });
        }
    }

    @Nested
    @DisplayName("New Properties Integration Tests")
    class NewPropertiesIntegrationTests {

        @Test
        @DisplayName("Should bind PromptEncryptionProperties with new structure")
        void shouldBindPromptEncryptionPropertiesWithNewStructure() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    OperationAuthorizationProperties.PromptEncryptionProperties promptEncryption = properties.getCapabilities().getOperationAuthorization().getPromptEncryption();
                    assertThat(promptEncryption).isNotNull();
                    assertThat(promptEncryption.isEnabled()).isTrue();
                    assertThat(promptEncryption.getEncryptionKeyId()).isEqualTo("test-key-id");
                });
        }
    }

    @Nested
    @DisplayName("JWKS Consumer Tests")
    class JwksConsumerTests {

        @Test
        @DisplayName("Should use local KeyManager when JWKS consumer is not configured")
        void shouldUseLocalKeyManagerWhenJwksConsumerNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    assertThat(context).hasSingleBean(KeyManager.class);
                });
        }

        @Test
        @DisplayName("Should fail when JWKS consumer is configured but not found")
        void shouldFailWhenJwksConsumerIsConfiguredButNotFound() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.jwks-consumer=non-existent-consumer"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure().getMessage())
                        .contains("JWKS consumer not found");
                });
        }
    }

    @Nested
    @DisplayName("Algorithm Configuration Tests")
    class AlgorithmConfigurationTests {

        @Test
        @DisplayName("Should create encoder with RSA-OAEP-256 and A256GCM")
        void shouldCreateEncoderWithRsaOaep256AndA256Gcm() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    JweEncoder encoder = context.getBean(JweEncoder.class);
                    assertThat(encoder).isInstanceOf(NimbusJweEncoder.class);
                });
        }

        @Test
        @DisplayName("Should create decoder with correct key")
        void shouldCreateDecoderWithCorrectKey() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JweDecoder.class);
                    JweDecoder decoder = context.getBean(JweDecoder.class);
                    assertThat(decoder).isInstanceOf(NimbusJweDecoder.class);
                });
        }
    }

    @Nested
    @DisplayName("Bean Dependency Tests")
    class BeanDependencyTests {

        @Test
        @DisplayName("All beans should depend on KeyManager")
        void allBeansShouldDependOnKeyManager() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyManager.class);
                    assertThat(context).hasSingleBean(JweEncoder.class);
                    assertThat(context).hasSingleBean(JweDecoder.class);
                    assertThat(context).hasSingleBean(PromptEncryptionService.class);
                    assertThat(context).hasSingleBean(PromptDecryptionService.class);
                });
        }

        @Test
        @DisplayName("PromptEncryptionService should depend on JweEncoder")
        void promptEncryptionServiceShouldDependOnJweEncoder() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptEncryptionService.class);
                    assertThat(context).hasSingleBean(JweEncoder.class);
                });
        }

        @Test
        @DisplayName("PromptDecryptionService should depend on JweDecoder")
        void promptDecryptionServiceShouldDependOnJweDecoder() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.content-encryption-algorithm=A256GCM"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptDecryptionService.class);
                    assertThat(context).hasSingleBean(JweDecoder.class);
                });
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should fail when encryption key ID is not configured")
        void shouldFailWhenEncryptionKeyIdIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-algorithm=RSA-OAEP-256"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                });
        }
    }
}