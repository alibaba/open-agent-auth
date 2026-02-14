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
package com.alibaba.openagentauth.core.protocol.oidc.builder;

import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for IdTokenBuilder.
 * <p>
 * This test class verifies the functionality of building ID Tokens with
 * fluent API.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("IdTokenBuilder Tests")
class IdTokenBuilderTest {

    @Mock
    private IdTokenGenerator generator;

    private IdTokenBuilder builder;

    @BeforeEach
    void setUp() {
        builder = IdTokenBuilder.create(generator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create builder with valid generator")
        void shouldCreateBuilderWithValidGenerator() {
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when generator is null")
        void shouldThrowExceptionWhenGeneratorIsNull() {
            assertThatThrownBy(() -> IdTokenBuilder.create(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ID Token generator");
        }
    }

    @Nested
    @DisplayName("Builder Methods Tests")
    class BuilderMethodsTests {

        @Test
        @DisplayName("Should set issuer")
        void shouldSetIssuer() {
            IdTokenBuilder result = builder.issuer("https://example.com");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder); // Fluent API
        }

        @Test
        @DisplayName("Should set subject")
        void shouldSetSubject() {
            IdTokenBuilder result = builder.subject("user123");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set audience")
        void shouldSetAudience() {
            IdTokenBuilder result = builder.audience("client123");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set nonce")
        void shouldSetNonce() {
            IdTokenBuilder result = builder.nonce("abc123");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set authTime with Long")
        void shouldSetAuthTimeWithLong() {
            IdTokenBuilder result = builder.authTime(1234567890L);
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set authTime with Instant")
        void shouldSetAuthTimeWithInstant() {
            Instant instant = Instant.now();
            IdTokenBuilder result = builder.authTime(instant);
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set acr")
        void shouldSetAcr() {
            IdTokenBuilder result = builder.acr("urn:mace:incommon:iap:silver");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set amr")
        void shouldSetAmr() {
            String[] amr = {"pwd", "mfa"};
            IdTokenBuilder result = builder.amr(amr);
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set azp")
        void shouldSetAzp() {
            IdTokenBuilder result = builder.azp("client123");
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should set lifetime")
        void shouldSetLifetime() {
            IdTokenBuilder result = builder.lifetime(7200);
            
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(builder);
        }
    }

    @Nested
    @DisplayName("Build Tests")
    class BuildTests {

        @Test
        @DisplayName("Should build ID token with required fields")
        void shouldBuildIdTokenWithRequiredFields() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), eq(3600L)))
                    .thenReturn(mockToken);

            IdToken result = builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .build();

            assertThat(result).isNotNull();
            verify(generator).generate(any(IdTokenClaims.class), eq(3600L));
        }

        @Test
        @DisplayName("Should throw exception when issuer is missing")
        void shouldThrowExceptionWhenIssuerIsMissing() {
            assertThatThrownBy(() -> builder
                    .subject("user123")
                    .audience("client123")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("issuer is required");
        }

        @Test
        @DisplayName("Should throw exception when subject is missing")
        void shouldThrowExceptionWhenSubjectIsMissing() {
            assertThatThrownBy(() -> builder
                    .issuer("https://example.com")
                    .audience("client123")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("subject is required");
        }

        @Test
        @DisplayName("Should throw exception when audience is missing")
        void shouldThrowExceptionWhenAudienceIsMissing() {
            assertThatThrownBy(() -> builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("audience is required");
        }

        @Test
        @DisplayName("Should build ID token with optional fields")
        void shouldBuildIdTokenWithOptionalFields() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), eq(7200L)))
                    .thenReturn(mockToken);

            Instant authTime = Instant.now().minusSeconds(300);
            String[] amr = {"pwd", "mfa"};

            IdToken result = builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .nonce("abc123")
                    .authTime(authTime)
                    .acr("urn:mace:incommon:iap:silver")
                    .amr(amr)
                    .azp("client123")
                    .lifetime(7200)
                    .build();

            assertThat(result).isNotNull();
            verify(generator).generate(any(IdTokenClaims.class), eq(7200L));
        }

        @Test
        @DisplayName("Should use default lifetime when not specified")
        void shouldUseDefaultLifetimeWhenNotSpecified() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), eq(3600L)))
                    .thenReturn(mockToken);

            builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .build();

            verify(generator).generate(any(IdTokenClaims.class), eq(3600L));
        }

        @Test
        @DisplayName("Should use custom lifetime when specified")
        void shouldUseCustomLifetimeWhenSpecified() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), eq(5400L)))
                    .thenReturn(mockToken);

            builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .lifetime(5400)
                    .build();

            verify(generator).generate(any(IdTokenClaims.class), eq(5400L));
        }

        @Test
        @DisplayName("Should include iat claim")
        void shouldIncludeIatClaim() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), anyLong()))
                    .thenReturn(mockToken);

            builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .build();

            verify(generator).generate(any(IdTokenClaims.class), eq(3600L));
        }

        @Test
        @DisplayName("Should include authTime claim when not specified")
        void shouldIncludeAuthTimeClaimWhenNotSpecified() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), anyLong()))
                    .thenReturn(mockToken);

            builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .build();

            verify(generator).generate(any(IdTokenClaims.class), eq(3600L));
        }

        @Test
        @DisplayName("Should use custom authTime when specified")
        void shouldUseCustomAuthTimeWhenSpecified() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), anyLong()))
                    .thenReturn(mockToken);

            Long customAuthTime = 1234567890L;
            builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .authTime(customAuthTime)
                    .build();

            verify(generator).generate(any(IdTokenClaims.class), eq(3600L));
        }
    }

    @Nested
    @DisplayName("Fluent API Tests")
    class FluentApiTests {

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            IdToken mockToken = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), anyLong()))
                    .thenReturn(mockToken);

            IdToken result = builder
                    .issuer("https://example.com")
                    .subject("user123")
                    .audience("client123")
                    .nonce("abc123")
                    .acr("acr_value")
                    .azp("client123")
                    .lifetime(7200)
                    .build();

            assertThat(result).isNotNull();
            verify(generator).generate(any(IdTokenClaims.class), eq(7200L));
        }

        @Test
        @DisplayName("Should allow multiple builder instances")
        void shouldAllowMultipleBuilderInstances() {
            IdToken mockToken1 = mock(IdToken.class);
            IdToken mockToken2 = mock(IdToken.class);
            when(generator.generate(any(IdTokenClaims.class), anyLong()))
                    .thenReturn(mockToken1, mockToken2);

            IdToken result1 = builder
                    .issuer("https://example.com")
                    .subject("user1")
                    .audience("client1")
                    .build();

            IdToken result2 = builder
                    .issuer("https://example.com")
                    .subject("user2")
                    .audience("client2")
                    .build();

            assertThat(result1).isNotNull();
            assertThat(result2).isNotNull();
            verify(generator, times(2)).generate(any(IdTokenClaims.class), eq(3600L));
        }
    }
}