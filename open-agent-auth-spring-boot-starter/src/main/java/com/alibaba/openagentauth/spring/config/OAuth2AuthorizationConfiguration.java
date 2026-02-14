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
package com.alibaba.openagentauth.spring.config;

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtParser;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.authorization.AuthorizationFlowStrategy;
import com.alibaba.openagentauth.framework.web.authorization.AuthorizationOrchestrator;
import com.alibaba.openagentauth.framework.web.authorization.ParAuthorizationFlowStrategy;
import com.alibaba.openagentauth.framework.web.authorization.TraditionalAuthorizationFlowStrategy;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Configuration class for OAuth 2.0 authorization components.
 * <p>
 * This configuration class sets up the authorization flow strategies and
 * orchestrator, following the Dependency Injection pattern. It enables
 * loose coupling and makes the system easy to test and extend.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Dependency Injection + Strategy Pattern
 * </p>
 * <p>
 * <b>Bean Definitions:</b></p>
 * <ul>
 *   <li>{@link ParAuthorizationFlowStrategy} - Handles PAR flow requests</li>
 *   <li>{@link TraditionalAuthorizationFlowStrategy} - Handles traditional OAuth 2.0 flow</li>
 *   <li>{@link AuthorizationOrchestrator} - Coordinates authorization workflow</li>
 * </ul>
 *
 * @since 1.0
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnExpression("'${open-agent-auth.roles.agent-user-idp.enabled:false}' == 'true' or '${open-agent-auth.roles.authorization-server.enabled:false}' == 'true' or '${open-agent-auth.roles.as-user-idp.enabled:false}' == 'true'")
public class OAuth2AuthorizationConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationConfiguration.class);

    /**
     * Creates the PAR authorization flow strategy bean.
     * <p>
     * This strategy handles Pushed Authorization Request (PAR) flow as defined
     * in RFC 9126. It is automatically enabled when PAR components are available.
     * </p>
     *
     * @param authorizationServer the authorization server
     * @param parServer the PAR server
     * @return the PAR authorization flow strategy, or null if PAR components are not available
     */
    @Bean
    public AuthorizationFlowStrategy parAuthorizationFlowStrategy(
            OAuth2AuthorizationServer authorizationServer,
            OAuth2ParServer parServer) {
        // Only create PAR strategy if PAR components are available
        if (authorizationServer != null && parServer != null) {
            return new ParAuthorizationFlowStrategy(authorizationServer, parServer);
        }
        return null;
    }

    /**
     * Creates the traditional authorization flow strategy bean.
     * <p>
     * This strategy handles standard OAuth 2.0 authorization code flow as defined
     * in RFC 6749. It is always available for authorization server roles.
     * </p>
     *
     * @param authorizationServer the authorization server
     * @return the traditional authorization flow strategy
     */
    @Bean
    public AuthorizationFlowStrategy traditionalAuthorizationFlowStrategy(
            OAuth2AuthorizationServer authorizationServer) {
        return new TraditionalAuthorizationFlowStrategy(authorizationServer);
    }

    /**
     * Creates the SessionMappingStore bean if not already defined.
     * <p>
     * This store provides the underlying storage for session mappings.
     * Default implementation uses in-memory storage.
     * </p>
     *
     * @return the Session Mapping Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingStore sessionMappingStore() {
        logger.info("Creating SessionMappingStore bean");
        return new InMemorySessionMappingStore();
    }

    /**
     * Creates the SessionMappingBizService bean if not already defined.
     * <p>
     * This service provides high-level session mapping operations with business logic.
     * </p>
     *
     * @param sessionMappingStore the session mapping store
     * @return the Session Mapping Business Service bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingBizService sessionMappingBizService(
        SessionMappingStore sessionMappingStore
    ) {
        logger.info("Creating SessionMappingBizService bean");
        return new SessionMappingBizService(sessionMappingStore);
    }




    /**
     * Creates the authorization orchestrator bean.
     * <p>
     * The orchestrator coordinates the authorization workflow, delegating to
     * appropriate strategies based on the request type. It aggregates all
     * available strategies and provides a unified interface for authorization
     * processing.
     * </p>
     *
     * @param strategies the list of available authorization flow strategies
     * @param userAuthenticationInterceptor the user authentication interceptor (optional)
     * @param consentPageProvider the consent page provider
     * @param sessionMappingBizService the session mapping business service
     * @param parServer the PAR server (can be null)
     * @param auditService the audit service (can be null)
     * @return the authorization orchestrator
     */
    @Bean
    public AuthorizationOrchestrator authorizationOrchestrator(
            List<AuthorizationFlowStrategy> strategies,
            Optional<UserAuthenticationInterceptor> userAuthenticationInterceptor,
            ConsentPageProvider consentPageProvider,
            SessionMappingBizService sessionMappingBizService,
            OAuth2ParServer parServer,
            Optional<AuditService> auditService
    ) {
        // Filter out null strategies (e.g., when PAR components are not available)
        List<AuthorizationFlowStrategy> nonNullStrategies = strategies.stream()
                .filter(Objects::nonNull)
                .toList();

        return new AuthorizationOrchestrator(
                nonNullStrategies,
                userAuthenticationInterceptor.orElse(null),
                consentPageProvider,
                sessionMappingBizService,
                parServer,
                new AapParJwtParser(),
                auditService.orElse(null)
        );
    }
}