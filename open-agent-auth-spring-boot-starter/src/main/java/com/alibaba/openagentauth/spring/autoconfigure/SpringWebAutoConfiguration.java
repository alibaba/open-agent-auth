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
package com.alibaba.openagentauth.spring.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

/**
 * Auto-configuration for Spring Web components.
 * <p>
 * This configuration class scans the {@code com.alibaba.openagentauth.spring} package
 * to discover and register REST controllers, MVC controllers, and other web components.
 * It enables the framework's HTTP endpoints to be automatically available when
 * the application is a web application.
 * </p>
 * <p>
 * <b>Scanned Components:</b></p>
 * <ul>
 *   <li>REST Controllers - OAuth 2.0 endpoints, OIDC endpoints, etc.</li>
 *   <li>MVC Controllers - Login pages, consent pages, etc.</li>
 *   <li>Web Interceptors - Authentication interceptors</li>
 *   <li>Web Providers - Consent page providers, etc.</li>
 * </ul>
 * <p>
 * <b>Design Pattern:</b> Component Scan Pattern
 * </p>
 *
 * @since 1.0
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ComponentScan(
        basePackages = "com.alibaba.openagentauth.spring",
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.REGEX,
                pattern = "com\\.alibaba\\.openagentauth\\.spring\\.autoconfigure\\.role\\..*"
        )
)
public class SpringWebAutoConfiguration {
    // Component scan handles everything - all components in com.alibaba.openagentauth.spring
    // will be automatically discovered and registered based on their annotations
    // and @ConditionalOn* annotations
}