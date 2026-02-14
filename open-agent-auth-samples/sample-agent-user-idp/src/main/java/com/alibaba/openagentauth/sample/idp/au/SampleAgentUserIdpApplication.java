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
package com.alibaba.openagentauth.sample.idp.au;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Sample Agent User Identity Provider Application.
 * <p>
 * This is a demonstration application that implements a standard OpenID Connect
 * Identity Provider for the AI Agent platform. It provides user authentication
 * and ID Token issuance capabilities following the OIDC specification.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>OpenID Connect Discovery endpoint</li>
 *   <li>JWKS endpoint for public key distribution</li>
 *   <li>OAuth 2.0 Authorization endpoint</li>
 *   <li>OAuth 2.0 Token endpoint</li>
 *   <li>User authentication with web interface</li>
 *   <li>Support for ES256 (ECDSA-P256) signing algorithm</li>
 * </ul>
 * <p>
 * <b>Port:</b> 8081
 * </p>
 * <p>
 * <b>Demo Users:</b></p>
 * <ul>
 *   <li>alice / password123</li>
 *   <li>bob / password456</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
@SpringBootApplication
@EnableConfigurationProperties
public class SampleAgentUserIdpApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleAgentUserIdpApplication.class, args);
    }
}