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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

/**
 * Peer service configuration properties.
 * <p>
 * A "peer" represents another service in the Open Agent Auth trust domain that this
 * service needs to communicate with. By declaring a peer, the framework automatically
 * configures:
 * <ul>
 *   <li>JWKS consumer — fetches the peer's public keys for token verification</li>
 *   <li>Service discovery — registers the peer's base URL for API calls</li>
 * </ul>
 * <p>
 * This eliminates the need to separately configure {@code jwks.consumers} and
 * {@code service-discovery.services} for the same service, reducing configuration
 * duplication significantly.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   peers:
 *     agent-idp:
 *       issuer: http://localhost:8082
 *     authorization-server:
 *       issuer: http://localhost:8085
 * </pre>
 *
 * @since 2.1
 */
public class PeerProperties {

    /**
     * The issuer URL of the peer service.
     * <p>
     * This URL serves as both the OIDC issuer identifier and the base URL for
     * service discovery. The JWKS endpoint is automatically derived as
     * {@code issuer + "/.well-known/jwks.json"}.
     * </p>
     */
    private String issuer;

    /**
     * Whether this peer is enabled.
     * <p>
     * When disabled, the peer's JWKS consumer and service discovery entry
     * will not be configured. Default: {@code true}.
     * </p>
     */
    private boolean enabled = true;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
