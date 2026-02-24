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
package com.alibaba.openagentauth.spring.autoconfigure.capability;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Custom condition that checks whether at least one User IDP role is enabled.
 * <p>
 * This condition evaluates to {@code true} when either {@code agent-user-idp} or
 * {@code as-user-idp} role is enabled in the configuration. It is used to guard
 * User IDP-specific beans (such as {@code IdTokenGenerator} and its adapter) from
 * being created in non-User-IDP scenarios like the Authorization Server.
 * </p>
 *
 * <h3>Checked Properties</h3>
 * <ul>
 *   <li>{@code open-agent-auth.roles.agent-user-idp.enabled}</li>
 *   <li>{@code open-agent-auth.roles.as-user-idp.enabled}</li>
 * </ul>
 *
 * @since 1.0
 * @see SharedCapabilityAutoConfiguration
 */
public class UserIdpRoleEnabledCondition extends SpringBootCondition {

    private static final String AGENT_USER_IDP_ENABLED = "open-agent-auth.roles.agent-user-idp.enabled";
    private static final String AS_USER_IDP_ENABLED = "open-agent-auth.roles.as-user-idp.enabled";

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        boolean agentUserIdpEnabled = "true".equalsIgnoreCase(
                context.getEnvironment().getProperty(AGENT_USER_IDP_ENABLED));
        boolean asUserIdpEnabled = "true".equalsIgnoreCase(
                context.getEnvironment().getProperty(AS_USER_IDP_ENABLED));

        if (agentUserIdpEnabled || asUserIdpEnabled) {
            return ConditionOutcome.match("At least one User IDP role is enabled");
        }

        return ConditionOutcome.noMatch("No User IDP role is enabled "
                + "(neither agent-user-idp nor as-user-idp)");
    }
}
