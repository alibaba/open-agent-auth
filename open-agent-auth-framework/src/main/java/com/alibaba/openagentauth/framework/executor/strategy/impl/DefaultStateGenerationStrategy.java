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
package com.alibaba.openagentauth.framework.executor.strategy.impl;

import com.alibaba.openagentauth.framework.executor.strategy.StateGenerationStrategy;

import java.util.UUID;

/**
 * Default implementation of StateGenerationStrategy.
 * <p>
 * This implementation generates state parameters using a format of
 * "agent:UUID:sessionId" when sessionId is provided, otherwise "agent:UUID".
 * </p>
 *
 * @since 1.0
 */
public class DefaultStateGenerationStrategy implements StateGenerationStrategy {
    
    private static final String PREFIX = "agent:";
    private static final String SEPARATOR = ":";
    
    @Override
    public String generate(String sessionId) {
        String uuid = UUID.randomUUID().toString();
        if (sessionId != null && !sessionId.isEmpty()) {
            return PREFIX + uuid + SEPARATOR + sessionId;
        }
        return PREFIX + uuid;
    }
}
