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

import com.alibaba.openagentauth.framework.executor.strategy.DeviceFingerprintStrategy;

import java.util.Objects;

/**
 * Default implementation of DeviceFingerprintStrategy.
 * <p>
 * This implementation generates device fingerprints using a simple prefix
 * combined with the workload ID.
 * </p>
 *
 * @since 1.0
 */
public class DefaultDeviceFingerprintStrategy implements DeviceFingerprintStrategy {
    
    private static final String DEFAULT_PREFIX = "dfp_";
    
    private final String prefix;
    
    /**
     * Creates a strategy with default prefix "dfp_".
     */
    public DefaultDeviceFingerprintStrategy() {
        this(DEFAULT_PREFIX);
    }
    
    /**
     * Creates a strategy with custom prefix.
     * 
     * @param prefix the prefix for device fingerprints
     */
    public DefaultDeviceFingerprintStrategy(String prefix) {
        this.prefix = Objects.requireNonNull(prefix, "Prefix cannot be null");
    }
    
    @Override
    public String generate(String workloadId) {
        return prefix + workloadId;
    }
}
