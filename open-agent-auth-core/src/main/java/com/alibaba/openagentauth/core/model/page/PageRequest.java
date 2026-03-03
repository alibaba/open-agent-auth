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
package com.alibaba.openagentauth.core.model.page;

/**
 * Request model for paginated queries.
 * <p>
 * This class encapsulates pagination parameters for list endpoints.
 * Page numbering starts from 1 (user-facing convention).
 * </p>
 *
 * @since 1.0
 */
public class PageRequest {

    private static final int DEFAULT_PAGE = 1;
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private Integer page;
    private Integer size;

    public PageRequest() {
    }

    public PageRequest(Integer page, Integer size) {
        this.page = page;
        this.size = size;
    }

    /**
     * Gets the page number (1-based). Returns default if null or invalid.
     *
     * @return the normalized page number, always >= 1
     */
    public int getEffectivePage() {
        return (page != null && page >= 1) ? page : DEFAULT_PAGE;
    }

    /**
     * Gets the page size. Returns default if null or invalid, capped at MAX_SIZE.
     *
     * @return the normalized page size, always between 1 and MAX_SIZE
     */
    public int getEffectiveSize() {
        if (size == null || size < 1) {
            return DEFAULT_SIZE;
        }
        return Math.min(size, MAX_SIZE);
    }

    /**
     * Calculates the zero-based offset for database/list slicing.
     *
     * @return the offset
     */
    public int getOffset() {
        return (getEffectivePage() - 1) * getEffectiveSize();
    }

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }
}
