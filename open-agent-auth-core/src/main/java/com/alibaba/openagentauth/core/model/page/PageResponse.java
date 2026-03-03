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

import java.util.Collections;
import java.util.List;

/**
 * Generic response model for paginated results.
 * <p>
 * This class wraps a page of items along with pagination metadata,
 * providing a consistent response format across all list endpoints.
 * </p>
 *
 * @param <T> the type of items in the page
 * @since 1.0
 */
public class PageResponse<T> {

    private List<T> items;
    private int page;
    private int size;
    private long totalItems;
    private int totalPages;

    public PageResponse() {
    }

    private PageResponse(List<T> items, int page, int size, long totalItems, int totalPages) {
        this.items = items;
        this.page = page;
        this.size = size;
        this.totalItems = totalItems;
        this.totalPages = totalPages;
    }

    /**
     * Creates a PageResponse by slicing a full list according to the given PageRequest.
     * <p>
     * This is a convenience factory method for in-memory pagination.
     * It handles boundary conditions (empty list, out-of-range page) gracefully.
     * </p>
     *
     * @param allItems    the complete list of items
     * @param pageRequest the pagination parameters
     * @param <T>         the item type
     * @return a PageResponse containing the requested page of items
     */
    public static <T> PageResponse<T> of(List<T> allItems, PageRequest pageRequest) {
        if (allItems == null || allItems.isEmpty()) {
            return new PageResponse<>(
                    Collections.emptyList(),
                    pageRequest.getEffectivePage(),
                    pageRequest.getEffectiveSize(),
                    0,
                    0
            );
        }

        int effectivePage = pageRequest.getEffectivePage();
        int effectiveSize = pageRequest.getEffectiveSize();
        long totalItems = allItems.size();
        int totalPages = (int) Math.ceil((double) totalItems / effectiveSize);

        int offset = pageRequest.getOffset();
        if (offset >= allItems.size()) {
            return new PageResponse<>(
                    Collections.emptyList(),
                    effectivePage,
                    effectiveSize,
                    totalItems,
                    totalPages
            );
        }

        int endIndex = Math.min(offset + effectiveSize, allItems.size());
        List<T> pageItems = allItems.subList(offset, endIndex);

        return new PageResponse<>(
                pageItems,
                effectivePage,
                effectiveSize,
                totalItems,
                totalPages
        );
    }

    public List<T> getItems() {
        return items;
    }

    public void setItems(List<T> items) {
        this.items = items;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public long getTotalItems() {
        return totalItems;
    }

    public void setTotalItems(long totalItems) {
        this.totalItems = totalItems;
    }

    public int getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(int totalPages) {
        this.totalPages = totalPages;
    }
}
