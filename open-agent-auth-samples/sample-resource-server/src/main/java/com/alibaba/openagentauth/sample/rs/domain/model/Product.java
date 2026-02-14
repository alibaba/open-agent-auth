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
package com.alibaba.openagentauth.sample.rs.domain.model;

import java.math.BigDecimal;

/**
 * Product domain model.
 * <p>
 * Represents a product in the shopping system.
 * </p>
 *
 * @since 1.0
 */
public class Product {
    
    private final String id;
    private final String name;
    private final String category;
    private final String description;
    private final BigDecimal price;
    private final String imageUrl;
    
    /**
     * Creates a new Product.
     *
     * @param id the product ID
     * @param name the product name
     * @param category the product category
     * @param description the product description
     * @param price the product price
     * @param imageUrl the product image URL
     */
    public Product(String id, String name, String category, String description, 
                   BigDecimal price, String imageUrl) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.description = description;
        this.price = price;
        this.imageUrl = imageUrl;
    }
    
    public String getId() {
        return id;
    }
    
    public String getName() {
        return name;
    }
    
    public String getCategory() {
        return category;
    }
    
    public String getDescription() {
        return description;
    }
    
    public BigDecimal getPrice() {
        return price;
    }
    
    public String getImageUrl() {
        return imageUrl;
    }
    
    @Override
    public String toString() {
        return String.format("Product{id='%s', name='%s', category='%s', price=¥%s}", 
                           id, name, category, price);
    }
}
