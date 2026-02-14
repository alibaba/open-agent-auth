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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Cart domain model.
 * <p>
 * Represents a shopping cart in the shopping system.
 * </p>
 *
 * @since 1.0
 */
public class Cart {
    
    private final String userId;
    private final Map<String, CartItem> items;
    
    /**
     * Cart item domain model.
     */
    public static class CartItem {
        private final String productId;
        private final String productName;
        private final int quantity;
        private final BigDecimal unitPrice;
        
        public CartItem(String productId, String productName, int quantity, BigDecimal unitPrice) {
            this.productId = productId;
            this.productName = productName;
            this.quantity = quantity;
            this.unitPrice = unitPrice;
        }
        
        public String getProductId() {
            return productId;
        }
        
        public String getProductName() {
            return productName;
        }
        
        public int getQuantity() {
            return quantity;
        }
        
        public BigDecimal getUnitPrice() {
            return unitPrice;
        }
        
        public BigDecimal getTotalPrice() {
            return unitPrice.multiply(BigDecimal.valueOf(quantity));
        }
    }
    
    /**
     * Creates a new Cart.
     *
     * @param userId the user ID
     */
    public Cart(String userId) {
        this.userId = userId;
        this.items = new HashMap<>();
    }
    
    public String getUserId() {
        return userId;
    }
    
    /**
     * Adds a product to the cart.
     *
     * @param productId the product ID
     * @param productName the product name
     * @param quantity the quantity to add
     * @param unitPrice the unit price
     */
    public void addItem(String productId, String productName, int quantity, BigDecimal unitPrice) {
        CartItem existingItem = items.get(productId);
        if (existingItem != null) {
            items.put(productId, new CartItem(productId, productName, 
                                            existingItem.getQuantity() + quantity, unitPrice));
        } else {
            items.put(productId, new CartItem(productId, productName, quantity, unitPrice));
        }
    }
    
    /**
     * Removes a product from the cart.
     *
     * @param productId the product ID
     */
    public void removeItem(String productId) {
        items.remove(productId);
    }
    
    /**
     * Updates the quantity of a product in the cart.
     *
     * @param productId the product ID
     * @param quantity the new quantity
     */
    public void updateQuantity(String productId, int quantity) {
        CartItem existingItem = items.get(productId);
        if (existingItem != null) {
            if (quantity <= 0) {
                items.remove(productId);
            } else {
                items.put(productId, new CartItem(productId, existingItem.getProductName(), 
                                                quantity, existingItem.getUnitPrice()));
            }
        }
    }
    
    /**
     * Clears all items from the cart.
     */
    public void clear() {
        items.clear();
    }
    
    /**
     * Gets all items in the cart.
     *
     * @return list of cart items
     */
    public List<CartItem> getItems() {
        return new ArrayList<>(items.values());
    }
    
    /**
     * Gets the total price of all items in the cart.
     *
     * @return total price
     */
    public BigDecimal getTotalPrice() {
        return items.values().stream()
                .map(CartItem::getTotalPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }
    
    /**
     * Gets the total number of items in the cart.
     *
     * @return total item count
     */
    public int getTotalItemCount() {
        return items.values().stream()
                .mapToInt(CartItem::getQuantity)
                .sum();
    }
    
    /**
     * Checks if the cart is empty.
     *
     * @return true if empty, false otherwise
     */
    public boolean isEmpty() {
        return items.isEmpty();
    }
    
    @Override
    public String toString() {
        return String.format("Cart{userId='%s', itemCount=%d, totalPrice=¥%s}", 
                           userId, getTotalItemCount(), getTotalPrice());
    }
}
