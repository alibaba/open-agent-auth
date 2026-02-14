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
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Order domain model.
 * <p>
 * Represents an order in the shopping system.
 * </p>
 *
 * @since 1.0
 */
public class Order {
    
    private final String id;
    private final String userId;
    private final List<OrderItem> items;
    private final BigDecimal totalAmount;
    private final OrderStatus status;
    private final LocalDateTime createdAt;
    private String shippingAddress;
    private String trackingNumber;
    
    /**
     * Order status enumeration.
     */
    public enum OrderStatus {
        PENDING,
        PROCESSING,
        PAID,
        SHIPPED,
        DELIVERED,
        CANCELLED
    }
    
    /**
     * Order item domain model.
     */
    public static class OrderItem {
        private final String productId;
        private final String productName;
        private final int quantity;
        private final BigDecimal unitPrice;
        
        public OrderItem(String productId, String productName, int quantity, BigDecimal unitPrice) {
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
     * Creates a new Order.
     *
     * @param id the order ID
     * @param userId the user ID
     * @param items the order items
     * @param status the order status
     * @param createdAt the creation time
     */
    public Order(String id, String userId, List<OrderItem> items, 
                 OrderStatus status, LocalDateTime createdAt) {
        this.id = id;
        this.userId = userId;
        this.items = new ArrayList<>(items);
        this.status = status;
        this.createdAt = createdAt;
        this.totalAmount = calculateTotalAmount();
    }
    
    private BigDecimal calculateTotalAmount() {
        return items.stream()
                .map(OrderItem::getTotalPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }
    
    public String getId() {
        return id;
    }
    
    public String getUserId() {
        return userId;
    }
    
    public List<OrderItem> getItems() {
        return new ArrayList<>(items);
    }
    
    public BigDecimal getTotalAmount() {
        return totalAmount;
    }
    
    public OrderStatus getStatus() {
        return status;
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public String getShippingAddress() {
        return shippingAddress;
    }
    
    public void setShippingAddress(String shippingAddress) {
        this.shippingAddress = shippingAddress;
    }
    
    public String getTrackingNumber() {
        return trackingNumber;
    }
    
    public void setTrackingNumber(String trackingNumber) {
        this.trackingNumber = trackingNumber;
    }
    
    @Override
    public String toString() {
        return String.format("Order{id='%s', userId='%s', totalAmount=¥%s, status=%s}", 
                           id, userId, totalAmount, status);
    }
}
