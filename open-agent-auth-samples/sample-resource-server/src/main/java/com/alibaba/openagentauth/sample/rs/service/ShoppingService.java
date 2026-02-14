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
package com.alibaba.openagentauth.sample.rs.service;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.sample.rs.domain.model.Cart;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import com.alibaba.openagentauth.sample.rs.domain.repository.InMemoryShoppingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Shopping service.
 * <p>
 * Provides business logic for shopping operations including product search,
 * cart management, and order processing. This service delegates to the
 * repository for data persistence.
 * </p>
 *
 * @since 1.0
 */
@Service
public class ShoppingService {
    
    private static final Logger logger = LoggerFactory.getLogger(ShoppingService.class);
    
    private final InMemoryShoppingRepository repository;
    
    /**
     * Creates a new ShoppingService.
     *
     * @param repository the shopping repository
     */
    public ShoppingService(InMemoryShoppingRepository repository) {
        this.repository = repository;
        logger.info("ShoppingService initialized");
    }
    
    /**
     * Searches products by category and keywords.
     *
     * @param category the product category
     * @param keywords optional search keywords
     * @param userId the user ID for context
     * @return list of matching products
     */
    public List<Product> searchProducts(String category, String keywords, String userId) {
        logger.info("Searching products - userId: {}, category: {}, keywords: {}", 
                   userId, category, keywords);
        return repository.searchProducts(category, keywords);
    }
    
    /**
     * Gets a product by ID.
     *
     * @param productId the product ID
     * @param userId the user ID for context
     * @return the product, or null if not found
     */
    public Product getProduct(String productId, String userId) {
        logger.info("Getting product - userId: {}, productId: {}", userId, productId);
        return repository.getProduct(productId);
    }
    
    /**
     * Adds a product to the user's cart.
     *
     * @param productId the product ID
     * @param quantity the quantity to add
     * @param userId the user ID
     * @return success message
     * @throws IllegalArgumentException if product not found or quantity invalid
     */
    public String addToCart(String productId, int quantity, String userId) {
        logger.info("Adding to cart - userId: {}, productId: {}, quantity: {}", 
                   userId, productId, quantity);
        
        Product product = repository.getProduct(productId);
        ValidationUtils.validateNotNull(product, "Product:" + productId);
        
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive: " + quantity);
        }
        
        Cart cart = repository.getOrCreateCart(userId);
        cart.addItem(productId, product.getName(), quantity, product.getPrice());
        repository.saveCart(cart);
        
        return String.format("Successfully added %d units of product (ID: %s) to cart", 
                            quantity, productId);
    }
    
    /**
     * Gets the user's cart.
     *
     * @param userId the user ID
     * @return the user's cart
     */
    public Cart getCart(String userId) {
        logger.info("Getting cart - userId: {}", userId);
        return repository.getOrCreateCart(userId);
    }
    
    /**
     * Purchases products from the user's cart.
     *
     * @param productId the product ID to purchase
     * @param quantity the quantity to purchase
     * @param userId the user ID
     * @return the created order
     * @throws IllegalArgumentException if product not found or quantity invalid
     */
    public Order purchaseProduct(String productId, int quantity, String userId) {
        logger.info("Purchasing product - userId: {}, productId: {}, quantity: {}", 
                   userId, productId, quantity);
        
        Product product = repository.getProduct(productId);
        ValidationUtils.validateNotNull(product, "Product not found: " + productId);
        
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive: " + quantity);
        }
        
        // Create order item
        Order.OrderItem orderItem = new Order.OrderItem(
                productId, product.getName(), quantity, product.getPrice()
        );
        
        // Create order
        String orderId = generateOrderId();
        Order order = new Order(
                orderId,
                userId,
                List.of(orderItem),
                Order.OrderStatus.PROCESSING,
                LocalDateTime.now()
        );
        
        // Save order
        repository.saveOrder(order);
        
        logger.info("Order created - orderId: {}, userId: {}, totalAmount: {}", 
                   orderId, userId, order.getTotalAmount());
        
        return order;
    }
    
    /**
     * Queries an order by ID.
     *
     * @param orderId the order ID
     * @param userId the user ID for authorization
     * @return the order, or null if not found
     */
    public Order queryOrder(String orderId, String userId) {
        logger.info("Querying order - userId: {}, orderId: {}", userId, orderId);
        Order order = repository.getOrder(orderId);
        
        if (order != null && !order.getUserId().equals(userId)) {
            logger.warn("Unauthorized order access attempt - userId: {}, orderId: {}", userId, orderId);
            return null;
        }
        
        return order;
    }
    
    /**
     * Lists all orders for a user.
     *
     * @param userId the user ID
     * @return list of user's orders
     */
    public List<Order> listOrders(String userId) {
        logger.info("Listing orders - userId: {}", userId);
        return repository.getOrdersByUserId(userId);
    }
    
    /**
     * Generates a unique order ID.
     *
     * @return a unique order ID
     */
    private String generateOrderId() {
        return "ORDER-" + System.currentTimeMillis() + "-" + 
               UUID.randomUUID().toString().substring(0, 8);
    }
}