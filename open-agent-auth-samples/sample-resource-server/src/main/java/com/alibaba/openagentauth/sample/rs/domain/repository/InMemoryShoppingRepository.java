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
package com.alibaba.openagentauth.sample.rs.domain.repository;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.sample.rs.domain.model.Cart;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory shopping repository.
 * <p>
 * Provides in-memory storage for products, carts, and orders with default initialization data.
 * This is thread-safe and suitable for demonstration and testing purposes.
 * </p>
 *
 * @since 1.0
 */
@Repository
public class InMemoryShoppingRepository {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemoryShoppingRepository.class);
    
    private final Map<String, Product> products;
    private final Map<String, Cart> carts;
    private final Map<String, Order> orders;
    
    /**
     * Creates a new InMemoryShoppingRepository and initializes default data.
     */
    public InMemoryShoppingRepository() {
        this.products = new ConcurrentHashMap<>();
        this.carts = new ConcurrentHashMap<>();
        this.orders = new ConcurrentHashMap<>();
        
        initializeDefaultProducts();
        logger.info("InMemoryShoppingRepository initialized with {} products", products.size());
    }
    
    /**
     * Initializes default product data.
     */
    private void initializeDefaultProducts() {
        // Clothing products
        addProduct(new Product(
                "PROD-001", "Down Jacket A", "clothing", 
                "Excellent warmth, suitable for daily commute", 
                new BigDecimal("599.00"), null
        ));
        addProduct(new Product(
                "PROD-002", "Wool Coat B", "clothing", 
                "Fashionable and versatile, suitable for business", 
                new BigDecimal("899.00"), null
        ));
        addProduct(new Product(
                "PROD-003", "Cotton Jacket C", "clothing", 
                "Lightweight and comfortable, suitable for casual wear", 
                new BigDecimal("399.00"), null
        ));
        addProduct(new Product(
                "PROD-004", "Wool Sweater D", "clothing", 
                "Soft and comfortable, warm and breathable", 
                new BigDecimal("299.00"), null
        ));
        
        // Electronics products
        addProduct(new Product(
                "PROD-005", "Smartphone X", "electronics", 
                "Latest model with advanced features", 
                new BigDecimal("4999.00"), null
        ));
        addProduct(new Product(
                "PROD-006", "Laptop Pro", "electronics", 
                "High performance for professionals", 
                new BigDecimal("8999.00"), null
        ));
        addProduct(new Product(
                "PROD-007", "Wireless Headphones", "electronics", 
                "Noise cancelling, premium sound", 
                new BigDecimal("1299.00"), null
        ));
        addProduct(new Product(
                "PROD-008", "Smart Watch", "electronics", 
                "Fitness tracking and notifications", 
                new BigDecimal("1999.00"), null
        ));
        
        // Books products
        addProduct(new Product(
                "PROD-009", "Java Programming Guide", "books", 
                "Comprehensive Java tutorial", 
                new BigDecimal("89.00"), null
        ));
        addProduct(new Product(
                "PROD-010", "Design Patterns", "books", 
                "Classic software design patterns", 
                new BigDecimal("79.00"), null
        ));
        addProduct(new Product(
                "PROD-011", "Clean Code", "books", 
                "Writing maintainable code", 
                new BigDecimal("69.00"), null
        ));
        addProduct(new Product(
                "PROD-012", "System Design Interview", "books", 
                "System design preparation", 
                new BigDecimal("99.00"), null
        ));
    }
    
    /**
     * Adds a product to the repository.
     *
     * @param product the product to add
     */
    public void addProduct(Product product) {
        products.put(product.getId(), product);
    }
    
    /**
     * Gets a product by ID.
     *
     * @param productId the product ID
     * @return the product, or null if not found
     */
    public Product getProduct(String productId) {
        return products.get(productId);
    }
    
    /**
     * Gets all products.
     *
     * @return list of all products
     */
    public List<Product> getAllProducts() {
        return new ArrayList<>(products.values());
    }
    
    /**
     * Searches products by category and keywords.
     * <p>
     * The keywords parameter supports word-based matching: if multiple words are provided,
     * a product matches if ANY of the words matches the product name or description.
     * This provides a more flexible search experience compared to exact string matching.
     * </p>
     *
     * @param category the product category
     * @param keywords optional search keywords (can contain multiple words separated by spaces)
     * @return list of matching products
     */
    public List<Product> searchProducts(String category, String keywords) {
        return products.values().stream()
                .filter(product -> {
                    boolean categoryMatch = category == null || category.equalsIgnoreCase(product.getCategory());
                    boolean keywordMatch = ValidationUtils.isNullOrEmpty(keywords) ||
                            matchesAnyKeyword(product, keywords);
                    return categoryMatch && keywordMatch;
                })
                .collect(Collectors.toList());
    }
    
    /**
     * Checks if the product matches any of the keywords.
     * <p>
     * This method splits the keywords string into individual words and checks
     * if ANY of them matches the product name or description (case-insensitive).
     * </p>
     *
     * @param product the product to check
     * @param keywords the keywords string (may contain multiple words)
     * @return true if any keyword matches, false otherwise
     */
    private boolean matchesAnyKeyword(Product product, String keywords) {
        if (ValidationUtils.isNullOrEmpty(keywords)) {
            return true;
        }
        
        // Split keywords into individual words and trim whitespace
        String[] keywordArray = keywords.trim().split("\\s+");
        String productName = product.getName().toLowerCase();
        String productDescription = product.getDescription().toLowerCase();
        
        // Check if ANY keyword matches the product name or description
        for (String keyword : keywordArray) {
            String normalizedKeyword = keyword.trim().toLowerCase();
            if (!normalizedKeyword.isEmpty() &&
                (productName.contains(normalizedKeyword) || 
                 productDescription.contains(normalizedKeyword))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Gets or creates a cart for a user.
     *
     * @param userId the user ID
     * @return the user's cart
     */
    public Cart getOrCreateCart(String userId) {
        return carts.computeIfAbsent(userId, Cart::new);
    }
    
    /**
     * Saves a cart.
     *
     * @param cart the cart to save
     */
    public void saveCart(Cart cart) {
        carts.put(cart.getUserId(), cart);
    }
    
    /**
     * Clears a user's cart.
     *
     * @param userId the user ID
     */
    public void clearCart(String userId) {
        carts.remove(userId);
    }
    
    /**
     * Saves an order.
     *
     * @param order the order to save
     */
    public void saveOrder(Order order) {
        orders.put(order.getId(), order);
    }
    
    /**
     * Gets an order by ID.
     *
     * @param orderId the order ID
     * @return the order, or null if not found
     */
    public Order getOrder(String orderId) {
        return orders.get(orderId);
    }
    
    /**
     * Gets all orders for a user.
     *
     * @param userId the user ID
     * @return list of user's orders
     */
    public List<Order> getOrdersByUserId(String userId) {
        return orders.values().stream()
                .filter(order -> order.getUserId().equals(userId))
                .sorted(Comparator.comparing(Order::getCreatedAt).reversed())
                .collect(Collectors.toList());
    }
    
    /**
     * Gets all orders.
     *
     * @return list of all orders
     */
    public List<Order> getAllOrders() {
        return new ArrayList<>(orders.values());
    }
}