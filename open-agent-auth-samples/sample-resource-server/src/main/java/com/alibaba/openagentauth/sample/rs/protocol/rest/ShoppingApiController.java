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
package com.alibaba.openagentauth.sample.rs.protocol.rest;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.mcp.client.McpAuthContext;
import com.alibaba.openagentauth.mcp.client.McpAuthContextHolder;
import com.alibaba.openagentauth.sample.rs.domain.model.Cart;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST API controller for shopping operations.
 * <p>
 * This controller provides RESTful endpoints for the shopping service,
 * allowing clients to interact with the shopping functionality through
 * standard HTTP methods. It delegates business logic to {@link ShoppingService}.
 * </p>
 *
 * @since 1.0
 */
@RestController
public class ShoppingApiController {
    
    private static final Logger logger = LoggerFactory.getLogger(ShoppingApiController.class);
    
    private final ShoppingService shoppingService;
    
    /**
     * Creates a new ShoppingApiController.
     *
     * @param shoppingService the shopping service
     */
    public ShoppingApiController(ShoppingService shoppingService) {
        this.shoppingService = shoppingService;
    }
    
    /**
     * Searches for products by category and keywords.
     *
     * @param category the product category
     * @param keywords optional search keywords
     * @return list of matching products
     */
    @GetMapping("/api/shopping/products")
    public ResponseEntity<?> searchProducts(
            @RequestParam String category,
            @RequestParam(required = false) String keywords) {
        try {
            String userId = extractUserIdFromAuthContext();
            List<Product> products = shoppingService.searchProducts(category, keywords, userId);
            return ResponseEntity.ok(products);
        } catch (Exception e) {
            logger.error("Error searching products", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Gets a product by ID.
     *
     * @param productId the product ID
     * @return the product details
     */
    @GetMapping("/api/shopping/products/{productId}")
    public ResponseEntity<?> getProduct(@PathVariable String productId) {
        try {
            String userId = extractUserIdFromAuthContext();
            Product product = shoppingService.getProduct(productId, userId);
            if (product == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorResponse("Product not found: " + productId));
            }
            return ResponseEntity.ok(product);
        } catch (Exception e) {
            logger.error("Error getting product", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Adds a product to the user's cart.
     *
     * @param request the add to cart request
     * @return success message
     */
    @PostMapping("/api/shopping/cart/items")
    public ResponseEntity<?> addToCart(@RequestBody AddToCartRequest request) {
        try {
            String userId = extractUserIdFromAuthContext();
            String result = shoppingService.addToCart(
                    request.getProductId(), 
                    request.getQuantity(), 
                    userId
            );
            return ResponseEntity.ok(new SuccessResponse(result));
        } catch (IllegalArgumentException e) {
            logger.error("Invalid add to cart request", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Error adding to cart", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Gets the user's cart.
     *
     * @return the user's cart
     */
    @GetMapping("/api/shopping/cart")
    public ResponseEntity<?> getCart() {
        try {
            String userId = extractUserIdFromAuthContext();
            Cart cart = shoppingService.getCart(userId);
            return ResponseEntity.ok(cart);
        } catch (Exception e) {
            logger.error("Error getting cart", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Purchases a product.
     *
     * @param request the purchase request
     * @return the created order
     */
    @PostMapping("/api/shopping/orders")
    public ResponseEntity<?> purchaseProduct(@RequestBody PurchaseRequest request) {
        try {
            String userId = extractUserIdFromAuthContext();
            Order order = shoppingService.purchaseProduct(
                    request.getProductId(), 
                    request.getQuantity(), 
                    userId
            );
            return ResponseEntity.ok(order);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid purchase request", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Error purchasing product", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Queries an order by ID.
     *
     * @param orderId the order ID
     * @return the order details
     */
    @GetMapping("/api/shopping/orders/{orderId}")
    public ResponseEntity<?> queryOrder(@PathVariable String orderId) {
        try {
            String userId = extractUserIdFromAuthContext();
            Order order = shoppingService.queryOrder(orderId, userId);
            if (order == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorResponse("Order not found: " + orderId));
            }
            return ResponseEntity.ok(order);
        } catch (Exception e) {
            logger.error("Error querying order", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Lists all orders for the user.
     *
     * @return list of user's orders
     */
    @GetMapping("/api/shopping/orders")
    public ResponseEntity<?> listOrders() {
        try {
            String userId = extractUserIdFromAuthContext();
            List<Order> orders = shoppingService.listOrders(userId);
            return ResponseEntity.ok(orders);
        } catch (Exception e) {
            logger.error("Error listing orders", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Extracts user ID from authentication context.
     *
     * @return the user ID
     * @throws IllegalStateException if user ID cannot be extracted
     */
    private String extractUserIdFromAuthContext() {
        try {
            McpAuthContext context = McpAuthContextHolder.getContext();
            if (context != null && context.getAgentOaToken() != null) {
                SignedJWT signedJwt = SignedJWT.parse(context.getAgentOaToken());
                JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();
                String userId = claimsSet.getSubject();
                if (!ValidationUtils.isNullOrEmpty(userId)) {
                    return userId;
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to extract user ID from authentication context: {}", e.getMessage());
        }
        throw new IllegalStateException("Unable to extract user ID from authentication context");
    }
    
    /**
     * Request DTO for adding items to cart.
     */
    public static class AddToCartRequest {
        private String productId;
        private int quantity;
        
        public String getProductId() {
            return productId;
        }
        
        public void setProductId(String productId) {
            this.productId = productId;
        }
        
        public int getQuantity() {
            return quantity;
        }
        
        public void setQuantity(int quantity) {
            this.quantity = quantity;
        }
    }
    
    /**
     * Request DTO for purchasing products.
     */
    public static class PurchaseRequest {
        private String productId;
        private int quantity;
        
        public String getProductId() {
            return productId;
        }
        
        public void setProductId(String productId) {
            this.productId = productId;
        }
        
        public int getQuantity() {
            return quantity;
        }
        
        public void setQuantity(int quantity) {
            this.quantity = quantity;
        }
    }
    
    /**
     * Response DTO for successful operations.
     */
    public static class SuccessResponse {
        private String message;
        
        public SuccessResponse(String message) {
            this.message = message;
        }
        
        public String getMessage() {
            return message;
        }
    }
    
    /**
     * Response DTO for error operations.
     */
    public static class ErrorResponse {
        private String error;
        
        public ErrorResponse(String error) {
            this.error = error;
        }
        
        public String getError() {
            return error;
        }
    }
}
