# Sample Resource Server Implementation Guide

This guide demonstrates how to implement a Resource Server (RS) with MCP protocol support using the Open Agent Auth framework. The implementation follows a decoupled architecture that makes it easy to extend and maintain.

## Architecture Overview

The RS architecture is built on three key design patterns:

### 1. Strategy Pattern - McpTool Interface
Each tool is implemented as a separate class implementing the `McpTool` interface. This allows tools to be developed, tested, and maintained independently.

```java
public interface McpTool {
    McpSchema.Tool getDefinition();
    McpSchema.CallToolResult execute(Map<String, Object> arguments);
    String getName();
}
```

### 2. Factory Pattern - ToolRegistry
The `ToolRegistry` manages the lifecycle of tool instances, providing thread-safe registration and retrieval.

```java
ToolRegistry registry = new ToolRegistry();
registry.register(new SearchProductsTool());
registry.register(new AddToCartTool());
```

### 3. Template Method Pattern - AbstractOpenAgentAuthMcpServer
The base class defines the MCP Server lifecycle with hooks for customization.

```java
public abstract class AbstractOpenAgentAuthMcpServer {
    public final void start() {
        initializeServer();
        registerTools();  // Hook for subclasses
        startServer();
    }
    
    protected abstract void registerTools();
    protected abstract McpSchema.Implementation getServerInfo();
}
```

## Project Structure

```
sample-resource-server/
├── src/main/java/com/alibaba/openagentauth/sample/
│   ├── resource/
│   │   ├── server/
│   │   │   └── AbstractOpenAgentAuthMcpServer.java    # Base server class
│   │   └── tool/
│   │       ├── McpTool.java                  # Tool interface
│   │       └── ToolRegistry.java             # Tool management
│   └── shopping/
│       ├── ShoppingMcpServer.java            # Concrete server
│       └── tool/
│           ├── SearchProductsTool.java        # Tool implementations
│           ├── AddToCartTool.java
│           ├── PurchaseProductTool.java
│           └── QueryOrdersTool.java
```

## Step-by-Step Implementation

### Step 1: Create a Tool Implementation

Implement the `McpTool` interface for each tool you want to provide:

```java
public class SearchProductsTool implements McpTool {
    
    private static final String TOOL_NAME = "search_products";
    private static final String TOOL_DESCRIPTION = "Search for products by category and keywords";
    
    @Override
    public McpSchema.Tool getDefinition() {
        return new McpSchema.Tool(
                TOOL_NAME,
                TOOL_DESCRIPTION,
                new McpSchema.JsonSchema(
                        "object",
                        Map.of(
                                "properties", Map.of(
                                        "category", Map.of(
                                                "type", "string",
                                                "description", "Product category"
                                        ),
                                        "keywords", Map.of(
                                                "type", "string",
                                                "description", "Search keywords"
                                        )
                                ),
                                "required", List.of("category")
                        )
                )
        );
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
        // Validate arguments
        String category = (String) arguments.get("category");
        if (category == null || category.trim().isEmpty()) {
            return new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent("Error: Category is required")),
                    true
            );
        }
        
        // Execute tool logic
        String result = searchProducts(category, (String) arguments.get("keywords"));
        
        return new McpSchema.CallToolResult(
                List.of(new McpSchema.TextContent(result)),
                false
        );
    }
    
    @Override
    public String getName() {
        return TOOL_NAME;
    }
    
    private String searchProducts(String category, String keywords) {
        // Your implementation here
        return "Product search results...";
    }
}
```

### Step 2: Create a Concrete MCP Server

Extend `AbstractOpenAgentAuthMcpServer` and register your tools:

```java
@Component
public class ShoppingMcpServer extends AbstractOpenAgentAuthMcpServer {
    
    public ShoppingMcpServer(ResourceServerService resourceServer) {
        super(resourceServer);
    }
    
    @Override
    protected McpSchema.Implementation getServerInfo() {
        return new McpSchema.Implementation("your-server-name", "1.0.0");
    }
    
    @Override
    protected void registerTools() {
        // Register all your tools
        registerTool(new SearchProductsTool());
        registerTool(new AddToCartTool());
        registerTool(new PurchaseProductTool());
        registerTool(new QueryOrdersTool());
    }
}
```

### Step 3: Configure Spring Boot

Add the required dependencies to your `pom.xml`:

```xml
<dependencies>
    <!-- Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- Open Agent Auth Starter -->
    <dependency>
        <groupId>com.alibaba.openagentauth</groupId>
        <artifactId>open-agent-auth-spring-boot-starter</artifactId>
    </dependency>

    <!-- MCP Adapter -->
    <dependency>
        <groupId>com.alibaba.openagentauth</groupId>
        <artifactId>open-agent-auth-mcp-adapter</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

## Key Benefits

### 1. Decoupling
- Each tool is independent and can be developed/tested separately
- Tools can be added or removed without affecting the server structure
- Easy to understand and maintain

### 2. Extensibility
- New tools can be added by implementing `McpTool`
- New MCP Servers can be created by extending `AbstractOpenAgentAuthMcpServer`
- No need to modify existing code when adding new functionality

### 3. Testability
- Each tool can be unit tested independently
- Mock implementations can be easily created for testing
- Clear separation of concerns

### 4. Reusability
- Tool implementations can be reused across different servers
- Common tool logic can be extracted into base classes
- Registry pattern allows dynamic tool management

## Authentication Integration

The architecture integrates with the Open Agent Auth framework for five-layer verification:

1. **Layer 1**: Workload Authentication (WIT validation)
2. **Layer 2**: Request Integrity (WPT validation)
3. **Layer 3**: User Authentication (AOAT validation)
4. **Layer 4**: Identity Consistency (User-Workload binding)
5. **Layer 5**: Policy Evaluation (OPA authorization)

For stdio transport, authentication headers are not available. In production with HTTP transport, the authentication headers would be automatically extracted and validated.

## Best Practices

### 1. Input Validation
Always validate input arguments before processing:

```java
String productId = (String) arguments.get("productId");
if (productId == null || productId.trim().isEmpty()) {
    return errorResult("Product ID is required");
}
```

### 2. Error Handling
Handle exceptions gracefully and return meaningful error messages:

```java
try {
    // Tool logic
} catch (Exception e) {
    logger.error("Error executing tool", e);
    return errorResult("Error: " + e.getMessage());
}
```

### 3. Logging
Log important operations for debugging and auditing:

```java
logger.info("Executing tool: {} with arguments: {}", toolName, arguments);
logger.debug("Tool execution completed successfully");
```

### 4. Documentation
Provide clear descriptions in tool definitions:

```java
new McpSchema.Tool(
    "tool_name",
    "Clear description of what this tool does",
    inputSchema
)
```

## Example: Adding a New Tool

To add a new tool to your server:

1. Create a new class implementing `McpTool`
2. Implement `getDefinition()`, `execute()`, and `getName()`
3. Register the tool in your server's `registerTools()` method

```java
// 1. Create the tool
public class NewTool implements McpTool {
    @Override
    public McpSchema.Tool getDefinition() {
        return new McpSchema.Tool("new_tool", "Description", schema);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
        // Implementation
    }
    
    @Override
    public String getName() {
        return "new_tool";
    }
}

// 2. Register in server
@Override
protected void registerTools() {
    registerTool(new NewTool());
}
```

## Running the Server

Start your Spring Boot application:

```bash
mvn spring-boot:run
```

The MCP Server will be available via stdio transport, allowing AI agents to connect and invoke your tools.

## Conclusion

This architecture provides a clean, maintainable, and extensible foundation for implementing Resource Servers with MCP protocol support. By following the patterns and best practices outlined in this guide, you can easily create new tools and servers without modifying existing code.
