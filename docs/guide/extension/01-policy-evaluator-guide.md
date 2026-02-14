# Policy Evaluator Guide

## Introduction

The Open Agent Auth framework provides a flexible and extensible policy evaluation engine that supports multiple policy types to meet diverse authorization requirements. This guide will walk you through the various policy evaluators available in the framework, their use cases, and how to configure and use them effectively in your applications. The policy evaluation system is designed to be pluggable, allowing you to choose the right evaluator for your specific needs while maintaining a consistent interface across all implementations.

## Policy Evaluator Interface

At the core of the policy evaluation system is the `PolicyEvaluator` interface, which defines the contract for all policy evaluation implementations. This interface provides two main methods for evaluating policies: a simple boolean evaluation and a detailed evaluation that returns comprehensive information about the decision. The interface follows the Interface Segregation Principle, focusing solely on evaluation operations while delegating policy storage and management to the `PolicyRegistry`. This separation of concerns allows for independent evolution of policy storage and evaluation logic. All policy evaluators in the framework implement this interface, ensuring consistency and interoperability. The evaluation process typically involves retrieving the policy from the registry, compiling or parsing it as needed, evaluating it against the provided input data, and returning an authorization decision. The input data is usually a map containing operation context, user information, workload identity, and other relevant data needed for making authorization decisions.

## Policy Builder Compatibility

It is important to understand that different PolicyEvaluator implementations require different PolicyBuilder implementations to generate policies in the correct format. The framework provides a PolicyBuilder interface that defines the contract for generating policies from authorization requests. Each PolicyEvaluator expects policies in a specific format, and using the wrong PolicyBuilder will result in evaluation failures. The Lightweight Policy Evaluator works with the default PolicyBuilder implementation which generates standard Rego policies. The OPA REST Policy Evaluator requires the OpaPolicyBuilder which generates Rego policies formatted specifically for OPA evaluation with proper package structure. The RAM Policy Evaluator requires the RamPolicyBuilder which generates JSON-formatted policies with statements, actions, and resources following the IAM-style policy model. The ACL Policy Evaluator requires the AclPolicyBuilder which generates JSON-formatted policies with principal-resource-permission mappings. The Scope Policy Evaluator requires the ScopePolicyBuilder which generates JSON-formatted policies with scope definitions and resources following OAuth 2.0 standards. When creating policies programmatically, ensure you use the correct PolicyBuilder for your chosen PolicyEvaluator to avoid format mismatches and evaluation errors.

## Custom Policy Evaluators and Builders

The Open Agent Auth framework is designed to be extensible, allowing you to create custom PolicyEvaluator and PolicyBuilder implementations to meet your specific authorization requirements. If the built-in evaluators and builders do not fully address your needs, you can implement your own by following the framework's extension points. To create a custom PolicyEvaluator, implement the PolicyEvaluator interface which requires two methods: evaluate for simple boolean evaluation and evaluateWithDetails for detailed evaluation results. Your custom evaluator can integrate with any policy engine or evaluation logic that suits your requirements. For example, you might create an evaluator that integrates with XACML, or one that uses machine learning models for dynamic authorization decisions. When implementing a custom evaluator, ensure thread-safety if the evaluator will be used in concurrent environments, and consider implementing caching mechanisms to improve performance for repeated evaluations. Similarly, you can create custom PolicyBuilder implementations to generate policies in formats specific to your custom evaluator or to integrate with external policy management systems. Implement the PolicyBuilder interface with the buildPolicy method that accepts a RequestAuthUrlRequest and returns a policy string. Your custom builder can generate policies in any format, including XML, YAML, or custom JSON structures, as long as your custom PolicyEvaluator can parse and evaluate them correctly. This flexibility allows you to integrate with legacy policy systems, support domain-specific policy languages, or implement advanced policy composition strategies. Custom evaluators and builders can be registered with the framework through Spring Boot configuration or programmatic registration, enabling seamless integration with the rest of the authorization infrastructure. When creating custom implementations, follow the framework's best practices for error handling, logging, and performance optimization to ensure robust and maintainable code.

## Available Policy Evaluators

### Lightweight Policy Evaluator

The Lightweight Policy Evaluator is a built-in, embedded policy evaluation engine that uses Rego (the policy language from Open Policy Agent) for defining authorization rules. This evaluator is ideal for scenarios where you need a simple, self-contained solution without external dependencies. It provides full Rego language support while being lightweight and fast, making it perfect for microservices and edge computing environments.

#### Evaluation Overview

The evaluation process follows these steps:
1. Load and parse the Rego policy from the registry
2. Prepare input data from the request context
3. Evaluate the policy rules against the input
4. Return authorization decision (ALLOW/DENY) with detailed reasoning

The evaluator parses and compiles Rego policies at registration time for fast runtime evaluation. It supports compiled policy caching to improve performance. The evaluator is thread-safe and handles concurrent requests efficiently.

The Lightweight Policy Evaluator is particularly well-suited for:
- Microservices that need embedded authorization logic
- Edge computing environments with limited external dependencies
- Applications that require fast policy evaluation without network overhead
- Development and testing environments where simplicity is preferred

This evaluator requires the `LightweightPolicyBuilder` which generates Rego policies formatted specifically for evaluation with proper package structure.

#### Policy Format Example

```rego
package agent

allow {
    input.operationType == "read"
    input.resourceId == "/api/data"
    input.user.role == "admin"
}

allow {
    input.operationType == "write"
    input.resourceId == "/api/data"
    input.user.role == "editor"
}
```

### OPA REST Policy Evaluator

The OPA REST Policy Evaluator integrates with an external OPA (Open Policy Agent) server for policy evaluation. This evaluator is designed for enterprise environments where policies are centrally managed and updated frequently. It leverages the full power of OPA's policy evaluation engine while maintaining a clean separation between your application and policy management.

#### Evaluation Overview

The evaluation process involves:
1. Loading the policy from the local registry
2. Preparing an HTTP request with input data
3. Sending the request to the OPA server
4. Parsing the OPA response and extracting the decision
5. Caching results and returning the authorization decision

The evaluator uses Java 11+ HttpClient with connection pooling for efficient HTTP communication. It's thread-safe and handles concurrent requests. This evaluator is ideal for centralized policy management, allowing policy authors to update rules without modifying application code. It also provides detailed evaluation results including reasoning and errors for auditing and debugging.

This evaluator requires the `OpaPolicyBuilder` which generates Rego policies formatted specifically for OPA evaluation with proper package structure.

#### Policy Format Example

```rego
package agent

allow {
    input.operationType == "read"
    input.resourceId == "/api/data"
    input.user.role == "admin"
}
```

### RAM Policy Evaluator

The RAM Policy Evaluator implements a Resource Access Management policy model similar to AWS IAM and Alibaba Cloud RAM. This evaluator is ideal for cloud-native applications and organizations already familiar with IAM-style policy definitions.

#### Evaluation Overview

RAM policies use a statement-based evaluation model:
1. Extract action, resource, and conditions from input
2. Evaluate statements in order
3. DENY statements take precedence over ALLOW statements
4. Return ALLOW if any ALLOW matches and no DENY matches
5. Otherwise return DENY

RAM policies consist of statements with effects (ALLOW/DENY), actions, resources, and optional conditions. The evaluator follows explicit denial principles, ensuring security overrides are respected.

This evaluator requires the `RamPolicyBuilder` which generates JSON-formatted policies with statements, actions, and resources.

#### Policy Format Example

```json
{
  "version": "1.0",
  "statement": [
    {
      "effect": "ALLOW",
      "action": ["read"],
      "resource": ["/api/data/*"],
      "condition": {
        "operator": "StringEquals",
        "key": "role",
        "value": "admin"
      }
    },
    {
      "effect": "DENY",
      "action": ["delete"],
      "resource": ["/api/data/production/*"]
    }
  ]
}
```

### ACL Policy Evaluator

The ACL Policy Evaluator implements a traditional Access Control List model where each resource has an associated list of permissions for specific principals. This evaluator is ideal for simple authorization scenarios where you need to control access to individual resources based on user or group identities.

#### Evaluation Overview

The ACL evaluation process works as follows:
1. Extract principal, resource, and permission from input
2. Search for matching ACL entries (exact match first, then wildcard)
3. Check the effect of the matching entry
4. Return ALLOW if an ALLOW entry matches
5. Return DENY if a DENY entry matches or no entry found

ACL policies define principals, resources, permissions, and effects in JSON format. The evaluator supports both exact and wildcard resource matching for flexible access control.

This evaluator requires the `AclPolicyBuilder` which generates JSON-formatted policies with principal-resource-permission mappings.

#### Policy Format Example

```json
{
  "version": "1.0",
  "entries": [
    {
      "principal": "user:alice",
      "resource": "/api/data",
      "permissions": ["read", "write"],
      "effect": "ALLOW"
    },
    {
      "principal": "role:editor",
      "resource": "/api/data/*",
      "permissions": ["read"],
      "effect": "ALLOW"
    },
    {
      "principal": "user:bob",
      "resource": "/api/data/sensitive",
      "permissions": ["write"],
      "effect": "DENY"
    }
  ]
}
```

### Scope Policy Evaluator

The Scope Policy Evaluator implements OAuth 2.0 scope-based authorization following RFC 6749 and RFC 8707 standards. This evaluator is ideal for applications that use OAuth 2.0 for authorization and need to control access based on token scopes.

#### Evaluation Overview

The scope evaluation process involves:
1. Extract the required scope from the token
2. Extract the target resource from the request
3. Look up the scope in the policy definition
4. Check if the resource is in the scope's allowed resources
5. Return ALLOW if found, otherwise return DENY

Scope policies define which scopes grant access to which resources, following OAuth 2.0 standards. Each scope has a name, description, and list of accessible resources.

This evaluator requires the `ScopePolicyBuilder` which generates JSON-formatted policies with scope definitions and resources.

#### Policy Format Example

```json
{
  "version": "1.0",
  "scopes": [
    {
      "name": "read:data",
      "description": "Read access to data resources",
      "resources": ["/api/data/*"]
    },
    {
      "name": "write:data",
      "description": "Write access to data resources",
      "resources": ["/api/data/input/*"]
    },
    {
      "name": "admin:all",
      "description": "Full administrative access",
      "resources": ["/api/*"]
    }
  ]
}
```

## Configuration and Usage

### Creating a Policy Evaluator

To use a policy evaluator in your application, you first need to create an instance of the desired evaluator type. All evaluators require a PolicyRegistry instance, which is responsible for storing and retrieving policies. The framework provides two built-in PolicyRegistry implementations: InMemoryPolicyRegistry for development and testing, and RemotePolicyRegistry for production use with centralized policy storage. For the Lightweight Policy Evaluator, you can create an instance with just a PolicyRegistry. The evaluator will use default settings for caching and performance. If you need to customize these settings, you can use the constructor that accepts cache configuration parameters. This allows you to control whether caching is enabled and the maximum number of policies to cache. For the OPA REST Policy Evaluator, you need to provide the OPA server base URL in addition to the PolicyRegistry. You can also configure the request timeout if needed. The evaluator will automatically connect to the OPA server and register policies before evaluation. Make sure the OPA server is running and accessible before creating the evaluator instance. For the RAM, ACL, and Scope Policy Evaluators, you can create instances with just a PolicyRegistry. These evaluators will use default settings for caching and performance. If you need to customize these settings, you can use the constructor that accepts cache configuration parameters. This allows you to control whether caching is enabled and the maximum number of policies to cache.

### Registering Policies

Before you can evaluate policies, you need to register them with the PolicyRegistry. The registration process varies depending on the policy type and evaluator you are using. For Lightweight and OPA REST Policy Evaluators, you register Rego policies as strings. For RAM, ACL, and Scope Policy Evaluators, you register policies as JSON strings that conform to the respective policy schemas. To register a policy, you call the register method on the PolicyRegistry with the policy content, description, creator, and optional expiration time. The registry will validate the policy, assign it a unique policy ID if not already set, and store it for later retrieval. The registration process ensures that only valid policies are stored and used for evaluation. For Rego policies, the framework validates the syntax before registration, checking for common errors like unbalanced braces, missing package declarations, and undefined rules. This helps catch policy errors early and prevents runtime issues during evaluation. The validation is performed automatically, so you don't need to worry about writing invalid policies. For JSON-based policies (RAM, ACL, Scope), the framework validates the JSON structure and ensures it conforms to the expected schema. This includes checking for required fields, valid data types, and proper nesting. The validation helps ensure that policies are correctly formatted and can be evaluated without errors.

### Evaluating Policies

Once policies are registered, you can evaluate them using the PolicyEvaluator interface. The simplest way to evaluate a policy is to call the evaluate method with the policy ID and input data. This method returns a boolean indicating whether the operation is allowed. If you need more information about the evaluation, you can call the evaluateWithDetails method, which returns a PolicyEvaluationResult containing the decision, reasoning, error messages, and additional output. The input data is a map containing all the information needed for policy evaluation. This typically includes operation type, resource ID, user identity, workload identity, and any other context relevant to the authorization decision. The structure of the input data depends on the policy type and evaluation logic, so you need to ensure your policies expect the correct input structure. For Lightweight and OPA REST Policy Evaluators, the input data is passed to the Rego policy as the input variable. This allows you to reference values in the input data using dot notation in your Rego policies. For example, you can access input.operationType to check the operation type or input.resourceId to check the resource ID. For RAM and ACL Policy Evaluators, the input data is used to extract values for action, resource, principal, and condition evaluation. The evaluator expects specific keys in the input data, such as operationType for action and resourceId for resource. Make sure your input data includes these keys with the correct values. For Scope Policy Evaluator, the input data is used to extract the required scope and resource for evaluation. The evaluator expects specific keys in the input data, such as operationType for scope and resourceId for resource. Make sure your input data includes these keys with the correct values.

### Handling Evaluation Results

The PolicyEvaluationResult returned by the evaluateWithDetails method contains comprehensive information about the evaluation. The isAllowed method returns the authorization decision, the getReasoning method provides an explanation for the decision, the getErrorMessage method returns any error messages if the evaluation failed, and the getOutput method returns additional structured output from the evaluation engine. You should always check the isSuccess method before using the evaluation result to ensure the evaluation succeeded without errors. If the evaluation failed, the isAllowed method will return false, and you can use the getErrorMessage method to get more information about what went wrong. This helps you handle errors gracefully and provide meaningful feedback to users. The reasoning string provides a human-readable explanation for the authorization decision. This can be valuable for logging, auditing, and debugging. For example, you can log the reasoning to track why certain requests were allowed or denied, or display it to users to help them understand authorization decisions. The output map contains engine-specific data from the evaluation. For OPA REST Policy Evaluator, this includes the OPA decision ID and the raw result from OPA. For RAM Policy Evaluator, this includes information about which statements matched and whether there were any deny statements. For ACL Policy Evaluator, this includes the matched ACL entry. For Scope Policy Evaluator, this includes the scope used for the decision.

## Best Practices

### Choosing the Right Evaluator

When choosing a policy evaluator for your application, consider your specific requirements and constraints. If you need a simple, embedded solution without external dependencies, the Lightweight Policy Evaluator is a good choice. If you need comprehensive policy evaluation with full Rego support, the OPA REST Policy Evaluator is recommended. If you are already using IAM-style policies in your organization, the RAM Policy Evaluator provides a familiar model. If you need simple resource-based access control, the ACL Policy Evaluator is intuitive and straightforward. If you are using OAuth 2.0 for authorization, the Scope Policy Evaluator ensures standards compliance. It's important to note that you can use multiple evaluators in the same application if needed. For example, you might use the OPA REST Policy Evaluator for complex authorization logic and the Scope Policy Evaluator for OAuth 2.0 integration. The framework's pluggable architecture allows you to mix and match evaluators to meet your specific needs.

### Policy Design

When designing policies, follow the principle of least privilege by granting only the minimum permissions necessary. Use explicit deny statements sparingly and only when necessary to override allow statements. Write clear and concise policies that are easy to understand and maintain. Use descriptive names for policies, scopes, and resources to improve readability. For Rego policies, follow OPA best practices for policy organization and structure. Use meaningful package names and rule names. Document your policies with comments to explain complex logic. Test your policies thoroughly before deploying to production to ensure they behave as expected. For RAM policies, organize statements logically and use consistent naming conventions for actions and resources. Leverage conditions to implement fine-grained control without creating excessive statements. Use wildcards judiciously to avoid over-permissive policies. For ACL policies, organize entries by resource or principal to improve readability. Use role-based principals to simplify permission management. Define clear and consistent permission names to avoid confusion. For Scope policies, design scopes that represent logical permission groups rather than individual operations. Use descriptive scope names that convey their purpose. Document what each scope allows access to for easy reference.

### Performance Optimization

Policy evaluation can impact application performance, especially for complex policies or high-traffic applications. To optimize performance, enable caching in your policy evaluators to avoid repeated parsing and compilation. Configure appropriate cache sizes based on your policy count and evaluation frequency. Monitor cache hit rates to ensure caching is effective. For OPA REST Policy Evaluator, consider using OPA's built-in caching and partial evaluation features to reduce network overhead. Configure appropriate timeouts to balance responsiveness and reliability. Use connection pooling to improve performance for concurrent evaluation requests. For all evaluators, minimize the complexity of your policies to reduce evaluation time. Avoid deeply nested conditions or excessive policy rules. Use efficient data structures in your input data to enable fast lookups. Profile your policy evaluation performance to identify bottlenecks and optimize accordingly.

### Security Considerations

Security is paramount when implementing authorization systems. Always validate input data before using it in policy evaluation to prevent injection attacks. Sanitize user input to prevent malicious policy manipulation. Use secure communication channels (HTTPS) for remote policy evaluation to protect sensitive data in transit. Implement proper access controls on policy registration and management endpoints to prevent unauthorized policy modifications. Use authentication and authorization to ensure only authorized users can register, update, or delete policies. Audit all policy changes and evaluation decisions for compliance and forensic analysis. For OPA REST Policy Evaluator, secure the OPA server with appropriate authentication and authorization mechanisms. Use network segmentation to restrict access to the OPA server. Regularly update OPA to the latest version to benefit from security patches and improvements. For all evaluators, implement proper error handling to prevent information leakage through error messages. Use fail-safe defaults (deny by default) to ensure security in case of evaluation failures. Regularly review and audit your policies to identify and address security issues.

## Integration with Spring Boot

The Open Agent Auth framework provides seamless integration with Spring Boot through auto-configuration. Simply add the framework dependency to your Spring Boot application, and the framework will automatically configure the appropriate components based on your application properties. You can customize the configuration through application.yml or application.properties files. To enable policy evaluation in your Spring Boot application, configure the open-agent-auth.policy.evaluator.type property to specify which evaluator to use. The framework supports lightweight, opa-rest, ram, acl, and scope evaluator types. Depending on the evaluator type, you may need to provide additional configuration such as OPA server URL or cache settings. The framework automatically creates and configures PolicyRegistry and PolicyEvaluator beans based on your configuration. You can inject these beans into your Spring components using dependency injection. This allows you to easily integrate policy evaluation into your Spring application without manual configuration. For example, you can inject the PolicyEvaluator into a service or controller and use it to evaluate authorization decisions. The framework also provides interceptors and filters that can automatically intercept requests and perform policy evaluation, reducing the amount of boilerplate code you need to write.

## Troubleshooting

### Common Issues

When working with policy evaluators, you may encounter various issues. One common issue is policy evaluation failures due to invalid policy syntax. Make sure your policies are correctly formatted and conform to the expected schema. Use the validation features provided by the framework to catch errors early. Another common issue is input data mismatches where the input data does not contain the expected keys or values. Make sure your input data matches the structure expected by your policies. Review the policy documentation to understand what input data is required. Performance issues can occur if caching is disabled or cache sizes are too small. Enable caching and configure appropriate cache sizes based on your usage patterns. Monitor cache hit rates to ensure caching is effective. For OPA REST Policy Evaluator, network connectivity issues can prevent evaluation. Make sure the OPA server is running and accessible from your application. Check firewall rules and network configuration to ensure connectivity.

### Debugging

Enable debug logging for policy evaluation to get detailed information about the evaluation process. Set the logging level for com.alibaba.openagentauth.core.policy to DEBUG to see evaluation steps, decisions, and reasoning. This can help you understand why certain decisions are made and identify issues in your policies. Use the evaluateWithDetails method to get comprehensive evaluation results. Review the reasoning and output to understand how the decision was made. This can help you debug policy logic and identify areas for improvement. For OPA REST Policy Evaluator, check the OPA server logs for additional information about policy evaluation. OPA provides detailed logs that can help you understand how policies are evaluated and why certain decisions are made. For all evaluators, write unit tests for your policies to ensure they behave as expected. Test various input scenarios to verify that policies allow and deny operations correctly. Use test-driven development to catch issues early.

### Getting Help

If you encounter issues that you cannot resolve, refer to the framework documentation for detailed information about policy evaluators. Check the sample applications for examples of how to use the evaluators in real-world scenarios. Review the test cases to understand expected behavior and common usage patterns. For issues specific to OPA, refer to the OPA documentation for comprehensive information about policy language, evaluation, and best practices. The OPA community is also a valuable resource for getting help and learning from other users. For issues related to the Open Agent Auth framework, consider opening an issue on the project repository. Provide detailed information about the issue, including error messages, configuration, and steps to reproduce. This will help the maintainers diagnose and resolve the issue quickly.

## Conclusion

The Open Agent Auth framework provides a comprehensive and flexible policy evaluation system that supports multiple policy types to meet diverse authorization requirements. Whether you need a simple embedded solution, full OPA integration, IAM-style policies, ACL-based access control, or OAuth 2.0 scope authorization, the framework has you covered.

By choosing the right evaluator for your needs and following best practices for policy design and implementation, you can build robust and secure authorization systems that protect your resources while enabling legitimate access. The framework's pluggable architecture and Spring Boot integration make it easy to get started and scale as your requirements grow.

Remember to regularly review and update your policies to ensure they continue to meet your security and business requirements. Monitor policy evaluation performance and audit decisions to maintain compliance and identify areas for improvement. With proper implementation and maintenance, the policy evaluation system will serve as a strong foundation for your authorization infrastructure.

For more information, refer to the [Configuration Guide](./configuration-guide.md), [Quick Start Guide](../start/01-quick-start.md), and [User Guide](../start/00-user-guide.md). You may also want to check the [IETF Draft for Agent Operation Authorization](https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/) and the [OPA Documentation](https://www.openpolicyagent.org/docs/latest/) for additional context and best practices.