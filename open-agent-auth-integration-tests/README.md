# Open Agent Auth Integration Tests

This module contains integration tests for the Open Agent Auth framework.

## Overview

Integration tests are designed to test the complete system behavior with external dependencies such as:
- Authorization Server (port 8085)
- OPA Server (port 8181)
- Various IDP services
- Resource Server

## Running Tests

### Default Behavior (Skip Integration Tests)

By default, integration tests are **automatically skipped** when running regular unit tests:

```bash
# This will skip all integration tests
mvn test
```

### Running Integration Tests

There are two ways to run integration tests:

#### Method 1: Using Maven Profile

```bash
# Run only integration tests
mvn test -P integration-test

# Run integration tests with verbose output
mvn test -P integration-test -X
```

#### Method 2: Using Environment Variable

```bash
# Set environment variable to enable integration tests
ENABLE_INTEGRATION_TESTS=true mvn test

# Or export it first
export ENABLE_INTEGRATION_TESTS=true
mvn test
```

### Running from IDE

To run integration tests from your IDE:

1. **IntelliJ IDEA**:
   - Go to Run → Edit Configurations
   - Add/Edit your test configuration
   - Click on the "Environment variables" field
   - Add: `ENABLE_INTEGRATION_TESTS=true`

2. **Eclipse**:
   - Right-click on test class → Run As → Run Configurations
   - Go to the "Environment" tab
   - Add: `ENABLE_INTEGRATION_TESTS=true`

3. **VS Code**:
   - Edit your `.vscode/launch.json`
   - Add to your configuration:
   ```json
   {
     "env": {
       "ENABLE_INTEGRATION_TESTS": "true"
     }
   }
   ```

## Test Structure

### Integration Test Annotation

All integration test classes are marked with the `@IntegrationTest` annotation:

```java
@IntegrationTest(
    value = "OAuth 2.0 Authorization Flow Integration Tests",
    requiredServices = {"localhost:8085"}
)
class OAuth2AuthorizationFlowIntegrationTest {
    // test methods
}
```

### Available Integration Tests

| Test Class | Description | Required Services |
|------------|-------------|-------------------|
| `OAuth2AuthorizationFlowIntegrationTest` | OAuth 2.0 authorization flow tests | localhost:8085 |
| `JwksEndpointIntegrationTest` | JWKS endpoint tests | localhost:8085 |
| `OpaPolicyEvaluationIntegrationTest` | OPA policy evaluation tests | localhost:8181 |
| `FiveLayerValidationIntegrationTest` | Five-layer validation framework tests | - |
| `SecurityIntegrationTest` | Security feature tests | localhost:8085 |
| `FullAuthorizationFlowE2ETest` | End-to-end authorization flow tests | localhost:8081-8086 |

## Prerequisites

### Starting Required Services

Before running integration tests, you need to start the required services:

```bash
cd open-agent-auth-samples
./scripts/sample-start.sh
```

This will start:
- Agent (port 8081)
- Agent IDP (port 8082)
- Agent User IDP (port 8083)
- AS User IDP (port 8084)
- Authorization Server (port 8085)
- Resource Server (port 8086)

### OPA Server (Optional)

For OPA policy evaluation tests:

```bash
# Install OPA
# macOS
brew install opa

# Linux
wget https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa_linux_amd64
sudo mv opa_linux_amd64 /usr/local/bin/opa

# Run OPA server
opa run --server
```

## How It Works

### IntegrationTestCondition

The `IntegrationTestCondition` class implements JUnit 5's `ExecutionCondition` interface to control test execution:

1. **Check Annotation**: Verifies if the test class is marked with `@IntegrationTest`
2. **Check Environment**: Looks for `ENABLE_INTEGRATION_TESTS` environment variable or system property
3. **Check Services**: Optionally verifies that required services are available
4. **Decision**: Enables or disables the test based on the above checks

### Maven Configuration

The `pom.xml` is configured to:
- Skip integration tests by default (`<skipITs>true</skipITs>`)
- Provide an `integration-test` profile to enable them
- Only run tests matching `**/*IntegrationTest.java` pattern

## Troubleshooting

### Tests Are Skipped

If integration tests are being skipped when you expect them to run:

1. **Check Environment Variable**:
   ```bash
   echo $ENABLE_INTEGRATION_TESTS
   # Should output: true
   ```

2. **Check Maven Profile**:
   ```bash
   mvn test -P integration-test -Dmaven.verbose=true | grep integration-test
   ```

3. **Verify Annotation**:
   Ensure your test class has the `@IntegrationTest` annotation.

### Services Not Available

If you see errors about services not being available:

1. **Check if services are running**:
   ```bash
   curl http://localhost:8085/.well-known/openid-configuration
   ```

2. **Start services**:
   ```bash
   cd open-agent-auth-samples
   ./scripts/sample-start.sh
   ```

3. **Check port conflicts**:
   ```bash
   lsof -i :8085
   ```

### Chrome Driver Issues (E2E Tests)

For `FullAuthorizationFlowE2ETest`:

1. **Install Chrome**:
   - macOS: Download from [chrome.google.com](https://chrome.google.com)
   - Linux: `sudo apt-get install chromium-browser`

2. **Check Chrome version**:
   ```bash
   chrome --version
   ```

3. **Update WebDriver** (if needed):
   - The test uses `webdrivermanager` which automatically manages ChromeDriver

## Best Practices

1. **Separate Unit and Integration Tests**: Keep unit tests in the core modules and integration tests here
2. **Use @IntegrationTest Annotation**: Always mark integration test classes with `@IntegrationTest`
3. **Specify Required Services**: Use the `requiredServices` parameter to declare dependencies
4. **Test in Isolation**: Each integration test should be able to run independently
5. **Clean Up Resources**: Use `@AfterEach` to clean up any resources created during tests
6. **Use Mock Services When Possible**: For tests that don't require full system, consider using WireMock

## Contributing

When adding new integration tests:

1. Create a new test class in the appropriate package
2. Add the `@IntegrationTest` annotation with description and required services
3. Follow the naming convention: `*IntegrationTest.java`
4. Document any prerequisites in the test class JavaDoc
5. Update this README with the new test information

## References

- [JUnit 5 User Guide](https://junit.org/junit5/docs/current/user-guide/)
- [JUnit 5 Conditional Test Execution](https://junit.org/junit5/docs/current/user-guide/#writing-tests-conditional-execution)
- [Maven Surefire Plugin](https://maven.apache.org/surefire/maven-surefire-plugin/)
- [Testcontainers Documentation](https://www.testcontainers.org/)
- [RestAssured Documentation](https://rest-assured.io/)
