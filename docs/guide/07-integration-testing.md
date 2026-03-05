# Open Agent Auth Integration Testing Guide

## Overview

Integration tests validate the complete system behavior by testing interactions between components with external dependencies. Unlike unit tests that verify individual components in isolation, integration tests examine how the authorization server, identity providers, policy engines, and resource servers work together in realistic scenarios. This comprehensive testing approach ensures that the entire authorization ecosystem operates correctly as designed.

### Test Categories

The integration test suite is organized into several categories, each targeting specific aspects of the system:

| Category | Description | Test Classes |
|----------|-------------|--------------|
| **Authorization Flow** | OAuth 2.0 and OpenID Connect protocol implementations | `OAuth2AuthorizationFlowIntegrationTest` |
| **Security** | Cryptographic operations, token validation, and attack resilience | `SecurityIntegrationTest` |
| **Validation Framework** | Five-layer verification mechanism | `FiveLayerValidationIntegrationTest` |
| **JWKS Endpoints** | JSON Web Key Set endpoint functionality | `JwksEndpointIntegrationTest` |
| **Policy Evaluation** | OPA policy evaluation and enforcement | `OpaPolicyEvaluationIntegrationTest` |
| **End-to-End** | Complete user workflow validation | `FullAuthorizationFlowE2ETest` |

### Required Services

Integration tests depend on the following external services:

| Service | Port | Description |
|---------|------|-------------|
| Agent | 8081 | AI Agent main interface |
| Agent IDP | 8082 | Agent identity provider |
| Agent User IDP | 8083 | User identity provider for agents |
| AS User IDP | 8084 | User identity provider for authorization server |
| Authorization Server | 8085 | OAuth 2.0 authorization server |
| Resource Server | 8086 | MCP server for tool execution |
| OPA Server | 8181 | Open Policy Agent for policy evaluation (optional) |

### Test Execution Modes

Integration tests support multiple execution modes to accommodate different testing scenarios:

- **Command Line with Maven Profile**: Suitable for CI/CD pipelines with explicit test control
- **Environment Variable**: Flexible approach for different operating systems and environments
- **IDE Execution**: Direct execution from IntelliJ IDEA, Eclipse, or VS Code with debugging support
- **E2E Test Runner Script**: Automated workflow for complete end-to-end validation

### Key Features

The integration testing framework provides several key features:

- **Conditional Execution**: Tests are automatically skipped when dependencies are unavailable
- **Service Health Checks**: Automatic verification of required services before test execution
- **Comprehensive Reporting**: Detailed test statistics with pass/fail status and diagnostic information
- **Flexible Configuration**: Support for multiple execution modes and customization options
- **Debug Support**: Debug mode for attaching debuggers to investigate issues

## Preparing the Test Environment

Before running integration tests, you need to ensure your environment is properly configured with all required services. The integration tests depend on several external services including the authorization server, identity providers, and resource servers. You can verify your environment readiness by running the diagnostic script located in the integration tests module. This script checks Java version, Maven installation, service availability, and endpoint accessibility, providing immediate feedback about any configuration issues that might prevent test execution.

To prepare your environment, navigate to the integration tests module directory and execute the diagnostic script. Navigate to the project root and run the diagnostic command from the integration tests scripts directory. The script will systematically check each prerequisite and report any discrepancies. If all checks pass, your environment is ready for integration testing. If any checks fail, the script will provide specific guidance on how to resolve the issues, such as installing missing dependencies or starting required services. The diagnostic output will display each check with a clear pass or fail indicator, making it easy to identify any configuration problems before attempting to run tests.

## Starting Required Services

Integration tests require all sample services to be running and healthy. The sample services module includes a startup script that orchestrates the service startup sequence, respecting service dependencies and waiting for each service to become healthy before proceeding. Navigate to the samples directory and execute the startup script to begin the service initialization process. The script will build the project if necessary, then start each service in the correct order.

The startup process typically takes one to two minutes to complete. During this time, the script monitors each service's health status and provides real-time feedback about startup progress. You will see status indicators for each service as it initializes, including the Agent, Agent IDP, Agent User IDP, AS User IDP, Authorization Server, and Resource Server. Once all services report as healthy, the startup process completes and your environment is ready for test execution. The startup script accepts optional parameters such as debug mode for attaching debuggers to services, skip build to bypass the Maven build step if the project is already built, and profile to activate specific Spring profiles.

If you need to restart services after making configuration changes, use the restart script instead of stopping and starting services manually. The restart script handles the entire process automatically, including stopping existing services, cleaning up resources, and starting fresh instances with the latest configuration. This approach ensures a clean state and prevents conflicts from previous executions. To check the status of all services at any time, use the status script which displays the operational state, process ID, and port for each service.

## Running Integration Tests via Command Line

Integration tests can be executed from the command line using Maven with the appropriate configuration. By default, integration tests are automatically skipped during regular test execution to prevent failures in environments where external dependencies are not available. To enable integration tests, you must either activate the integration-test Maven profile or set the ENABLE_INTEGRATION_TESTS environment variable to true.

To run integration tests using the Maven profile approach, navigate to the integration tests module and execute the test command with the integration-test profile activated. This method is particularly suitable for continuous integration pipelines where test execution needs to be explicitly controlled through build configurations. The profile ensures that only integration tests matching the specified pattern are executed, while unit tests are excluded. You can also run all integration tests from the project root by specifying the integration tests module in the Maven command.

Alternatively, you can enable integration tests by setting the environment variable before invoking Maven. This approach provides flexibility across different operating systems and execution environments. The framework checks for both environment variables and system properties, allowing tests to be enabled through command-line arguments, IDE configuration, or environment variable injection without code modifications. Set the environment variable in your shell before running Maven, or pass it directly in the Maven command using the system property syntax.

For end-to-end tests that require browser automation, use the dedicated E2E test runner script located in the integration tests scripts directory. This script automates the entire testing workflow from service restart through test execution and result reporting. It rebuilds the project, restarts all sample services with the appropriate configuration profiles, and executes the specified test class with the correct Maven configurations. The script accepts optional parameters such as debug mode to start services with debugging enabled, skip build to bypass the Maven build step, and test class to specify which test class to run. The script also generates a comprehensive summary report with test duration, pass/fail status, and detailed statistics.

## Running Integration Tests from IDE

You can run and debug integration tests directly from your integrated development environment with minimal configuration. The key requirement is passing the ENABLE_INTEGRATION_TESTS environment variable to the test runner. Each IDE provides a different mechanism for configuring environment variables in test run configurations.

In IntelliJ IDEA, navigate to the run configuration editor for your test class. Click on the environment variables field and add the ENABLE_INTEGRATION_TESTS variable with a value of true. You can also specify additional environment variables or system properties as needed for your specific test scenario. Once configured, you can run the test using the run button or debug it using the debug button, leveraging the full power of IDE debugging tools while maintaining the same execution semantics as command-line invocations.

Eclipse provides a similar interface for configuring environment variables. Right-click on your test class and select Run As to access the run configurations dialog. Navigate to the environment tab and add the ENABLE_INTEGRATION_TESTS variable. The configuration is saved with your run configuration, so you can reuse it for subsequent test executions without re-entering the environment variables.

For Visual Studio Code users, environment variables can be specified in the launch.json configuration file. Add an env object to your test configuration with the ENABLE_INTEGRATION_TESTS variable set to true. This approach allows you to version control your test configurations alongside your code, ensuring consistency across different development environments.

## Running Specific Test Categories

The integration test suite includes several categories of tests targeting different aspects of the system. You can run specific test categories by executing individual test classes or using Maven's test filtering capabilities. Authorization flow tests verify OAuth 2.0 and OpenID Connect protocol implementations, security tests validate cryptographic operations and attack resilience, and validation framework tests examine the five-layer verification mechanism.

To run a specific integration test class, navigate to the integration tests module and use the Maven test command with the test parameter specifying the class name. This approach is useful when you want to focus on a particular aspect of the system or when debugging a specific failure. The test class must be annotated with @IntegrationTest and follow the naming convention *IntegrationTest.java to be properly recognized by the test framework. You can also run tests using the fully qualified class name to avoid ambiguity when multiple test classes have similar names.

For comprehensive validation of the entire authorization flow, run the end-to-end test class by specifying the test class parameter in the Maven command. This test simulates a complete user workflow from authentication through tool execution, validating the entire system as experienced by end users. The test employs Selenium WebDriver to automate browser interactions, enabling verification of both user interface behavior and backend functionality in a single test scenario. Before running E2E tests, ensure that Chrome browser is installed and that all required services are running and healthy.

## Using the E2E Test Runner Script

The E2E test runner script provides a comprehensive solution for executing end-to-end tests with minimal manual intervention. Navigate to the integration tests scripts directory and execute the run-e2e-tests script to begin the automated testing workflow. This script orchestrates the entire process from project build through service restart and test execution, providing a streamlined experience for running complete end-to-end validation.

### Basic Usage

To run E2E tests with default settings, navigate to the integration tests module and execute the script:

```bash
cd open-agent-auth-integration-tests/scripts
./run-e2e-tests.sh
```

This command will:
- Build the entire project
- Restart all sample services with the mock-llm profile
- Verify service health
- Run the FullAuthorizationFlowE2ETest class
- Display test results with statistics

### Script Parameters

The E2E test runner script accepts several optional parameters to customize test execution:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--debug` | Start services in debug mode for attaching debuggers | `./run-e2e-tests.sh --debug` |
| `--skip-build` | Skip the Maven build step if project is already built | `./run-e2e-tests.sh --skip-build` |
| `--test-class <class>` | Specify which test class to run | `./run-e2e-tests.sh --test-class FullAuthorizationFlowE2ETest` |

### Usage Examples

Run E2E tests with debug mode enabled:
```bash
./run-e2e-tests.sh --debug
```

Skip the build step to speed up execution:
```bash
./run-e2e-tests.sh --skip-build
```

Run a specific test class:
```bash
./run-e2e-tests.sh --test-class OAuth2AuthorizationFlowIntegrationTest
```

Combine multiple parameters:
```bash
./run-e2e-tests.sh --debug --skip-build --test-class FullAuthorizationFlowE2ETest
```

The script executes a four-step workflow starting with building the entire project using Maven. This ensures that all code changes are included in the test execution. The build step can be skipped using the skip build parameter if the project has already been built. After building, the script restarts all sample services with the mock-llm profile activated, which enables simulated large language model responses for testing purposes. The restart process ensures a clean state for all services.

Once services are restarted, the script performs health checks on critical services including the Agent User IDP, AS User IDP, Authorization Server, and Resource Server. These checks verify that each service is not only running but also responding correctly to health check endpoints. If any service fails the health check, the script aborts execution and provides guidance for troubleshooting.

After verifying service health, the script executes the specified test class with the appropriate Maven configurations. The default test class is FullAuthorizationFlowE2ETest, which performs comprehensive validation of the entire authorization flow. You can specify a different test class using the test class parameter to run specific E2E tests. The script activates the e2e-test Spring profile and enables integration tests through the ENABLE_INTEGRATION_TESTS environment variable.

The script accepts several optional parameters to customize test execution. The debug parameter starts services in debug mode, allowing you to attach debuggers to investigate issues. The skip build parameter bypasses the Maven build step if you have already built the project. The test class parameter allows you to specify which test class to run, enabling focused testing of specific scenarios.

Upon test completion, the script generates a comprehensive summary report displayed in the terminal. The report includes the overall pass or fail status, total test duration, and detailed statistics including the number of tests run, failures, errors, and skipped tests. The report uses color-coded indicators to make it easy to quickly assess test results. For failing tests, the script provides troubleshooting guidance including commands for viewing service logs, checking service status, and restarting services.

The script also displays the current service status before test execution, allowing you to verify that all required services are healthy. During test execution, the script captures both standard output and error streams, preserving detailed diagnostic information for later analysis. The real-time output allows you to monitor test progress and identify issues as they occur.

After the test completes, the script provides next steps based on the test outcome. For successful tests, it suggests reviewing the test output and checking service logs if needed. For failed tests, it provides specific troubleshooting steps including reviewing error details, checking service logs, verifying service status, and restarting services if necessary. This structured approach to post-test guidance helps you quickly identify and resolve any issues that arise during testing.

## Monitoring Test Execution

During test execution, Maven provides real-time output showing the progress of each test. You can observe test methods being executed, assertions being evaluated, and results being reported. For integration tests that involve HTTP requests, the output includes request and response details, which can be valuable for debugging failures. The test framework also captures detailed diagnostic information including stack traces for failed assertions and warnings for skipped tests.

The E2E test runner script provides enhanced monitoring capabilities with color-coded status indicators and progress bars. The script displays the current service status before test execution, allowing you to verify that all required services are healthy. During test execution, the script shows real-time progress and captures both standard output and error streams for later analysis.

After test completion, review the test summary report which includes overall pass/fail status, test duration, and detailed statistics. The report highlights any failures or errors, making it easy to identify problematic tests. For Maven executions, the standard Surefire report provides additional details including execution time for each test method and links to detailed error messages.

## Troubleshooting Test Failures

When integration tests fail, the first step is to examine the test output for error messages and stack traces. These outputs typically provide immediate clues about the nature of the failure. Common issues include services failing to start, ports being occupied by other processes, network connectivity problems, and configuration mismatches between test expectations and actual service behavior.

If services are not running or not healthy, verify service status using the status check script located in the samples scripts directory. This script provides a comprehensive overview of all sample services including their ports, process IDs, and operational status. If services are not running, use the startup script to start them. For services that are running but unhealthy, check the service logs using the logs script to identify error messages, exceptions, or other diagnostic information. You can view logs for a specific service by passing the service name as a parameter to the logs script, or view all service logs simultaneously.

Port conflicts frequently cause integration test failures in development environments where multiple projects might compete for the same ports. Use the diagnostic script to identify which ports are in use and which processes are occupying them. When port conflicts are detected, stop the conflicting processes using the kill command with the process ID, or modify the port configuration in the application properties files. The framework uses a consistent port allocation scheme, making it straightforward to identify and resolve conflicts by examining the standard port assignments documented in the sample services configuration.

For end-to-end tests that rely on Selenium WebDriver, ensure Chrome browser is installed and compatible with the WebDriver version. The framework uses the WebDriverManager library to automatically manage Chrome driver binaries, but tests may still fail if Chrome is not installed or if there are compatibility issues. The diagnostic script checks for Chrome browser installation and reports the version if found. If Chrome is not installed, install it using your system package manager or download it from the official Chrome website.

## Viewing Service Logs

Service logs contain detailed diagnostic information that can help identify the root cause of test failures. The logs script located in the samples scripts directory allows you to view logs from individual services or all services simultaneously. When investigating a specific failure, focus on the logs from services that are directly involved in the failing test scenario. For example, if an authorization flow test fails, examine the authorization server and identity provider logs first. To view logs for a specific service, pass the service name as a parameter to the logs script.

Log entries include timestamps, log levels, and detailed messages about service operations. Look for error messages, exceptions, and warnings that indicate problems with service configuration, database connectivity, or external dependencies. The logs also include information about request processing, token issuance, and policy evaluation, which can be valuable for understanding the flow of requests through the system. You can use grep or other text processing tools to filter logs for specific patterns or error messages.

If you need to share logs with team members or attach them to bug reports, redirect the output of the logs script to a file using shell redirection. This approach preserves the log formatting and makes it easier to share large log files without cluttering communication channels. When sharing logs, consider filtering by log level or time range to focus on the most relevant entries. You can also use the tail command with the follow option to monitor logs in real-time while tests are running.

## Cleaning Up After Testing

After completing integration testing, you should clean up resources to ensure a clean state for subsequent test runs. The stop script located in the samples scripts directory terminates all sample services and removes temporary files and process identifiers. This cleanup prevents conflicts from previous test executions and ensures that future tests start with a fresh environment. Execute the stop script without any parameters to stop all services, or pass a specific service name to stop only that service.

If you need to completely reset the test environment, including removing logs and cached data, manually delete the logs directory and any temporary files created during testing. This more thorough cleanup is useful when troubleshooting persistent issues that might be caused by residual state from previous test runs. Navigate to the samples directory and remove the logs directory and any temporary files that may have been created during test execution.

For development environments where you frequently run integration tests, consider creating a custom script that combines cleanup, service startup, and test execution into a single workflow. This approach reduces manual effort and ensures consistent test execution across different testing sessions. Your custom script can call the stop script, then the start script, and finally execute the test commands in sequence, providing a single command that performs the entire testing workflow.
