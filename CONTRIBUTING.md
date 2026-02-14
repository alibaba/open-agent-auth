# Contributing to Open Agent Auth

Thank you for your interest in contributing! We welcome contributions from the community and are excited to have you on board.

## Getting Started

### Prerequisites
- Java 17+
- Maven 3.6+
- Git

### Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/open-agent-auth.git
cd open-agent-auth

# Add upstream remote
git remote add upstream https://github.com/alibaba/open-agent-auth.git

# Build
mvn clean install

# Run tests
mvn test
```

### Project Structure

```
open-agent-auth/
├── open-agent-auth-core/              # Core interfaces and models
├── open-agent-auth-framework/         # Framework implementation
├── open-agent-auth-spring-boot-starter/  # Spring Boot autoconfiguration
├── open-agent-auth-mcp-adapter/       # MCP protocol adapter
├── open-agent-auth-samples/           # Sample applications
├── open-agent-auth-integration-tests/ # Integration tests
└── docs/                              # Documentation
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

**Branch naming**: `feature/`, `fix/`, `docs/`, `refactor/`, `test/`, `chore/`

### 2. Make Changes

- Write clean code following [Coding Standards](#coding-standards)
- Add tests for new functionality
- Update documentation as needed
- Keep commits atomic and focused

### 3. Commit Changes

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

Types: feat, fix, docs, style, refactor, test, chore, perf, ci
Scopes: core, framework, starter, mcp, docs, security

Examples:
git commit -m "feat(core): add workload identity validation"
git commit -m "fix(starter): resolve JWT parsing error"
git commit -m "docs(readme): update quick start guide"
```

### 4. Push and Submit PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Coding Standards

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `WorkloadIdentityValidator`)
- **Methods**: `camelCase` with verbs (e.g., `validateToken()`)
- **Variables**: `camelCase` (e.g., `workloadIdentity`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TRUST_DOMAIN`)

### Best Practices

```java
// ✅ Good: Clear naming, proper validation
public WorkloadIdentity validateWorkloadIdentity(String witToken) {
    Objects.requireNonNull(witToken, "WIT token must not be null");
    
    if (witToken.isEmpty()) {
        throw new IllegalArgumentException("WIT token must not be empty");
    }
    
    return parseAndValidateToken(witToken);
}

// ❌ Bad: Unclear naming, no validation
public Object validate(String t) {
    return parse(t);
}
```

### Documentation

Add Javadoc for all public APIs:

```java
/**
 * Validates a Workload Identity Token (WIT) against the trust domain.
 *
 * @param witToken the Workload Identity Token to validate
 * @return the validated workload identity
 * @throws IllegalArgumentException if the token is null or empty
 * @throws SecurityException if validation fails
 */
public WorkloadIdentity validateWorkloadIdentity(String witToken) {
    // implementation
}
```

## Testing

### Test Coverage

Aim for **80%+ code coverage**. Critical security code requires **95%+ coverage**.

### Test Structure

```java
class WorkloadIdentityValidatorTest {
    
    @Test
    void shouldValidateValidWITToken() {
        // Given
        String validToken = generateValidWITToken();
        WorkloadIdentityValidator validator = new WorkloadIdentityValidator();
        
        // When
        WorkloadIdentity identity = validator.validateWorkloadIdentity(validToken);
        
        // Then
        assertNotNull(identity);
        assertEquals("expected-subject", identity.getSubject());
    }
}
```

### Running Tests

```bash
# Run all tests
mvn test

# Run with coverage
mvn test jacoco:report

# Run specific test
mvn test -Dtest=WorkloadIdentityValidatorTest

# Run integration tests
mvn verify -P integration-tests
```

## Pull Request Requirements

Before submitting a PR, ensure:

- ✅ All tests pass (`mvn test`)
- ✅ Code coverage is maintained or improved
- ✅ Code follows coding standards
- ✅ Documentation is updated (if needed)
- ✅ Commit messages follow Conventional Commits
- ✅ No merge conflicts with `main`

## Security

As a security-focused project:

- Never commit secrets (API keys, passwords, tokens)
- Validate all inputs at boundaries
- Follow OWASP security best practices
- See [SECURITY.md](SECURITY.md) for security reporting

## Reporting Issues

- **Bugs**: Use [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)
- **Features**: Use [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md)
- **Questions**: Use [Question Template](.github/ISSUE_TEMPLATE/question.md)

## Additional Resources

- [Documentation](docs/)
- [SECURITY.md](SECURITY.md)
- [CHANGELOG.md](CHANGELOG.md)
- [GitHub Discussions](https://github.com/alibaba/open-agent-auth/discussions)

---

**Thank you for contributing!** 🎉
