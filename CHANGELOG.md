# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source release preparation
- Apache License 2.0 licensing
- GitHub contribution guidelines
- Security policy documentation
- Issue and pull request templates

## [1.0.0.beta.1] - 2026-02-13

### Added
- Core authorization framework with WIMSE workload identity pattern
- Three-layer cryptographic identity binding (User-Workload-Token)
- Five-layer security verification mechanism
- Spring Boot 3.x autoconfiguration starter
- MCP (Model Context Protocol) adapter
- Dynamic policy registration with OPA integration
- W3C VC-based semantic audit trail
- Request-level virtual workload isolation
- Comprehensive sample applications
- Complete documentation

### Security
- Cryptographic token validation (WIT, AOAT, WPT)
- Multi-layer verification (5 security layers)
- Policy-based access control with OPA
- Immutable audit trail with W3C Verifiable Credentials

### Testing
- Unit test coverage > 80%
- Integration test suite
- End-to-end testing
- JaCoCo code coverage reporting

## [1.0.0] - Upcoming

### Planned
- Authorization Discovery
- Agent-to-Agent Authorization
- OpenAPI Adapter
- Prompt Security Transmission
- Enhanced Audit & Compliance

### Security
- Security audit completion
- Additional security hardening
- Penetration testing
- Dependency vulnerability scanning
- Automated security checks in CI

### Infrastructure
- CI/CD automation
- Maven Central publication
- Performance optimization
- Enhanced error messages
- Troubleshooting guide

---

## Version Format

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Categories

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security vulnerability fixes

---

For more information, see our [README](README.md).
