# Prompt Protection

## Introduction

When working with AI systems, users often include sensitive information in their prompts without realizing the potential risks. Someone might paste an API key, share a phone number, or include confidential business details while asking an AI assistant for help. This is where Prompt Protection comes in.

Prompt Protection is a security feature that automatically detects and handles sensitive information before it reaches the AI system. It acts as a safeguard, ensuring that sensitive data stays protected while still allowing users to benefit from AI capabilities.

### Why Do We Need Prompt Protection?

Think about it this way: you're using an AI assistant to help with a coding task, and you accidentally include your database password in the prompt. Without protection, that password would be sent to the AI service, potentially exposing it to unauthorized parties. Prompt Protection prevents this by:

- **Catching sensitive data** before it leaves your system
- **Offering choices** about how to handle detected information
- **Keeping you in control** of what gets shared
- **Helping meet compliance requirements** like GDPR and CCPA

---

## How It Works: Three Layers of Protection

Prompt Protection uses three layers working together to keep your data safe. Think of it like a security system with multiple checkpoints - each layer adds an extra level of protection.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Prompt Protection Chain                      │
└─────────────────────────────────────────────────────────────────┘

1. JWE Encryption Layer (Locking It Up)
   └─> Encrypts your prompt so it can only be read by authorized parties
       └─> Like putting your message in a locked box

2. Intelligent Sanitization Layer (Finding and Hiding Sensitive Info)
   └─> Scans for things like emails, phone numbers, API keys
       └─> Replaces or flags sensitive content based on your settings
       └─> Double-checks even after you make edits

3. User Decision Layer (Giving You Control)
   └─> Shows you what it found and asks what you want to do
       └─> Lets you choose: send as-is, send the cleaned version, edit it, or cancel
```

### Layer 1: JWE Encryption - Locking Your Data

The first layer encrypts your prompt before it goes anywhere. This is like putting your message in a secure, locked box that only the right person can open.

**What it does**:
- Uses industry-standard encryption (RFC 7516)
- Only authorized recipients can decrypt and read your prompt
- Works seamlessly with other security protocols

**When you need it**:
- Sending prompts over networks
- Working in shared environments
- Meeting encryption requirements for compliance
- Anytime you want to ensure only the right people can read your data

### Layer 2: Intelligent Sanitization - Finding Sensitive Information

This layer looks through your prompt to find anything sensitive. It's like having a security guard check your message before it goes out.

**What it looks for**:
- **Personal information**: Names, email addresses, phone numbers
- **Credentials**: API keys, passwords, access tokens
- **Financial data**: Credit card numbers, bank details
- **Confidential info**: Trade secrets, proprietary information
- **Health information**: Medical records (important for HIPAA compliance)

**How strict should it be?**

You can choose how sensitive you want the detection to be:

| Level | What It Means | When to Use |
|-------|---------------|-------------|
| **NONE** | Don't check anything | Development and testing |
| **LOW** | Only catch obvious stuff | Internal tools, trusted teams |
| **MEDIUM** | Catch most sensitive info | Everyday production use |
| **HIGH** | Catch everything possible | Strict compliance requirements |

**Double-checking for safety**:
The system checks twice - once when you first submit your prompt, and again if you edit it. This way, even if you make changes, you won't accidentally introduce new sensitive information.

### Layer 3: User Decision - You're in Control

When sensitive information is found, you get to decide what happens next. This layer gives you the control and visibility you need.

**Your options**:

| What You Want | What Happens |
|---------------|--------------|
| **Send original** | Send your prompt as-is (you know what you're doing) |
| **Send cleaned version** | Send the version with sensitive info hidden or removed |
| **Cancel** | Don't send anything - you changed your mind |
| **Edit first** | Make changes to your prompt before sending it |

**Two ways to interact**:

**Interactive Mode** - You see what was found and make the choice:
- The system shows you what sensitive information it detected
- You see the cleaned version of your prompt
- You decide how to proceed
- Great for situations where you want to review everything

**Automatic Mode** - The system decides based on rules you set:
- No interruption to your workflow
- Follows policies you've configured
- Everything gets logged for your records
- Perfect for high-volume scenarios where you don't want to stop for every prompt

---

## What Happens When You Use It

### The Standard Flow

Here's what happens when you submit a prompt for protection:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Standard Protection Flow                    │
└─────────────────────────────────────────────────────────────────┘

1. You submit your prompt
   └─> System checks your settings

2. The system scans for sensitive information
   └─> Finds things like emails, API keys, etc.
   └─> Cleans or flags them based on your settings

3. You decide what to do (or the system decides automatically)
   └─> Interactive: You see what was found and choose
   └─> Automatic: System follows your preset rules

4. If enabled, your prompt gets encrypted
   └─> Locked so only authorized people can read it

5. You get the result
   └─> Your protected prompt ready to use
```

### When You Edit Your Prompt

If you decide to edit your prompt after seeing what was detected, the system checks it again:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Re-Protection Flow (User Edit)               │
└─────────────────────────────────────────────────────────────────┘

1. You edit your prompt
   └─> System validates your changes

2. The system scans again (double-checking)
   └─> Looks for anything new you might have added
   └─> Compares with what was found before

3. You decide on the edited version
   └─> See what's still sensitive
   └─> Choose how to proceed

4. Encryption if enabled
   └─> Your edited prompt gets locked down

5. Updated result
   └─> Your newly protected prompt
```

### When You Pre-Approve Decisions

If you've already decided how you want things handled, you can skip the interaction:

```
┌─────────────────────────────────────────────────────────────────┐
│                  Pre-Approved Decision Flow                      │
└─────────────────────────────────────────────────────────────────┘

1. You submit your prompt with a pre-approved decision
   └─> "Always clean sensitive info" or "Always send as-is"

2. The system scans for sensitive information
   └─> Finds what's there

3. Uses your pre-approved decision immediately
   └─> No need to ask you each time
   └─> Faster processing

4. Encryption if enabled
   └─> Gets locked down

5. Result based on your pre-approved choice
   └─> Done your way, automatically
```

---

## Setting It Up

### Basic Configuration

Prompt Protection is configured through the Agent's configuration properties. Here's how to get started with basic settings:

```yaml
open-agent-auth:
  # Enable prompt protection
  prompt-protection-enabled: true
  
  # Enable encryption for sensitive data
  encryption-enabled: true
  
  # Set the default sanitization level
  sanitization-level: MEDIUM
  
  # Choose whether to require user interaction for high-severity items
  require-user-interaction: false
```

### Choosing How Strict to Be

You can control how sensitive the detection should be by setting the sanitization level:

```yaml
open-agent-auth:
  sanitization-level: MEDIUM  # Options: NONE, LOW, MEDIUM, HIGH
```

**What each level means**:

| Level | What It Does | When to Use |
|-------|--------------|-------------|
| **NONE** | No sanitization applied | Development and testing only |
| **LOW** | Light masking (preserves some information) | Debugging and auditing |
| **MEDIUM** | Standard masking patterns | Everyday production use (recommended) |
| **HIGH** | Complete replacement with placeholders | Strict compliance requirements |

### Setting Up Encryption

Encryption can be configured at two levels:

**Agent-level encryption** (configured in the Agent):
```yaml
open-agent-auth:
  encryption-enabled: true
```

**Authorization Server encryption** (configured in the Authorization Server):
```yaml
open-agent-auth:
  authorization-server:
    prompt-encryption:
      enabled: true
      encryption-key-id: jwe-encryption-key-001
      encryption-algorithm: RSA-OAEP-256
      content-encryption-algorithm: A256GCM
```

### Choosing How Decisions Are Made

Control whether users are asked to confirm or if the system decides automatically:

```yaml
open-agent-auth:
  require-user-interaction: false  # Set to true for interactive mode
```

**Interactive mode** (`require-user-interaction: true`):
- Users see what was detected
- Users choose how to proceed
- Great for situations where you want review

**Automatic mode** (`require-user-interaction: false`):
- No interruption to workflow
- System follows intelligent defaults
- Everything gets logged for records
- Perfect for high-volume scenarios

---

## Using It in Your Code

### Basic Protection Example

Here's how to protect a prompt in your application:

```java
import com.alibaba.openagentauth.core.protocol.vc.chain.PromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionResult;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;

// Set up what you want to protect
ProtectionContext context = new ProtectionContext(
    "My API key is sk-1234567890abcdef",  // originalPrompt
    SanitizationLevel.MEDIUM,              // preferredLevel
    true,                                  // enableEncryption
    true                                   // requireConfirmation
);

// Apply protection
ProtectionResult result = protectionChain.protect(context);

// Check what happened
if (result.isSuccess()) {
    String protectedPrompt = result.getProtectedPrompt();
    boolean hasSensitiveInfo = result.hasSensitiveInfo();
    
    System.out.println("Protected prompt: " + protectedPrompt);
    System.out.println("Has sensitive info: " + hasSensitiveInfo);
}
```

### Understanding the ProtectionContext

The `ProtectionContext` is created using its constructor with these parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `originalPrompt` | String | The prompt text you want to protect (required) |
| `preferredLevel` | SanitizationLevel | How strict to be (NONE, LOW, MEDIUM, HIGH) |
| `enableEncryption` | boolean | Whether to encrypt with JWE |
| `requireConfirmation` | boolean | Whether to require user interaction |

**Example configurations**:

```java
// Strict protection with encryption
ProtectionContext strict = new ProtectionContext(
    prompt,
    SanitizationLevel.HIGH,
    true,  // encryption enabled
    true   // require confirmation
);

// Automatic mode without interaction
ProtectionContext automatic = new ProtectionContext(
    prompt,
    SanitizationLevel.MEDIUM,
    true,  // encryption enabled
    false  // no confirmation required
);

// Development mode
ProtectionContext dev = new ProtectionContext(
    prompt,
    SanitizationLevel.LOW,
    false, // no encryption
    false  // no confirmation
);
```

---

## Working with Security Standards

The Prompt Protection system is designed to work smoothly with industry security standards like WIMSE and Agent Operation Authorization.

### WIMSE Integration

The system respects workload identities and security contexts from WIMSE:

- **Knows who you are**: Protection decisions consider your workload identity
- **Follows your security policies**: Enforces rules based on your WIMSE context
- **Keeps track of context**: Maintains security information throughout the process
- **Creates an audit trail**: Records all protection decisions for your security audits

### Agent Operation Authorization Integration

The system aligns with Agent Operation Authorization specifications:

- **Records every decision**: Keeps track of what users decide
- **Enforces authorization policies**: Makes sure everything follows your rules
- **Stays compliant**: Ensures protection meets authorization requirements
- **Follows IETF standards**: Aligns with the latest Agent Operation Authorization draft specifications

---

## Keeping Your Data Safe

### Privacy First

- **Only the right people can read**: JWE encryption means only authorized parties can decrypt your prompts
- **Nothing gets stored**: Sensitive information isn't saved or logged anywhere
- **Everything stays in memory**: All processing happens without writing to disk
- **Meets regulations**: Helps you comply with GDPR, CCPA, HIPAA, and other requirements

### Stopping Threats

- **Prevents data leaks**: Stops sensitive data from reaching AI systems
- **Tracks everything**: Creates an audit trail of all protection decisions
- **Monitors compliance**: Lets you keep an eye on how well your data protection policies are working
- **Reduces risk**: Lowers the chance of data breaches and regulatory fines

### What You Should Do

1. **Pick the right sensitivity level**: Choose how strict you want protection to be based on your needs
2. **Turn on encryption**: Always use JWE encryption in production
3. **Use automatic mode when it makes sense**: Great for high-volume scenarios
4. **Keep an eye on things**: Set up monitoring and alerts for protection events
5. **Audit regularly**: Check your protection decisions and policies periodically
6. **Educate your users**: Help everyone understand why prompt protection matters

---

## Real-World Examples

### Example 1: Enterprise AI Assistant

**The situation**: Your company has an AI assistant that helps employees with various tasks. Employees might accidentally include sensitive company information in their prompts.

**How to handle it**:
- Use MEDIUM sensitivity level for good protection without being too strict
- Enable user interaction so employees see what's being detected
- Turn on JWE encryption to keep everything confidential
- Log all protection decisions for compliance records

**Configuration**:
```yaml
open-agent-auth:
  prompt-protection-enabled: true
  encryption-enabled: true
  sanitization-level: MEDIUM
  require-user-interaction: true
  authorization-server:
    prompt-encryption:
      enabled: true
      encryption-key-id: jwe-encryption-key-001
      encryption-algorithm: RSA-OAEP-256
      content-encryption-algorithm: A256GCM
```

### Example 2: Customer Support Chatbot

**The situation**: Your chatbot handles customer inquiries that might include personal information like names, email addresses, and phone numbers.

**How to handle it**:
- Use HIGH sensitivity level for maximum protection
- Enable automatic mode so customers don't have to stop and make decisions
- Turn on JWE encryption to protect customer data

**Configuration**:
```yaml
open-agent-auth:
  prompt-protection-enabled: true
  encryption-enabled: true
  sanitization-level: HIGH
  require-user-interaction: false
  authorization-server:
    prompt-encryption:
      enabled: true
      encryption-key-id: jwe-encryption-key-001
      encryption-algorithm: RSA-OAEP-256
      content-encryption-algorithm: A256GCM
```

### Example 3: Internal Development Tool

**The situation**: Your developers use an AI tool for code generation, and they might accidentally include API keys or secrets in their prompts.

**How to handle it**:
- Use LOW sensitivity level for development (less friction)
- Enable user interaction so developers can see what's detected
- Keep encryption off for development (turn it on in production!)

**Configuration**:
```yaml
open-agent-auth:
  prompt-protection-enabled: true
  encryption-enabled: false
  sanitization-level: LOW
  require-user-interaction: true
  authorization-server:
    prompt-encryption:
      enabled: false  # Development only!
```

---

## When Things Don't Work as Expected

### Problem: Sensitive Information Isn't Being Caught

**What might be happening**:
- Your sensitivity level is set too low
- The type of information isn't configured to be detected
- Detection rules aren't set up properly

**How to fix it**:
- Increase the sensitivity level to MEDIUM or HIGH
- Check that detection rules are configured correctly
- Look at the logs to see what's being detected

### Problem: Too Many False Alarms

**What might be happening**:
- Your sensitivity level is set too high
- Detection rules are too aggressive
- Normal content is matching sensitive patterns

**How to fix it**:
- Adjust the sensitivity level to something more reasonable
- Customize detection rules to reduce false positives
- Use INTERACTIVE mode so you can review and approve things manually

### Problem: Things Are Running Slow

**What might be happening**:
- Detection rules are too complex
- Prompts are very large
- You're processing a lot of requests

**How to fix it**:
- Simplify your detection rules
- Use AUTOMATIC mode for faster processing
- Set up caching for repeated prompts
- Consider scaling up your service

---

## Wrapping Up

Prompt Protection gives you a comprehensive way to keep sensitive information safe when using AI systems. By combining encryption, intelligent detection, and flexible decision-making, you can leverage AI capabilities while maintaining security and compliance.

**What you get**:
- **Multiple layers of protection**: Three different ways to keep your data safe
- **Standards compliance**: Works with IETF protocols like WIMSE and Agent Operation Authorization
- **Flexibility**: Configure it to match your needs
- **User control**: See what's happening and make informed decisions
- **Security**: Encrypt and clean sensitive information
- **Compliance**: Help meet regulatory requirements

**Want to learn more?**
- [Configuration Guide](04-configuration.md)
- [Security and Audit](../architecture/security/README.md)
- [Agent Operation Authorization Draft](../standard/draft-liu-agent-operation-authorization-01.txt)

---

## References

### Standards

- [RFC 7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516)
- [WIMSE Protocol Specification](https://datatracker.ietf.org/doc/draft-ietf-wimse-wimse/)
- [Agent Operation Authorization Draft](../standard/draft-liu-agent-operation-authorization-01.txt)

### Related Documentation

- [Configuration Guide](04-configuration.md)
- [Security and Audit](../architecture/security/README.md)
- [Identity and Workload Management](../architecture/identity/README.md)
