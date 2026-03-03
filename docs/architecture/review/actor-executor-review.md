# Actor Package & AgentAapExecutor Architecture Review

## Review Date: 2026-02-24

## 重要约束
- 所有修改、变动及新增的代码保持单测覆盖
- 在 JDK 17 环境下运行通过
- 运行通过后使用一行 commit message 进行 git commit
- **一定不要 push**

## JDK 17 环境
```bash
export JAVA_HOME=/Users/fudai.yf/Library/Java/JavaVirtualMachines/corretto-17.0.14/Contents/Home
```

---

## 问题清单与处理进度

### P0-1: Actor 与 Executor 的职责边界模糊
- **状态**: 待处理
- **问题**: `Agent` 接口承担了过多职责，既是 Actor（领域角色），又包含了协议流程编排逻辑。`AgentAapExecutor` 作为编排器，与 `Agent` 之间存在职责重叠。
- **具体表现**:
  - `Agent.initiateAuthorization()` 和 `AgentAapExecutor.initiateUserAuth()` 本质上是同一件事
  - `Agent.prepareAuthorizationContext()` 和 `AgentAapExecutor.buildAuthContext()` 也是如此
  - `DefaultAgentAapExecutor` 的大部分方法只是简单委托给 `Agent`
- **方案**: Actor 接口定义角色的原子能力（What），Executor 接口编排协议流程（How）。移除 `Agent` 中的编排级方法 `initiateAuthorization()` 和 `prepareAuthorizationContext()`，这些只在 Executor 中存在。
- **涉及文件**:
  - `Agent.java` - 移除 `initiateAuthorization()`，保留原子能力
  - `AgentAapExecutor.java` - 保持不变（已是编排层）
  - `DefaultAgentAapExecutor.java` - 调整委托逻辑

### P0-2: 继承体系设计不合理 — FrameworkOAuth2TokenClient 的滥用
- **状态**: 待处理
- **问题**: `AuthorizationServer extends FrameworkOAuth2TokenClient, FrameworkOAuth2TokenServer`，AS 同时是 Token Client 不合理。
- **方案**: `AuthorizationServer` 移除 `FrameworkOAuth2TokenClient` 继承。AS 与 AS User IDP 的交互通过内部组合实现。
- **涉及文件**:
  - `AuthorizationServer.java` - 移除 `FrameworkOAuth2TokenClient` 继承

### P1-1: 缺少 Executor 层的角色对称性
- **状态**: 待处理
- **问题**: 只有 `AgentAapExecutor` 一个 Executor，其他角色没有对应的 Executor。
- **方案**: 为 RS 提供 `ResourceServerAapExecutor`，为 AS 提供 `AuthorizationServerAapExecutor`，为 Agent IDP 提供 `AgentIdpAapExecutor`。
- **涉及文件**:
  - 新增 `ResourceServerAapExecutor.java`
  - 新增 `AuthorizationServerAapExecutor.java`
  - 新增 `AgentIdpAapExecutor.java`

### P1-2: AgentAapExecutor 接口方法命名不够专业
- **状态**: 待处理
- **问题**: 方法命名中 "Auth" 模糊，不符合 IETF 标准术语。
- **方案**:
  - `initiateUserAuth` → `initiateUserAuthentication`
  - `exchangeUserIdToken` → `exchangeAuthorizationCodeForIdToken`
  - `exchangeAgentAuthToken` → `exchangeAuthorizationCodeForAoat`
  - `buildAuthContext` → `buildAuthorizationContext`
  - `cleanup` → `revokeWorkloadAndCleanup`
- **涉及文件**:
  - `AgentAapExecutor.java`
  - `DefaultAgentAapExecutor.java`
  - 所有调用方

### P1-3: WorkloadContext 暴露了敏感信息
- **状态**: 待处理
- **问题**: `WorkloadContext` 包含 `privateKey` 字段并支持 Jackson 序列化，私钥可能被意外泄露。
- **方案**: 在 `privateKey` 上添加 `@JsonIgnore`，在 `toString()` 中脱敏。
- **涉及文件**:
  - `WorkloadContext.java`

### P2-1: ResourceServer 接口过于简单
- **状态**: 待处理
- **问题**: 只有 2 个方法，不够灵活可扩展。
- **方案**: 增加各层独立验证方法。
- **涉及文件**:
  - `ResourceServer.java`

### P2-2: Javadoc 中的 ASCII 流程图过于冗长
- **状态**: 待处理
- **问题**: `Agent.java` 有 573 行，约 400 行是 Javadoc 中的 ASCII 流程图。
- **方案**: 精简 Javadoc，将详细流程图移到 `docs/architecture/` 目录。
- **涉及文件**:
  - `Agent.java`

---

## Git Commit 记录
（每个问题处理完成后记录 commit message）

