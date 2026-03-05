<script setup>
import { useData } from 'vitepress'

const { isDark } = useData()
</script>

<template>
  <div class="home-content">

    <!-- Quick Navigation -->
    <section class="quick-nav">
      <div class="section-header">
        <span class="section-label">Explore</span>
        <h2>Jump Right In</h2>
        <p class="section-desc">Everything you need to integrate enterprise-grade agent authorization.</p>
      </div>
      <div class="nav-grid">
        <a href="/open-agent-auth/docs/guide/01-quick-start" class="nav-card">
          <div class="nav-icon">🚀</div>
          <div class="nav-body">
            <h3>Quick Start</h3>
            <p>Get running in 5 minutes with the sample project.</p>
          </div>
          <span class="nav-arrow">→</span>
        </a>
        <a href="/open-agent-auth/docs/architecture/" class="nav-card">
          <div class="nav-icon">🏗️</div>
          <div class="nav-body">
            <h3>Architecture</h3>
            <p>Understand the zero-trust security model and token flow.</p>
          </div>
          <span class="nav-arrow">→</span>
        </a>
        <a href="/open-agent-auth/docs/api/00-api-overview" class="nav-card">
          <div class="nav-icon">📖</div>
          <div class="nav-body">
            <h3>API Reference</h3>
            <p>Actors, Executors, and Spring Boot Starter APIs.</p>
          </div>
          <span class="nav-arrow">→</span>
        </a>
        <a href="/open-agent-auth/docs/guide/03-integration-guide" class="nav-card">
          <div class="nav-icon">🔧</div>
          <div class="nav-body">
            <h3>Integration Guide</h3>
            <p>Role-based setup for Agent, AS, and Resource Server.</p>
          </div>
          <span class="nav-arrow">→</span>
        </a>
      </div>
    </section>

    <!-- How It Works -->
    <section class="how-it-works">
      <div class="section-header">
        <span class="section-label">How It Works</span>
        <h2>Three-Layer Cryptographic Binding</h2>
        <p class="section-desc">Every agent operation is authenticated, authorized, and auditable through a standards-based flow.</p>
      </div>
      <div class="flow-steps">
        <div class="flow-step">
          <div class="step-number">01</div>
          <div class="step-icon">👤</div>
          <h3>Authenticate</h3>
          <p>User authenticates via OpenID Connect. The Agent creates a virtual workload with temporary WIMSE credentials, binding user identity to a request-scoped environment.</p>
          <div class="step-token">ID Token → WIT</div>
        </div>
        <div class="flow-connector">
          <svg width="40" height="2" viewBox="0 0 40 2"><line x1="0" y1="1" x2="40" y2="1" stroke="currentColor" stroke-width="2" stroke-dasharray="4 4" /></svg>
        </div>
        <div class="flow-step">
          <div class="step-number">02</div>
          <div class="step-icon">🔐</div>
          <h3>Authorize</h3>
          <p>Agent submits an Operation Proposal via OAuth 2.0 PAR. The Authorization Server evaluates policies (OPA / RAM / ACL) and issues an Agent Operation Authorization Token.</p>
          <div class="step-token">WIT → AOAT</div>
        </div>
        <div class="flow-connector">
          <svg width="40" height="2" viewBox="0 0 40 2"><line x1="0" y1="1" x2="40" y2="1" stroke="currentColor" stroke-width="2" stroke-dasharray="4 4" /></svg>
        </div>
        <div class="flow-step">
          <div class="step-number">03</div>
          <div class="step-icon">🛡️</div>
          <h3>Verify & Execute</h3>
          <p>Resource Server performs five-layer verification — workload auth, request integrity, user auth, identity consistency, and policy evaluation — then executes the operation.</p>
          <div class="step-token">AOAT + WPT → Result</div>
        </div>
      </div>
      <div class="flow-cta">
        <a href="/open-agent-auth/docs/architecture/05-agent-authorization-flow" class="link-button">
          View Full Authorization Flow →
        </a>
      </div>
    </section>

    <!-- Why Open Agent Auth -->
    <section class="why-section">
      <div class="section-header">
        <span class="section-label">Why</span>
        <h2>Built for the AI Agent Era</h2>
        <p class="section-desc">Traditional authorization wasn't designed for agents acting on behalf of users.</p>
      </div>
      <div class="comparison-grid">
        <div class="comparison-card challenge">
          <div class="comparison-header">
            <span class="comparison-icon">⚠️</span>
            <span>Traditional Approach</span>
          </div>
          <ul>
            <li>Single-layer authentication — identity ambiguity</li>
            <li>Coarse-grained, static permissions</li>
            <li>Process-level isolation only</li>
            <li>Basic operation logs, no traceability</li>
          </ul>
        </div>
        <div class="comparison-card solution">
          <div class="comparison-header">
            <span class="comparison-icon">✅</span>
            <span>Open Agent Auth</span>
          </div>
          <ul>
            <li>Three-layer cryptographic identity binding</li>
            <li>Dynamic policy evaluation (OPA / RAM / ACL)</li>
            <li>Request-level virtual workload isolation</li>
            <li>W3C VC semantic audit trails</li>
          </ul>
        </div>
      </div>
    </section>

    <!-- Built On Standards -->
    <section class="standards-section">
      <div class="section-header">
        <span class="section-label">Foundation</span>
        <h2>Built on Open Standards</h2>
        <p class="section-desc">Leveraging battle-tested protocols for enterprise-grade security.</p>
      </div>
      <div class="standards-grid">
        <div class="standard-item">
          <div class="standard-name">OAuth 2.0</div>
          <div class="standard-role">Authorization</div>
        </div>
        <div class="standard-item">
          <div class="standard-name">OpenID Connect</div>
          <div class="standard-role">Identity</div>
        </div>
        <div class="standard-item">
          <div class="standard-name">WIMSE</div>
          <div class="standard-role">Workload Identity</div>
        </div>
        <div class="standard-item">
          <div class="standard-name">W3C VC</div>
          <div class="standard-role">Audit Trail</div>
        </div>
        <div class="standard-item">
          <div class="standard-name">MCP</div>
          <div class="standard-role">Tool Protocol</div>
        </div>
        <div class="standard-item">
          <div class="standard-name">IETF Draft</div>
          <div class="standard-role">Agent Auth Spec</div>
        </div>
      </div>
    </section>

    <!-- Bottom CTA -->
    <section class="bottom-cta">
      <div class="cta-content">
        <h2>Ready to Secure Your AI Agents?</h2>
        <p>Open Agent Auth is open-source under Apache 2.0. Star us on GitHub, try the sample project, or dive into the docs.</p>
        <div class="cta-buttons">
          <a href="/open-agent-auth/docs/guide/01-quick-start" class="cta-primary">
            Get Started →
          </a>
          <a href="https://github.com/alibaba/open-agent-auth" class="cta-secondary" target="_blank" rel="noopener">
            ⭐ Star on GitHub
          </a>
        </div>
      </div>
    </section>

  </div>
</template>

<style scoped>
.home-content {
  max-width: 1152px;
  margin: 0 auto;
  padding: 0 24px;
}

/* ─── Section Header ─── */
.section-header {
  text-align: center;
  margin-bottom: 3rem;
}

.section-label {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
  padding: 4px 12px;
  border-radius: 100px;
  margin-bottom: 1rem;
}

.section-header h2 {
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.2;
  color: var(--vp-c-text-1);
  margin: 0 0 0.75rem;
}

.section-desc {
  font-size: 1.1rem;
  color: var(--vp-c-text-2);
  max-width: 560px;
  margin: 0 auto;
  line-height: 1.6;
}

/* ─── Quick Navigation ─── */
.quick-nav {
  padding: 4rem 0 3rem;
}

.nav-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

@media (max-width: 768px) {
  .nav-grid {
    grid-template-columns: 1fr;
  }
}

.nav-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px 24px;
  border-radius: 12px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  text-decoration: none;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.nav-card:hover {
  border-color: var(--vp-c-brand-1);
  box-shadow: 0 4px 20px rgba(16, 185, 129, 0.08);
  transform: translateY(-2px);
}

.dark .nav-card:hover {
  box-shadow: 0 4px 20px rgba(16, 185, 129, 0.12);
}

.nav-icon {
  font-size: 1.75rem;
  flex-shrink: 0;
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--vp-c-brand-soft);
  border-radius: 10px;
}

.nav-body {
  flex: 1;
  min-width: 0;
}

.nav-body h3 {
  font-size: 1rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
  margin: 0 0 4px;
  line-height: 1.3;
}

.nav-body p {
  font-size: 0.875rem;
  color: var(--vp-c-text-2);
  margin: 0;
  line-height: 1.5;
}

.nav-arrow {
  font-size: 1.25rem;
  color: var(--vp-c-text-3);
  flex-shrink: 0;
  transition: color 0.2s, transform 0.2s;
}

.nav-card:hover .nav-arrow {
  color: var(--vp-c-brand-1);
  transform: translateX(4px);
}

/* ─── How It Works ─── */
.how-it-works {
  padding: 3rem 0;
}

.flow-steps {
  display: flex;
  align-items: flex-start;
  justify-content: center;
  gap: 0;
}

.flow-step {
  flex: 1;
  max-width: 320px;
  text-align: center;
  padding: 2rem 1.5rem;
  border-radius: 16px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  position: relative;
}

.flow-connector {
  display: flex;
  align-items: center;
  padding-top: 4rem;
  color: var(--vp-c-brand-2);
  flex-shrink: 0;
}

@media (max-width: 860px) {
  .flow-steps {
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }
  .flow-connector {
    transform: rotate(90deg);
    padding-top: 0;
  }
  .flow-step {
    max-width: 100%;
    width: 100%;
  }
}

.step-number {
  position: absolute;
  top: 12px;
  left: 16px;
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--vp-c-brand-1);
  font-family: var(--vp-font-family-mono);
}

.step-icon {
  font-size: 2rem;
  margin-bottom: 0.75rem;
}

.flow-step h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
  margin: 0 0 0.5rem;
}

.flow-step p {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  line-height: 1.6;
  margin: 0 0 1rem;
}

.step-token {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 600;
  font-family: var(--vp-font-family-mono);
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
  padding: 4px 12px;
  border-radius: 6px;
}

.flow-cta {
  text-align: center;
  margin-top: 2rem;
}

.link-button {
  display: inline-block;
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  text-decoration: none;
  padding: 8px 0;
  border-bottom: 2px solid transparent;
  transition: border-color 0.2s;
}

.link-button:hover {
  border-bottom-color: var(--vp-c-brand-1);
}

/* ─── Why Section ─── */
.why-section {
  padding: 3rem 0;
}

.comparison-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
}

@media (max-width: 640px) {
  .comparison-grid {
    grid-template-columns: 1fr;
  }
}

.comparison-card {
  padding: 24px 28px;
  border-radius: 14px;
  border: 1px solid var(--vp-c-divider);
}

.comparison-card.challenge {
  background: var(--vp-c-bg-soft);
}

.comparison-card.solution {
  background: var(--vp-c-brand-soft);
  border-color: rgba(16, 185, 129, 0.2);
}

.comparison-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.9rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.comparison-icon {
  font-size: 1.1rem;
}

.comparison-card ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.comparison-card li {
  font-size: 0.875rem;
  color: var(--vp-c-text-2);
  line-height: 1.6;
  padding: 6px 0;
  padding-left: 1.2em;
  position: relative;
}

.comparison-card li::before {
  content: '·';
  position: absolute;
  left: 0;
  font-weight: 700;
  color: var(--vp-c-text-3);
}

.comparison-card.solution li::before {
  content: '✓';
  color: var(--vp-c-brand-1);
  font-size: 0.8rem;
}

/* ─── Standards Section ─── */
.standards-section {
  padding: 3rem 0;
}

.standards-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
}

@media (max-width: 860px) {
  .standards-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}

@media (max-width: 480px) {
  .standards-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

.standard-item {
  text-align: center;
  padding: 20px 12px;
  border-radius: 12px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  transition: border-color 0.2s;
}

.standard-item:hover {
  border-color: var(--vp-c-brand-2);
}

.standard-name {
  font-size: 0.9rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
  margin-bottom: 4px;
}

.standard-role {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ─── Bottom CTA ─── */
.bottom-cta {
  padding: 3rem 0 5rem;
}

.cta-content {
  text-align: center;
  padding: 3.5rem 2rem;
  border-radius: 20px;
  background: linear-gradient(135deg, var(--vp-c-brand-soft) 0%, rgba(16, 185, 129, 0.04) 100%);
  border: 1px solid rgba(16, 185, 129, 0.15);
}

.cta-content h2 {
  font-size: 1.75rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  margin: 0 0 0.75rem;
}

.cta-content p {
  font-size: 1rem;
  color: var(--vp-c-text-2);
  max-width: 480px;
  margin: 0 auto 2rem;
  line-height: 1.6;
}

.cta-buttons {
  display: flex;
  justify-content: center;
  gap: 12px;
  flex-wrap: wrap;
}

.cta-primary {
  display: inline-flex;
  align-items: center;
  padding: 12px 28px;
  font-size: 0.95rem;
  font-weight: 600;
  color: #fff;
  background: var(--vp-button-brand-bg);
  border-radius: 10px;
  text-decoration: none;
  transition: background 0.2s;
}

.cta-primary:hover {
  background: var(--vp-button-brand-hover-bg);
}

.cta-secondary {
  display: inline-flex;
  align-items: center;
  padding: 12px 28px;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  background: var(--vp-c-bg);
  border: 1px solid var(--vp-c-divider);
  border-radius: 10px;
  text-decoration: none;
  transition: border-color 0.2s;
}

.cta-secondary:hover {
  border-color: var(--vp-c-brand-1);
}
</style>
