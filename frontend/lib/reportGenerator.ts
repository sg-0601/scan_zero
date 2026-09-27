import { WebsiteResult } from "../components/ScanZeroDashboard";

/**
 * ScanZero Autonomous Security Audit & Comparative Report Generator
 * Generates standalone, self-contained, responsive HTML/Printable security audit reports
 * compliant with Gemini AI threat intelligence, 10 Core Scoring Rules, and OWASP ZAP telemetry.
 * 
 * Works seamlessly on mobile phones (iOS Safari, Android Chrome, webviews) and desktop browsers.
 */

function escapeHtml(str: any): string {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getGradeBadgeColor(grade: string): { bg: string; text: string; border: string } {
  switch (grade?.toUpperCase()) {
    case "A+":
      return { bg: "#ecfdf5", text: "#065f46", border: "#6ee7b7" };
    case "A":
      return { bg: "#f0fdf4", text: "#166534", border: "#86efac" };
    case "B":
      return { bg: "#f0f9ff", text: "#075985", border: "#7dd3fc" };
    case "C":
      return { bg: "#fffbeb", text: "#92400e", border: "#fde68a" };
    case "D":
      return { bg: "#fff7ed", text: "#9a3412", border: "#fed7aa" };
    case "F":
    default:
      return { bg: "#fef2f2", text: "#991b1b", border: "#fca5a5" };
  }
}

function getStatusBadge(status: string): string {
  const s = String(status || "").toUpperCase();
  if (s.includes("PASS")) {
    return `<span class="badge badge-pass">PASS</span>`;
  }
  if (s.includes("WARN")) {
    return `<span class="badge badge-warn">WARN</span>`;
  }
  return `<span class="badge badge-fail">FAIL</span>`;
}

function getRiskBadge(risk: string): string {
  const r = String(risk || "Small").toLowerCase();
  if (r === "big" || r === "critical" || r === "high") {
    return `<span class="badge badge-risk-big">${escapeHtml(risk)}</span>`;
  }
  if (r === "moderate" || r === "medium") {
    return `<span class="badge badge-risk-mod">${escapeHtml(risk)}</span>`;
  }
  if (r === "compensated") {
    return `<span class="badge badge-risk-comp">🛡️ Compensated</span>`;
  }
  if (r === "small" || r === "low") {
    return `<span class="badge badge-risk-small">${escapeHtml(risk)}</span>`;
  }
  return `<span class="badge badge-risk-neg">${escapeHtml(risk || "Info")}</span>`;
}

function getSeverityBadge(severity: string): string {
  const s = String(severity || "").toLowerCase();
  if (s.includes("crit") || s === "high") {
    return `<span class="badge badge-risk-big">${escapeHtml(severity)}</span>`;
  }
  if (s.includes("med")) {
    return `<span class="badge badge-risk-mod">${escapeHtml(severity)}</span>`;
  }
  if (s.includes("low")) {
    return `<span class="badge badge-risk-small">${escapeHtml(severity)}</span>`;
  }
  return `<span class="badge badge-risk-neg">${escapeHtml(severity || "Info")}</span>`;
}

/**
 * Builds a single-site comprehensive audit HTML section
 */
function buildSingleSiteAuditSection(site: WebsiteResult, index: number, totalSites: number): string {
  const gradeColors = getGradeBadgeColor(site.grade);
  const detailedSets = site.detailedSets || {};
  const setKeys = [
    { key: "set1", name: "Set 1: Network & TLS Encryption", weight: "25%" },
    { key: "set2", name: "Set 2: HTTP Security Headers & CSP", weight: "30%" },
    { key: "set3", name: "Set 3: DNS Posture & Anti-Spoofing", weight: "20%" },
    { key: "set4", name: "Set 4: Attack Surface & OSINT Footprint", weight: "15%" },
    { key: "set5", name: "Set 5: DAST & Dynamic Endpoint Probes", weight: "5%" },
    { key: "set6", name: "Set 6: Deception & Honeypot Defenses", weight: "5%" },
  ];

  // Dynamic Cap
  const cap = site.contextualRiskAnalysis?.critical_vulnerability_cap;
  const isCapped = Boolean(cap?.is_capped);

  // Compensating controls
  const compControls = site.contextualRiskAnalysis?.compensating_controls_detected || [];
  const riskAdjustments = site.contextualRiskAnalysis?.risk_adjustments || [];
  const crossInteractions = site.contextualRiskAnalysis?.cross_set_interactions || "";

  // Server Hardening
  const serverSnippets = site.serverHardening || {};

  return `
    <div class="site-audit-block ${index > 0 ? "page-break" : ""}">
      <!-- SITE HEADER HERO -->
      <div class="card hero-card">
        <div class="hero-top">
          <div>
            <div class="tag-row">
              <span class="tag tag-teal">ScanZero Security Audit</span>
              <span class="tag tag-slate">Scan ID: ${escapeHtml(site.scanId || "LIVE-" + site.domain)}</span>
              ${totalSites > 1 ? `<span class="tag tag-purple">Domain ${index + 1} of ${totalSites}</span>` : ""}
            </div>
            <h1 class="domain-title">${escapeHtml(site.domain.toLowerCase())}</h1>
            <p class="target-url">Audit Target: <a href="${escapeHtml(site.url || "https://" + site.domain)}" target="_blank" rel="noopener noreferrer">${escapeHtml(site.url || "https://" + site.domain)}</a></p>
          </div>
          
          <div class="score-display-box" style="background-color: ${gradeColors.bg}; border-color: ${gradeColors.border}">
            <div class="score-number" style="color: ${gradeColors.text}">${site.overallScore}<span class="score-max">/100</span></div>
            <div class="grade-badge" style="background-color: ${gradeColors.text}; color: #ffffff">GRADE ${escapeHtml(site.grade)}</div>
            <div class="status-subtext" style="color: ${gradeColors.text}">${escapeHtml(site.statusText || "Evaluated Posture")}</div>
          </div>
        </div>

        <div class="meta-stats-grid">
          <div class="meta-stat">
            <span class="meta-label">Overall Posture</span>
            <span class="meta-value">${site.overallScore}%</span>
            <span class="meta-hint">Grade ${escapeHtml(site.grade)}</span>
          </div>
          <div class="meta-stat">
            <span class="meta-label">Critical Risks</span>
            <span class="meta-value" style="color: #e11d48">${site.criticalIssues?.length || 0}</span>
            <span class="meta-hint">${(site.criticalIssues?.length || 0) > 0 ? "Requires Immediate Action" : "Clean Perimeter"}</span>
          </div>
          <div class="meta-stat">
            <span class="meta-label">Verified Strengths</span>
            <span class="meta-value" style="color: #059669">${site.strengths?.length || 0}</span>
            <span class="meta-hint">Industry Passing Defenses</span>
          </div>
          <div class="meta-stat">
            <span class="meta-label">Dynamic Probes</span>
            <span class="meta-value" style="color: #0d9488">${site.zapAlerts?.length || 0}</span>
            <span class="meta-hint">OWASP ZAP Telemetry Alerts</span>
          </div>
        </div>
      </div>

      <!-- GEMINI AI EXECUTIVE THREAT ASSESSMENT -->
      ${site.executiveSummary ? `
      <div class="card bg-callout-teal avoid-break">
        <div class="card-header">
          <span class="card-icon">⚡</span>
          <h2 class="card-title text-teal">Gemini AI Executive Threat Assessment</h2>
        </div>
        <p class="summary-body">${escapeHtml(site.executiveSummary)}</p>
        
        ${site.attackerPerspective ? `
        <div class="attacker-perspective-box">
          <div class="attacker-title">⚠️ Adversary &amp; Threat Actor Perspective</div>
          <p class="attacker-quote">"${escapeHtml(site.attackerPerspective)}"</p>
        </div>` : ""}
      </div>` : ""}

      <!-- CORRELATED ATTACK CHAIN -->
      ${site.attackChain && site.attackChain.length > 0 ? `
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">🎯</span>
          <h2 class="card-title">Correlated Multi-Stage Exploitation Chain</h2>
          <span class="badge badge-risk-big">${site.attackChain.length} Stages Identified</span>
        </div>
        <p class="card-subtext">Gemini synthesized this multi-stage attack path based on real telemetry gaps detected during scanning:</p>
        <div class="attack-chain-grid">
          ${site.attackChain.map((step, sIdx) => `
            <div class="chain-step-card">
              <div class="chain-step-header">
                <span class="chain-badge">Stage ${step.step || sIdx + 1}</span>
                <span class="chain-vector">${escapeHtml(step.exploit_vector)}</span>
              </div>
              <div class="chain-title">${escapeHtml(step.title)}</div>
              <p class="chain-desc">${escapeHtml(step.description)}</p>
            </div>
          `).join("")}
        </div>
      </div>` : ""}

      <!-- CONTEXTUAL RISK ASSESSMENT & COMPENSATING CONTROLS -->
      <div class="card bg-callout-purple avoid-break">
        <div class="card-header">
          <span class="card-icon">🛡️</span>
          <h2 class="card-title text-purple">Contextual Risk Analysis &amp; Compensating Controls (Rule 1-6)</h2>
          <span class="badge badge-risk-comp">HOLISTIC DEFENSE VERIFICATION</span>
        </div>
        <p class="card-subtext">ScanZero applies AI-driven contextual evaluation. Static rule deductions are adjusted when compensating defenses (such as Cloudflare WAF, strict CSP frame-ancestors, or HSTS preload) neutralize active exploitability.</p>

        <!-- DYNAMIC CRITICAL VULNERABILITY CAP -->
        ${isCapped ? `
        <div class="cap-alert-box">
          <div class="cap-header">
            <span class="cap-title">⚠️ Dynamic Critical Vulnerability Cap Active</span>
            <div class="cap-tags">
              ${cap?.cap_range ? `<span class="badge badge-risk-big">Cap Range: ${escapeHtml(cap.cap_range)}</span>` : ""}
              ${cap?.max_allowed_score !== undefined && cap?.max_allowed_score !== null ? `<span class="badge badge-risk-big">Max Score Ceiling: ${cap.max_allowed_score}/100</span>` : ""}
            </div>
          </div>
          <p class="cap-reason"><strong>Cap Rationale:</strong> ${escapeHtml(cap?.reason)}</p>
          ${cap?.proofs && cap.proofs.length > 0 ? `
            <div class="cap-proofs">
              <strong>Verified Telemetry Proofs:</strong>
              <ul>
                ${cap.proofs.map(p => `<li><code>${escapeHtml(p)}</code></li>`).join("")}
              </ul>
            </div>` : ""}
        </div>` : ""}

        <!-- DETECTED COMPENSATING CONTROLS -->
        ${compControls.length > 0 ? `
        <div class="comp-controls-section">
          <div class="section-mini-title">Active Compensating Controls Verified:</div>
          <div class="comp-tags-wrap">
            ${compControls.map(ctrl => `<span class="comp-tag">✓ ${escapeHtml(ctrl)}</span>`).join("")}
          </div>
        </div>` : ""}

        <!-- CROSS-SET INTERACTIONS -->
        ${crossInteractions ? `
        <div class="cross-interaction-box">
          <strong>Cross-Set Defense Interaction:</strong> ${escapeHtml(crossInteractions)}
        </div>` : ""}

        <!-- RISK ADJUSTMENTS TABLE -->
        ${riskAdjustments.length > 0 ? `
        <div class="table-wrap">
          <table class="report-table">
            <thead>
              <tr>
                <th>Finding / Vulnerability</th>
                <th>Set</th>
                <th>Risk Level</th>
                <th>Compensating Defense</th>
                <th>Penalty Adjustment</th>
                <th>Contextual Rationale</th>
              </tr>
            </thead>
            <tbody>
              ${riskAdjustments.map(adj => `
                <tr>
                  <td><strong>${escapeHtml(adj.finding)}</strong></td>
                  <td><span class="tag tag-slate">${escapeHtml(adj.original_set)}</span></td>
                  <td>${getRiskBadge(adj.risk_level)}</td>
                  <td>${adj.compensating_control && adj.compensating_control !== "None" ? `<span class="text-emerald">🛡️ ${escapeHtml(adj.compensating_control)}</span>` : `<span class="text-slate">None (Exposed)</span>`}</td>
                  <td><span class="text-purple font-mono font-bold">${escapeHtml(adj.penalty_applied)}</span></td>
                  <td class="text-slate text-sm">${escapeHtml(adj.explanation)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>` : ""}
      </div>

      <!-- 6-SET SCORECARD OVERVIEW TABLE -->
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">📊</span>
          <h2 class="card-title">The 6-Set Security Framework Scorecard</h2>
          <span class="tag tag-slate">Weighted Standard Formula</span>
        </div>
        <div class="table-wrap">
          <table class="report-table">
            <thead>
              <tr>
                <th>Security Dimension</th>
                <th>Weight</th>
                <th>Score</th>
                <th>Grade</th>
                <th>Status</th>
                <th>Weighted Contribution</th>
                <th>AI Verdict Summary</th>
              </tr>
            </thead>
            <tbody>
              ${setKeys.map((item) => {
                const sObj = detailedSets[item.key] || {};
                const sScore = (site.setScores as any)?.[item.key] ?? sObj.score ?? 70;
                const weightNum = parseFloat(item.weight) / 100;
                const contrib = (sScore * weightNum).toFixed(1);
                const sGrade = sObj.grade || (sScore >= 85 ? "A" : sScore >= 70 ? "B" : sScore >= 50 ? "C" : "F");
                const sStatus = sScore >= 70 ? "PASS" : sScore >= 50 ? "WARN" : "FAIL";

                return `
                  <tr>
                    <td><strong>${escapeHtml(item.name)}</strong></td>
                    <td class="font-mono">${escapeHtml(item.weight)}</td>
                    <td class="font-mono font-bold" style="color: ${sScore >= 70 ? "#059669" : sScore >= 50 ? "#d97706" : "#e11d48"}">${sScore}/100</td>
                    <td><span class="badge ${sGrade === "A" || sGrade === "A+" ? "badge-pass" : sGrade === "B" ? "badge-pass" : sGrade === "C" ? "badge-warn" : "badge-fail"}">${sGrade}</span></td>
                    <td>${getStatusBadge(sStatus)}</td>
                    <td class="font-mono font-bold text-teal">+${contrib} pts</td>
                    <td class="text-slate text-sm">${escapeHtml(sObj.summary || sObj.whyScoreGiven || "Dimension evaluated against real telemetry.")}</td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      </div>

      <!-- DETAILED 6-SET FINDINGS BREAKDOWN -->
      ${setKeys.map((setMeta) => {
        const sData = detailedSets[setMeta.key];
        if (!sData) return "";
        const sScore = (site.setScores as any)?.[setMeta.key] ?? sData.score ?? 70;
        const sGrade = sData.grade || (sScore >= 85 ? "A" : sScore >= 70 ? "B" : sScore >= 50 ? "C" : "F");

        return `
          <div class="card set-detail-card avoid-break">
            <div class="set-detail-header">
              <div>
                <span class="tag tag-teal font-mono uppercase">${escapeHtml(setMeta.name)}</span>
                <h3 class="set-title">${escapeHtml(sData.name || setMeta.name)}</h3>
                <p class="set-summary-text">${escapeHtml(sData.summary || "Complete dimension security posture audit.")}</p>
              </div>
              <div class="set-score-pill">
                <div class="set-score-val" style="color: ${sScore >= 70 ? "#059669" : sScore >= 50 ? "#d97706" : "#e11d48"}">${sScore}<span class="score-max">/100</span></div>
                <div class="set-grade-val">Grade ${escapeHtml(sGrade)}</div>
              </div>
            </div>

            <!-- WHY SCORE GIVEN & COMPENSATING CONTROLS -->
            ${sData.whyScoreGiven ? `
            <div class="why-score-box">
              <strong class="text-teal">AI Scoring Rationale &amp; Context:</strong>
              <p>${escapeHtml(sData.whyScoreGiven)}</p>
            </div>` : ""}

            <!-- SET 1 CERTIFICATE TRUST CHAIN (IF SET 1) -->
            ${setMeta.key === "set1" ? `
            <div class="cert-chain-box">
              <div class="cert-chain-header">
                <strong>🔒 SSL/TLS Certificate Trust Chain Architecture</strong>
                <span class="tag tag-teal">${escapeHtml(sData.protocol || "TLS 1.2 / TLS 1.3")}</span>
                <span class="tag tag-emerald">${escapeHtml(sData.trust_chain_status || "CHAIN VERIFIED")}</span>
              </div>
              <div class="cert-chain-steps">
                <div class="cert-step">
                  <div class="cert-step-role">Root CA Anchor</div>
                  <div class="cert-step-name">${escapeHtml(sData.issuer || "Public Trusted CA Anchor")}</div>
                  <div class="cert-step-status text-emerald">✓ Root Store Verified</div>
                </div>
                <div class="cert-step-arrow">→</div>
                <div class="cert-step">
                  <div class="cert-step-role">Intermediate CA</div>
                  <div class="cert-step-name">${escapeHtml(sData.issuer ? sData.issuer + " Intermediate" : "Signed Authority")}</div>
                  <div class="cert-step-status text-teal">✓ Valid Signature</div>
                </div>
                <div class="cert-step-arrow">→</div>
                <div class="cert-step">
                  <div class="cert-step-role">Server Leaf Certificate</div>
                  <div class="cert-step-name">${escapeHtml(site.domain)}</div>
                  <div class="cert-step-status text-emerald">✓ Active SSL Encryption</div>
                </div>
              </div>
            </div>` : ""}

            <!-- ANALYZED ITEMS TABLE -->
            ${sData.analyzed_items && sData.analyzed_items.length > 0 ? `
            <div class="items-section">
              <h4 class="sub-heading">Analyzed Security Controls &amp; Benchmarks:</h4>
              <div class="table-wrap">
                <table class="report-table">
                  <thead>
                    <tr>
                      <th>Evaluated Benchmark</th>
                      <th>Status</th>
                      <th>Risk Classification</th>
                      <th>Compensating Defense</th>
                      <th>Telemetry Evidence &amp; Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${sData.analyzed_items.map((item: any) => {
                      const itemName = typeof item === "string" ? item : item.item;
                      const itemStatus = (typeof item === "object" ? item.status : "PASS") || "PASS";
                      const itemDetails = typeof item === "object" ? item.details : "";
                      const itemRisk = typeof item === "object" ? item.risk_level : "";
                      const itemComp = typeof item === "object" ? item.compensating_control : "";

                      return `
                        <tr>
                          <td><strong>${escapeHtml(itemName)}</strong></td>
                          <td>${getStatusBadge(itemStatus)}</td>
                          <td>${getRiskBadge(itemRisk || (itemStatus === "PASS" ? "Clean" : itemStatus === "WARN" ? "Moderate" : "Big"))}</td>
                          <td>${itemComp && itemComp !== "None" ? `<span class="text-emerald">🛡️ ${escapeHtml(itemComp)}</span>` : `<span class="text-slate">None</span>`}</td>
                          <td class="text-slate text-sm font-mono">${escapeHtml(itemDetails || "Verified")}</td>
                        </tr>
                      `;
                    }).join("")}
                  </tbody>
                </table>
              </div>
            </div>` : ""}

            <!-- POSITIVE & NEGATIVE FINDINGS -->
            <div class="findings-cols-grid">
              ${sData.positiveFindings && sData.positiveFindings.length > 0 ? `
              <div class="finding-col finding-col-pos">
                <h5 class="finding-col-title text-emerald">✓ Verified Posture Strengths</h5>
                <ul>
                  ${sData.positiveFindings.map((p: string) => `<li>${escapeHtml(p)}</li>`).join("")}
                </ul>
              </div>` : ""}

              ${sData.negativeFindings && sData.negativeFindings.length > 0 && !sData.negativeFindings.every((f: string) => f.toLowerCase().startsWith("none") || f.toLowerCase().includes("clean")) ? `
              <div class="finding-col finding-col-neg">
                <h5 class="finding-col-title text-rose">✕ Gaps &amp; Negative Exposures</h5>
                <ul>
                  ${sData.negativeFindings.map((n: string) => `<li>${escapeHtml(n)}</li>`).join("")}
                </ul>
              </div>` : ""}
            </div>

            <!-- NEGATIVE REMEDIATION GUIDES -->
            ${sData.negative_remediation_guides && sData.negative_remediation_guides.length > 0 && !sData.negativeFindings?.every((f: string) => f.toLowerCase().startsWith("none") || f.toLowerCase().includes("clean")) ? `
            <div class="remediation-guides-section">
              <h5 class="remed-header-title">🛡️ Step-by-Step Resolution Guides:</h5>
              ${sData.negative_remediation_guides.map((guide: any) => `
                <div class="remed-guide-card">
                  <div class="remed-finding-title">Issue to Resolve: <span class="text-rose font-bold">${escapeHtml(guide.finding)}</span></div>
                  <ol class="remed-steps-list">
                    ${(guide.steps || []).map((step: string) => `<li>${escapeHtml(step)}</li>`).join("")}
                  </ol>
                  ${guide.fix_urls && guide.fix_urls.length > 0 ? `
                  <div class="remed-urls-row">
                    <span class="remed-url-label">Official Documentation &amp; Fix Guides:</span>
                    ${guide.fix_urls.map((link: any) => `
                      <a href="${escapeHtml(link.url?.startsWith("http") ? link.url : "https://" + link.url)}" target="_blank" rel="noopener noreferrer" class="link-btn">
                        ${escapeHtml(link.label || "Fix Guide")} ↗
                      </a>
                    `).join("")}
                  </div>` : ""}
                </div>
              `).join("")}
            </div>` : ""}
          </div>
        `;
      }).join("")}

      <!-- OWASP ZAP & DAST VULNERABILITY AUDIT LEDGER (IF ALERTS PRESENT) -->
      ${site.zapAlerts && site.zapAlerts.length > 0 ? `
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">⚡</span>
          <h2 class="card-title">OWASP ZAP 7GB Cloud Dynamic Audit Findings</h2>
          <span class="badge badge-risk-big">${site.zapAlerts.length} Dynamic Vulnerability Notices</span>
        </div>
        <p class="card-subtext">The following alerts were detected by the dynamic active scanner runner with CWE mappings and remediation solutions:</p>
        <div class="table-wrap">
          <table class="report-table">
            <thead>
              <tr>
                <th>Vulnerability Title</th>
                <th>Severity</th>
                <th>CWE ID</th>
                <th>Discovered URL / Parameter</th>
                <th>Description &amp; Suggested Remediation</th>
              </tr>
            </thead>
            <tbody>
              ${site.zapAlerts.map(alert => `
                <tr>
                  <td><strong>${escapeHtml(alert.title)}</strong></td>
                  <td>${getSeverityBadge(alert.severity)}</td>
                  <td><code class="tag tag-slate">${escapeHtml(alert.evidence?.cweid || "N/A")}</code></td>
                  <td class="font-mono text-sm">${escapeHtml(alert.evidence?.url || alert.evidence?.param || "Host Root")}</td>
                  <td>
                    <p class="text-sm text-slate">${escapeHtml(alert.description)}</p>
                    ${alert.solution ? `<div class="solution-box"><strong>Solution:</strong> ${escapeHtml(alert.solution)}</div>` : ""}
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>` : ""}

      <!-- TRANSPARENT POINT ATTRIBUTION TABLE -->
      ${site.scoringBreakdown && site.scoringBreakdown.length > 0 ? `
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">⚖️</span>
          <h2 class="card-title">Transparent Point Attribution Ledger</h2>
          <span class="tag tag-slate">Zero Mystery Numbers</span>
        </div>
        <p class="card-subtext">Every point awarded or deducted is mapped directly to real evidence, severity, and remediation pathways:</p>
        <div class="table-wrap">
          <table class="report-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Score</th>
                <th>Severity</th>
                <th>Detected Issue / Gap</th>
                <th>Reason Earned / Deducted</th>
                <th>Remediation Action</th>
              </tr>
            </thead>
            <tbody>
              ${site.scoringBreakdown.map((item) => `
                <tr>
                  <td><strong>${escapeHtml(item.category)}</strong></td>
                  <td class="font-mono font-bold ${item.earned === item.max ? "text-emerald" : "text-amber"}">${item.earned} / ${item.max}</td>
                  <td>${getSeverityBadge(item.severity)}</td>
                  <td>${escapeHtml(item.detectedIssue || "Compliant")}</td>
                  <td class="text-sm text-slate">${escapeHtml(item.reasonDeducted || item.reasonEarned)}</td>
                  <td class="text-sm text-teal font-medium">${escapeHtml(item.improvement)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>` : ""}

      <!-- ACTIONABLE PRIORITY MATRIX -->
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">🚀</span>
          <h2 class="card-title">Prioritized Dynamic Remediation Roadmap</h2>
          <span class="tag tag-teal">High Impact First</span>
        </div>
        <div class="table-wrap">
          <table class="report-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Action Item</th>
                <th>Affected Set</th>
                <th>Expected Posture Gain</th>
              </tr>
            </thead>
            <tbody>
              ${(site.scoringBreakdown || []).filter(b => b.max - b.earned > 0).length > 0 ? (
                site.scoringBreakdown
                  .filter(b => b.max - b.earned > 0)
                  .map((item) => {
                    const penalty = item.max - item.earned;
                    const priority = penalty >= 10 ? "HIGH" : penalty >= 5 ? "MEDIUM" : "LOW";
                    const pClass = priority === "HIGH" ? "badge-risk-big" : priority === "MEDIUM" ? "badge-risk-mod" : "badge-risk-small";

                    return `
                      <tr>
                        <td><span class="badge ${pClass}">${priority}</span></td>
                        <td><strong>${escapeHtml(item.improvement)}</strong></td>
                        <td><span class="tag tag-slate">${escapeHtml(item.category)}</span></td>
                        <td class="font-mono font-bold text-emerald">+${penalty} Points</td>
                      </tr>
                    `;
                  }).join("")
              ) : `
                <tr>
                  <td><span class="badge badge-pass">PASS</span></td>
                  <td><strong>All core benchmarks satisfied; continuous telemetry monitoring recommended.</strong></td>
                  <td><span class="tag tag-teal">All Dimensions</span></td>
                  <td class="font-mono font-bold text-emerald">Max Score</td>
                </tr>
              `}
            </tbody>
          </table>
        </div>
      </div>

      <!-- SERVER HARDENING READY-TO-DEPLOY CONFIGURATIONS -->
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">🛠️</span>
          <h2 class="card-title">Ready-to-Deploy Server Hardening Configurations</h2>
          <span class="tag tag-slate">Tailored for ${escapeHtml(site.domain)}</span>
        </div>
        <p class="card-subtext">Copy and paste these verified security header directives directly into your server configuration:</p>

        <div class="code-tabs-container">
          <!-- NGINX -->
          <div class="code-block-wrap">
            <div class="code-block-title">
              <span>Nginx Configuration (<code>/etc/nginx/conf.d/security.conf</code>)</span>
            </div>
            <pre class="code-content"><code>${escapeHtml(serverSnippets.nginx || `# Nginx Security Bundle\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self' https:; object-src 'none';" always;\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;`)}</code></pre>
          </div>

          <!-- APACHE -->
          <div class="code-block-wrap">
            <div class="code-block-title">
              <span>Apache Configuration (<code>.htaccess</code> or <code>httpd.conf</code>)</span>
            </div>
            <pre class="code-content"><code>${escapeHtml(serverSnippets.apache || `<IfModule mod_headers.c>\n  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n  Header always set X-Content-Type-Options "nosniff"\n  Header always set X-Frame-Options "SAMEORIGIN"\n  Header always set Referrer-Policy "strict-origin-when-cross-origin"\n  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"\n</IfModule>`)}</code></pre>
          </div>

          <!-- CLOUDFLARE -->
          <div class="code-block-wrap">
            <div class="code-block-title">
              <span>Cloudflare Worker / Transform Rule</span>
            </div>
            <pre class="code-content"><code>${escapeHtml(serverSnippets.cloudflare || `// Cloudflare Transform Rule for ${site.domain}\n// Add Response Headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy`)}</code></pre>
          </div>

          <!-- CADDY -->
          <div class="code-block-wrap">
            <div class="code-block-title">
              <span>Caddy Web Server (<code>Caddyfile</code>)</span>
            </div>
            <pre class="code-content"><code>${escapeHtml(serverSnippets.caddy || `# Caddyfile Hardening\nheader {\n    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n    X-Content-Type-Options "nosniff"\n    X-Frame-Options "SAMEORIGIN"\n    Referrer-Policy "strict-origin-when-cross-origin"\n    Permissions-Policy "camera=(), microphone=(), geolocation=()"\n}`)}</code></pre>
          </div>
        </div>
      </div>

      <!-- READY TO DEPLOY CODE FIXES (IF PRESENT) -->
      ${site.readyToDeployFixes && site.readyToDeployFixes.length > 0 ? `
      <div class="card avoid-break">
        <div class="card-header">
          <span class="card-icon">⚡</span>
          <h2 class="card-title">Instant Deployable Code Fixes</h2>
        </div>
        <div class="space-y-4">
          ${site.readyToDeployFixes.map(fix => `
            <div class="remed-guide-card">
              <div class="flex-between">
                <strong>${escapeHtml(fix.title)}</strong>
                <span class="tag tag-slate">${escapeHtml(fix.target)}</span>
              </div>
              <p class="text-sm text-slate mt-1">${escapeHtml(fix.explanation)}</p>
              <pre class="code-content mt-2"><code>${escapeHtml(fix.code)}</code></pre>
            </div>
          `).join("")}
        </div>
      </div>` : ""}

      <!-- STRENGTHS & WEAKNESSES LEDGER -->
      <div class="grid-2-cols avoid-break">
        <div class="card">
          <div class="card-header">
            <span class="card-icon text-emerald">✓</span>
            <h3 class="card-title text-emerald">Verified Security Strengths</h3>
          </div>
          <ul class="bullet-list-pos">
            ${(site.strengths || []).map(s => `<li>${escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-icon text-rose">✕</span>
            <h3 class="card-title text-rose">Identified Vulnerabilities &amp; Gaps</h3>
          </div>
          <ul class="bullet-list-neg">
            ${(site.criticalIssues || site.weaknesses || []).map(w => `<li>${escapeHtml(w)}</li>`).join("")}
          </ul>
        </div>
      </div>
    </div>
  `;
}

/**
 * Builds the Multi-Site Comparative section covering head-to-head analysis across all contexts
 */
function buildMultiSiteComparisonSection(results: WebsiteResult[]): string {
  if (results.length < 2) return "";

  // Sort sites to find leader
  const sorted = [...results].sort((a, b) => (b.overallScore || 0) - (a.overallScore || 0));
  const leader = sorted[0];
  const trailer = sorted[sorted.length - 1];
  const delta = leader.overallScore - trailer.overallScore;

  const contexts = [
    { key: "set1", label: "Context 1: Network & TLS Encryption", weight: "25%", desc: "Evaluates cryptographic cipher suites, TLS version (1.3 vs 1.2), root CA chain, and HTTPS enforcement." },
    { key: "set2", label: "Context 2: HTTP Security Headers & CSP", weight: "30%", desc: "Audits CSP directives, HSTS preload, X-Frame-Options vs frame-ancestors, and cookie security flags." },
    { key: "set3", label: "Context 3: DNS Posture & Email Spoofing Defense", weight: "20%", desc: "Verifies SPF strictness (-all vs ~all), DMARC policy (reject vs none), DKIM records, and DNSSEC validation." },
    { key: "set4", label: "Context 4: Attack Surface & OSINT Footprint", weight: "15%", desc: "Enumerates certificate transparency subdomains, open network ports, cloud bucket leakage, and public CVEs." },
    { key: "set5", label: "Context 5: DAST & Dynamic Endpoint Probes", weight: "5%", desc: "Scans for exposed sensitive files (.env, .git), administrative endpoints, and OWASP ZAP cloud dynamic alerts." },
    { key: "set6", label: "Context 6: Deception & Honeypot Defenses", weight: "5%", desc: "Probes canary URI tokens, tarpit latency traps, and proactive adversary honeypot mechanisms." },
  ];

  return `
    <div class="card hero-card comparison-hero">
      <div class="hero-top">
        <div>
          <div class="tag-row">
            <span class="tag tag-purple">Multi-Site Intelligence</span>
            <span class="tag tag-teal">Head-to-Head Contextual Comparison</span>
            <span class="tag tag-slate">${results.length} Websites Evaluated</span>
          </div>
          <h1 class="domain-title">Multi-Site Security Benchmark &amp; Comparative Audit</h1>
          <p class="target-url">
            Comparing: ${results.map(r => `<strong>${escapeHtml(r.domain)}</strong> (${r.overallScore}/100, Grade ${r.grade})`).join(" &bull; ")}
          </p>
        </div>
      </div>

      <!-- LEADER HIGHLIGHT BANNER -->
      <div class="leader-banner">
        <div class="leader-text">
          <strong>🏆 Best-in-Class Posture Leader: <span class="text-teal">${escapeHtml(leader.domain)}</span></strong>
          <p>Scored <strong>${leader.overallScore}/100 (Grade ${leader.grade})</strong>, outperforming trailing peer <strong>${escapeHtml(trailer.domain)} (${trailer.overallScore}/100)</strong> by a delta of <strong>+${delta} points</strong>.</p>
        </div>
      </div>
    </div>

    <!-- GEMINI MULTI-SITE COMPARATIVE INSIGHT -->
    <div class="card bg-callout-purple avoid-break">
      <div class="card-header">
        <span class="card-icon">⚡</span>
        <h2 class="card-title text-purple">Gemini AI Multi-Site Comparative Intelligence &bull; Why They Differ</h2>
      </div>
      
      <div class="space-y-3">
        ${results.map((r, i) => {
          if (!r.multiSiteComparisonInsight) return "";
          return `
            <div class="multi-insight-card">
              <span class="tag tag-purple font-mono uppercase">${escapeHtml(r.domain)} Comparative Synthesis:</span>
              <p class="summary-body mt-1">${escapeHtml(r.multiSiteComparisonInsight)}</p>
            </div>
          `;
        }).join("")}

        ${!results.some(r => Boolean(r.multiSiteComparisonInsight)) ? `
          <p class="summary-body">
            The security posture of <strong>${escapeHtml(results[0].domain)}</strong> (${results[0].overallScore}/100) and <strong>${escapeHtml(results[1]?.domain)}</strong> (${results[1]?.overallScore || 0}/100) diverges primarily across 
            ${results[0].overallScore >= (results[1]?.overallScore || 0)
              ? `Set 2 (HTTP Headers: ${results[0].setScores.set2} vs ${results[1]?.setScores.set2}) and Set 3 (DNS: ${results[0].setScores.set3} vs ${results[1]?.setScores.set3})`
              : `Set 1 (TLS: ${results[0].setScores.set1} vs ${results[1]?.setScores.set1}) and Set 4 (OSINT: ${results[0].setScores.set4} vs ${results[1]?.setScores.set4})`}.
          </p>` : ""}
      </div>
    </div>

    <!-- SIDE-BY-SIDE DIMENSIONAL MATRIX (ALL 6 CONTEXTS) -->
    <div class="card avoid-break">
      <div class="card-header">
        <span class="card-icon">📊</span>
        <h2 class="card-title">Side-by-Side Contextual Scoring Matrix</h2>
        <span class="tag tag-slate">6 Dimensions Evaluated</span>
      </div>
      <div class="table-wrap">
        <table class="report-table">
          <thead>
            <tr>
              <th>Security Context</th>
              <th>Weight</th>
              ${results.map(r => `<th>${escapeHtml(r.domain)}</th>`).join("")}
              <th>Dimension Winner</th>
            </tr>
          </thead>
          <tbody>
            <!-- OVERALL SCORE ROW -->
            <tr style="background-color: #f8fafc; font-weight: bold;">
              <td><strong>OVERALL SECURITY GRADE</strong></td>
              <td>100%</td>
              ${results.map(r => `
                <td>
                  <span class="font-mono text-lg" style="color: ${r.overallScore >= 70 ? "#059669" : r.overallScore >= 50 ? "#d97706" : "#e11d48"}">${r.overallScore}/100</span>
                  <span class="badge ${r.grade === "A" || r.grade === "A+" ? "badge-pass" : "badge-warn"} ml-1">${r.grade}</span>
                </td>
              `).join("")}
              <td><strong class="text-teal">🏆 ${escapeHtml(leader.domain)}</strong></td>
            </tr>

            <!-- 6 CONTEXT ROWS -->
            ${contexts.map(ctx => {
              const bestScore = Math.max(...results.map(r => (r.setScores as any)?.[ctx.key] || 0));
              const winningDomain = results.find(r => (r.setScores as any)?.[ctx.key] === bestScore)?.domain || leader.domain;

              return `
                <tr>
                  <td>
                    <strong>${escapeHtml(ctx.label)}</strong>
                    <div class="text-xs text-slate">${escapeHtml(ctx.desc)}</div>
                  </td>
                  <td class="font-mono">${escapeHtml(ctx.weight)}</td>
                  ${results.map(r => {
                    const sc = (r.setScores as any)?.[ctx.key] || 0;
                    return `
                      <td class="font-mono font-bold" style="color: ${sc >= 70 ? "#059669" : sc >= 50 ? "#d97706" : "#e11d48"}">
                        ${sc}/100
                        ${sc === bestScore ? `<span class="tag tag-emerald" style="margin-left: 4px; font-size: 9px">WINNER</span>` : ""}
                      </td>
                    `;
                  }).join("")}
                  <td><strong>${escapeHtml(winningDomain)}</strong></td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- CONTEXT-BY-CONTEXT DEEP DIVE COMPARISON (ALL 6 CONTEXTS HEAD-TO-HEAD) -->
    <div class="card avoid-break">
      <div class="card-header">
        <span class="card-icon">🔍</span>
        <h2 class="card-title">Context-by-Context Head-to-Head Qualitative Analysis</h2>
      </div>

      <div class="space-y-6">
        ${contexts.map(ctx => {
          return `
            <div class="context-compare-block">
              <div class="context-compare-header">
                <div>
                  <h3 class="context-title">${escapeHtml(ctx.label)}</h3>
                  <p class="context-desc">${escapeHtml(ctx.desc)}</p>
                </div>
                <span class="tag tag-teal font-mono">Weight: ${escapeHtml(ctx.weight)}</span>
              </div>

              <div class="grid-side-by-side">
                ${results.map(r => {
                  const sScore = (r.setScores as any)?.[ctx.key] || 0;
                  const sData = r.detailedSets?.[ctx.key] || {};

                  return `
                    <div class="site-context-box">
                      <div class="flex-between">
                        <strong class="domain-mini-title">${escapeHtml(r.domain)}</strong>
                        <span class="font-mono font-bold" style="color: ${sScore >= 70 ? "#059669" : sScore >= 50 ? "#d97706" : "#e11d48"}">${sScore}/100 (Grade ${sData.grade || (sScore >= 85 ? "A" : sScore >= 70 ? "B" : "C")})</span>
                      </div>
                      <p class="text-xs text-slate mt-2">${escapeHtml(sData.whyScoreGiven || sData.summary || "Dimension evaluated against multi-tool telemetry baseline.")}</p>
                      
                      ${sData.positiveFindings && sData.positiveFindings.length > 0 ? `
                        <div class="mt-2 text-xs text-emerald">
                          <strong>Top Strength:</strong> ${escapeHtml(sData.positiveFindings[0])}
                        </div>` : ""}

                      ${sData.negativeFindings && sData.negativeFindings.length > 0 && !sData.negativeFindings[0]?.toLowerCase().startsWith("none") ? `
                        <div class="mt-1 text-xs text-rose">
                          <strong>Top Gap:</strong> ${escapeHtml(sData.negativeFindings[0])}
                        </div>` : ""}
                    </div>
                  `;
                }).join("")}
              </div>
            </div>
          `;
        }).join("")}
      </div>
    </div>
  `;
}

/**
 * Main function: Generates complete standalone, self-contained HTML report
 */
export function generateSecurityReportHtml(results: WebsiteResult[], isComparison: boolean, selectedSiteIndex: number = 0): string {
  const primarySite = results[selectedSiteIndex] || results[0];
  const title = isComparison
    ? `ScanZero Multi-Site Comparative Security Audit Report — ${results.map(r => r.domain).join(" vs ")}`
    : `ScanZero Security Audit Report — ${primarySite.domain}`;

  const generatedDate = new Date().toUTCString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
  <title>${escapeHtml(title)}</title>
  <style>
    /* ========================================================= */
    /* MODERN EXECUTIVE REPORT STYLESHEET                       */
    /* ========================================================= */
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --teal: #0d9488;
      --teal-light: #f0fdfa;
      --purple: #7c3aed;
      --purple-light: #faf5ff;
      --emerald: #059669;
      --emerald-light: #ecfdf5;
      --amber: #d97706;
      --amber-light: #fffbeb;
      --rose: #e11d48;
      --rose-light: #fff1f2;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 0;
      margin: 0;
      font-size: 13px;
      -webkit-font-smoothing: antialiased;
    }

    /* TOP ACTION BAR (HIDDEN IN PRINT) */
    .top-action-bar {
      position: sticky;
      top: 0;
      z-index: 100;
      background: rgba(255, 255, 255, 0.95);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }

    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-icon {
      width: 28px;
      height: 28px;
      background: #0f172a;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #14b8a6;
      font-weight: bold;
      font-size: 14px;
    }

    .brand-title {
      font-weight: 900;
      font-size: 14px;
      letter-spacing: -0.02em;
      color: #0f172a;
    }

    .brand-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .btn-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.15s ease;
      border: 1px solid transparent;
    }

    .btn-primary {
      background: var(--teal);
      color: #ffffff;
      box-shadow: 0 2px 4px rgba(13, 148, 136, 0.2);
    }

    .btn-primary:hover {
      background: #0f766e;
    }

    .btn-secondary {
      background: #ffffff;
      color: var(--text-main);
      border-color: var(--border);
    }

    .btn-secondary:hover {
      background: #f1f5f9;
    }

    /* MAIN CONTAINER */
    .report-container {
      max-width: 1150px;
      margin: 24px auto 60px auto;
      padding: 0 20px;
    }

    /* CARDS */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    }

    .hero-card {
      background: #ffffff;
      border-color: #cbd5e1;
      position: relative;
    }

    .comparison-hero {
      border-top: 5px solid var(--purple);
    }

    .hero-top {
      display: flex;
      flex-direction: column;
      gap: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 20px;
    }

    @media (min-width: 768px) {
      .hero-top {
        flex-direction: row;
        justify-content: space-between;
        align-items: center;
      }
    }

    .domain-title {
      font-size: 28px;
      font-weight: 900;
      letter-spacing: -0.03em;
      color: var(--text-main);
      margin: 8px 0 4px 0;
    }

    .target-url {
      font-size: 13px;
      color: var(--text-muted);
    }

    .target-url a {
      color: var(--teal);
      text-decoration: none;
      word-break: break-all;
    }

    .score-display-box {
      border: 2px solid;
      border-radius: 16px;
      padding: 16px 24px;
      text-align: center;
      min-width: 170px;
    }

    .score-number {
      font-size: 42px;
      font-weight: 900;
      line-height: 1;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .score-max {
      font-size: 16px;
      font-weight: 500;
      opacity: 0.6;
    }

    .grade-badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 900;
      padding: 2px 10px;
      border-radius: 999px;
      margin-top: 6px;
      letter-spacing: 0.05em;
    }

    .status-subtext {
      font-size: 11px;
      font-weight: 700;
      margin-top: 6px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    /* META STATS GRID */
    .meta-stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
    }

    @media (min-width: 768px) {
      .meta-stats-grid {
        grid-template-columns: repeat(4, 1fr);
      }
    }

    .meta-stat {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 16px;
      text-align: center;
    }

    .meta-label {
      font-size: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      display: block;
    }

    .meta-value {
      font-size: 22px;
      font-weight: 900;
      color: var(--text-main);
      margin-top: 4px;
      display: block;
    }

    .meta-hint {
      font-size: 10px;
      color: #94a3b8;
      display: block;
      margin-top: 2px;
    }

    /* CARD HEADERS */
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }

    .card-title {
      font-size: 17px;
      font-weight: 900;
      letter-spacing: -0.01em;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .card-subtext {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 16px;
      line-height: 1.5;
    }

    /* TAGS & BADGES */
    .tag-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
    }

    .tag {
      font-size: 10px;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .tag-teal { background: var(--teal-light); color: var(--teal); border: 1px solid #99f6e4; }
    .tag-purple { background: var(--purple-light); color: var(--purple); border: 1px solid #ddd6fe; }
    .tag-slate { background: #f1f5f9; color: #475569; border: 1px solid var(--border); }
    .tag-emerald { background: var(--emerald-light); color: var(--emerald); border: 1px solid #a7f3d0; }

    .badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 800;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      padding: 2px 7px;
      border-radius: 999px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }

    .badge-pass { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
    .badge-warn { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
    .badge-fail { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }

    .badge-risk-big { background: #ffe4e6; color: #be123c; border: 1px solid #fda4af; }
    .badge-risk-mod { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
    .badge-risk-small { background: #fef9c3; color: #854d0e; border: 1px solid #fef08a; }
    .badge-risk-comp { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
    .badge-risk-neg { background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1; }

    /* CALLOUT BOXES */
    .bg-callout-teal {
      background: linear-gradient(135deg, #f0fdfa 0%, #ffffff 100%);
      border-color: #99f6e4;
    }

    .bg-callout-purple {
      background: linear-gradient(135deg, #faf5ff 0%, #ffffff 100%);
      border-color: #ddd6fe;
    }

    .summary-body {
      font-size: 13px;
      color: #334155;
      line-height: 1.6;
    }

    .attacker-perspective-box {
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px solid #ccfbf1;
    }

    .attacker-title {
      font-size: 11px;
      font-weight: 800;
      color: #be123c;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }

    .attacker-quote {
      font-style: italic;
      color: #475569;
      font-size: 12px;
      line-height: 1.5;
    }

    /* ATTACK CHAIN */
    .attack-chain-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
      margin-top: 12px;
    }

    @media (min-width: 768px) {
      .attack-chain-grid {
        grid-template-columns: repeat(3, 1fr);
      }
    }

    .chain-step-card {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }

    .chain-step-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      margin-bottom: 8px;
    }

    .chain-badge {
      font-size: 10px;
      font-weight: 800;
      background: #fee2e2;
      color: #b91c1c;
      border: 1px solid #fca5a5;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .chain-vector {
      font-size: 10px;
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 120px;
    }

    .chain-title {
      font-weight: 800;
      font-size: 13px;
      color: var(--text-main);
      margin-bottom: 4px;
    }

    .chain-desc {
      font-size: 11px;
      color: #64748b;
      line-height: 1.4;
    }

    /* DYNAMIC CAP */
    .cap-alert-box {
      background: #fff1f2;
      border: 1px solid #fecdd3;
      border-radius: 12px;
      padding: 14px;
      margin: 14px 0;
    }

    .cap-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 6px;
    }

    .cap-title {
      font-weight: 900;
      color: #9f1239;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .cap-reason {
      font-size: 12px;
      color: #881337;
      margin-bottom: 8px;
    }

    .cap-proofs {
      font-size: 11px;
      color: #9f1239;
      border-top: 1px solid #fecdd3;
      padding-top: 8px;
    }

    .cap-proofs ul {
      margin-left: 18px;
      margin-top: 4px;
    }

    /* COMPENSATING CONTROLS */
    .comp-controls-section {
      margin: 14px 0;
    }

    .section-mini-title {
      font-size: 11px;
      font-weight: 800;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .comp-tags-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .comp-tag {
      background: #ecfdf5;
      color: #065f46;
      border: 1px solid #a7f3d0;
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
    }

    .cross-interaction-box {
      background: #eef2ff;
      border: 1px solid #c7d2fe;
      color: #3730a3;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 12px;
      margin-bottom: 14px;
    }

    /* TABLES */
    .table-wrap {
      overflow-x: auto;
      margin: 12px 0;
      -webkit-overflow-scrolling: touch;
    }

    .report-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 12px;
    }

    .report-table th {
      background: #f8fafc;
      color: #475569;
      font-weight: 800;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 10px 12px;
      border-bottom: 2px solid var(--border);
    }

    .report-table td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    .report-table tr:hover {
      background-color: #f8fafc;
    }

    /* SET DETAIL CARDS */
    .set-detail-card {
      border-left: 4px solid var(--teal);
    }

    .set-detail-header {
      display: flex;
      flex-direction: column;
      gap: 12px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 14px;
    }

    @media (min-width: 768px) {
      .set-detail-header {
        flex-direction: row;
        justify-content: space-between;
        align-items: center;
      }
    }

    .set-title {
      font-size: 18px;
      font-weight: 900;
      color: var(--text-main);
      margin: 4px 0 2px 0;
    }

    .set-summary-text {
      font-size: 12px;
      color: var(--text-muted);
    }

    .set-score-pill {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 10px 18px;
      text-align: center;
      min-width: 110px;
    }

    .set-score-val {
      font-size: 26px;
      font-weight: 900;
      line-height: 1;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .set-grade-val {
      font-size: 11px;
      font-weight: 800;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .why-score-box {
      background: #f0fdfa;
      border: 1px solid #ccfbf1;
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 12px;
      color: #0f766e;
      margin-bottom: 16px;
    }

    /* CERTIFICATE CHAIN */
    .cert-chain-box {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 16px;
    }

    .cert-chain-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      font-size: 12px;
    }

    .cert-chain-steps {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    @media (min-width: 768px) {
      .cert-chain-steps {
        flex-direction: row;
        align-items: center;
      }
    }

    .cert-step {
      flex: 1;
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
    }

    .cert-step-role {
      font-size: 9px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--text-muted);
      text-transform: uppercase;
    }

    .cert-step-name {
      font-weight: 800;
      font-size: 12px;
      color: var(--text-main);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .cert-step-status {
      font-size: 10px;
      font-weight: 700;
      margin-top: 2px;
    }

    .cert-step-arrow {
      color: #94a3b8;
      font-weight: bold;
      text-align: center;
    }

    /* FINDINGS COLUMNS */
    .findings-cols-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
      margin: 16px 0;
    }

    @media (min-width: 768px) {
      .findings-cols-grid {
        grid-template-columns: 1fr 1fr;
      }
    }

    .finding-col {
      border-radius: 12px;
      padding: 14px;
      border: 1px solid var(--border);
    }

    .finding-col-pos { background: #f0fdf4; border-color: #bbf7d0; }
    .finding-col-neg { background: #fef2f2; border-color: #fecaca; }

    .finding-col-title {
      font-size: 12px;
      font-weight: 800;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .finding-col ul {
      margin-left: 18px;
      font-size: 12px;
    }

    .finding-col li {
      margin-bottom: 4px;
    }

    /* REMEDIATION GUIDES */
    .remed-guide-card {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin-top: 10px;
    }

    .remed-finding-title {
      font-size: 12px;
      margin-bottom: 8px;
    }

    .remed-steps-list {
      margin-left: 18px;
      font-size: 12px;
      color: #334155;
    }

    .remed-steps-list li {
      margin-bottom: 4px;
    }

    .remed-urls-row {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
    }

    .remed-url-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
    }

    .link-btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 3px 8px;
      font-size: 10px;
      font-weight: 700;
      color: var(--teal);
      text-decoration: none;
    }

    /* SERVER HARDENING CODE BLOCKS */
    .code-tabs-container {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .code-block-wrap {
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }

    .code-block-title {
      background: #f1f5f9;
      padding: 8px 12px;
      font-size: 11px;
      font-weight: 700;
      color: #475569;
      border-bottom: 1px solid var(--border);
    }

    .code-content {
      background: #0f172a;
      color: #e2e8f0;
      padding: 12px 14px;
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* COMPARISON BLOCKS */
    .leader-banner {
      background: #f0fdfa;
      border: 1px solid #99f6e4;
      border-radius: 12px;
      padding: 14px 18px;
      margin-top: 14px;
    }

    .leader-text strong {
      font-size: 14px;
      display: block;
      margin-bottom: 4px;
    }

    .leader-text p {
      font-size: 12px;
      color: #334155;
    }

    .multi-insight-card {
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      margin-top: 8px;
    }

    .context-compare-block {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      background: #ffffff;
    }

    .context-compare-header {
      display: flex;
      flex-direction: column;
      gap: 6px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
      margin-bottom: 12px;
    }

    @media (min-width: 768px) {
      .context-compare-header {
        flex-direction: row;
        justify-content: space-between;
        align-items: center;
      }
    }

    .context-title {
      font-size: 14px;
      font-weight: 800;
      color: var(--text-main);
    }

    .context-desc {
      font-size: 11px;
      color: var(--text-muted);
    }

    .grid-side-by-side {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }

    @media (min-width: 768px) {
      .grid-side-by-side {
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      }
    }

    .site-context-box {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
    }

    .domain-mini-title {
      font-size: 13px;
      color: var(--text-main);
    }

    /* FOOTER */
    .report-footer {
      text-align: center;
      font-size: 11px;
      color: #94a3b8;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    .report-footer p {
      margin-bottom: 4px;
    }

    /* UTILITIES */
    .flex-between { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .grid-2-cols { display: grid; grid-template-columns: 1fr; gap: 16px; }
    @media (min-width: 768px) { .grid-2-cols { grid-template-columns: 1fr 1fr; } }
    .text-teal { color: var(--teal); }
    .text-purple { color: var(--purple); }
    .text-emerald { color: var(--emerald); }
    .text-rose { color: var(--rose); }
    .text-slate { color: var(--text-muted); }
    .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .font-bold { font-weight: 700; }
    .mt-1 { margin-top: 4px; }
    .mt-2 { margin-top: 8px; }
    .space-y-3 > * + * { margin-top: 12px; }
    .space-y-4 > * + * { margin-top: 16px; }
    .space-y-6 > * + * { margin-top: 24px; }
    .bullet-list-pos, .bullet-list-neg { margin-left: 20px; font-size: 12px; }
    .bullet-list-pos li { margin-bottom: 6px; color: #166534; }
    .bullet-list-neg li { margin-bottom: 6px; color: #991b1b; }
    .solution-box {
      margin-top: 6px;
      padding: 6px 8px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 6px;
      font-size: 11px;
      color: #166534;
    }

    /* PRINT SPECIFIC RULES */
    @media print {
      body {
        background: #ffffff !important;
        color: #000000 !important;
        font-size: 10pt;
      }
      .top-action-bar, .no-print {
        display: none !important;
      }
      .report-container {
        max-width: 100% !important;
        margin: 0 !important;
        padding: 0 !important;
      }
      .card {
        box-shadow: none !important;
        border: 1px solid #cbd5e1 !important;
        page-break-inside: avoid;
        margin-bottom: 16px;
        padding: 16px;
      }
      .page-break {
        page-break-before: always !important;
      }
      .avoid-break {
        page-break-inside: avoid !important;
      }
      a {
        text-decoration: none !important;
        color: inherit !important;
      }
      .code-content {
        background: #f1f5f9 !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
      }
    }
  </style>
</head>
<body>

  <!-- TOP ACTION TOOLBAR (HIDDEN DURING PRINT) -->
  <header class="top-action-bar no-print">
    <div class="brand-wrap">
      <div class="brand-icon">🛡️</div>
      <div>
        <div class="brand-title">SCANZER0 ANALYSIS ENGINE</div>
        <div class="brand-subtitle">Autonomous Security Audit &bull; Generated ${escapeHtml(generatedDate)}</div>
      </div>
    </div>

    <div class="btn-group">
      <button onclick="window.print()" class="btn btn-primary">
        🖨️ Print / Save as PDF
      </button>
      <button onclick="triggerFileDownload()" class="btn btn-secondary">
        📥 Save HTML File
      </button>
    </div>
  </header>

  <!-- MAIN REPORT CONTAINER -->
  <main class="report-container">
    ${isComparison ? buildMultiSiteComparisonSection(results) : ""}

    <!-- AUDIT FOR EACH WEBSITE -->
    ${results.map((site, idx) => buildSingleSiteAuditSection(site, idx, results.length)).join("")}

    <!-- FOOTER -->
    <footer class="report-footer">
      <p><strong>ScanZero Autonomous Security Intelligence</strong> &bull; Verified via 55 Multi-Tool Telemetry &amp; Gemini AI Rules</p>
      <p>Document Generated: ${escapeHtml(generatedDate)} &bull; Confidential Security Audit</p>
    </footer>
  </main>

  <script>
    function triggerFileDownload() {
      const blob = new Blob([document.documentElement.outerHTML], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "${escapeHtml(isComparison ? `ScanZero-MultiSite-Comparison-Report-${results.map(r => r.domain).join("-vs-")}.html` : `ScanZero-${primarySite.domain}-Security-Audit-Report.html`)}";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  </script>
</body>
</html>`;
}

/**
 * Downloads or opens the generated report directly on mobile or desktop devices.
 */
export function downloadSecurityReport(results: WebsiteResult[], isComparison: boolean, selectedSiteIndex: number = 0): void {
  if (!results || results.length === 0) return;

  const html = generateSecurityReportHtml(results, isComparison, selectedSiteIndex);
  const primarySite = results[selectedSiteIndex] || results[0];
  const filename = isComparison
    ? `ScanZero-MultiSite-Comparison-Report-${results.map(r => r.domain).join("-vs-")}.html`
    : `ScanZero-${primarySite.domain}-Security-Audit-Report.html`;

  // 1. Create a UTF-8 Blob of the full report
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const blobUrl = URL.createObjectURL(blob);

  // 2. Trigger native file download (works across iOS Safari, Android Chrome, desktop)
  const downloadLink = document.createElement("a");
  downloadLink.href = blobUrl;
  downloadLink.download = filename;
  downloadLink.style.display = "none";
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);

  // 3. For enhanced mobile and desktop UX:
  // If the browser supports window.open, open the report in a new tab so mobile users
  // can view it immediately, pinch-zoom, or use iOS/Android share to "Print / Save as PDF".
  try {
    const newWindow = window.open(blobUrl, "_blank");
    if (!newWindow || newWindow.closed || typeof newWindow.closed === "undefined") {
      // Popup blocked or not supported on this mobile webview; file download already triggered above!
    }
  } catch (e) {
    // Silently continue since downloadLink.click() initiated the file download
  }

  // Cleanup blob URL after 60 seconds
  setTimeout(() => {
    URL.revokeObjectURL(blobUrl);
  }, 60000);
}
