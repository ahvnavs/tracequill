// 墨影録 (Bokuei) Frontend Application
// Pure Vanilla JS - Zero External Dependencies

(function() {
  'use strict';

  // Global state
  const state = {
    activeTab: 'map',
    graphData: { nodes: [], edges: [], regions: [] },
    nodePositions: {}, // id -> {x, y, vx, vy}
    simulationTimer: null,
    timeHistory: [],   // timestamps from server
    selectedNode: null,
    totalUnknowns: 0,
    totalClaims: 0,
    isHistorical: false,
    historicalCutoff: null,
  };

  // DOM Elements
  const dom = {
    tabs: document.querySelectorAll('.tab-btn'),
    panels: {
      map: document.getElementById('view-map'),
      explain: document.getElementById('view-explain'),
      diff: document.getElementById('view-diff'),
      impact: document.getElementById('view-impact'),
      ask: document.getElementById('view-ask'),
    },
    statUnknowns: document.getElementById('stat-unknowns-count'),
    statClaims: document.getElementById('stat-claims-count'),
    askBadge: document.getElementById('ask-counter-badge'),

    // Map view
    graphSvg: document.getElementById('graph-canvas'),
    graphNodes: document.getElementById('graph-nodes'),
    graphEdges: document.getElementById('graph-edges'),
    graphHatch: document.getElementById('graph-hatch-regions'),
    timeSlider: document.getElementById('time-slider'),
    timeDisplay: document.getElementById('time-display'),
    timeResetBtn: document.getElementById('time-reset-btn'),
    inspector: document.getElementById('node-inspector'),
    inspectorTitle: document.getElementById('inspector-title'),
    inspectorBody: document.getElementById('inspector-body'),
    inspectorClose: document.getElementById('inspector-close'),
    inspectorExplain: document.getElementById('inspector-explain-btn'),
    inspectorImpact: document.getElementById('inspector-impact-btn'),

    // Explain view
    explainInput: document.getElementById('explain-input'),
    explainSubmit: document.getElementById('explain-submit-btn'),
    explainResult: document.getElementById('explain-result'),

    // Diff view
    diffTargetA: document.getElementById('diff-target-a'),
    diffTargetB: document.getElementById('diff-target-b'),
    diffSubmit: document.getElementById('diff-submit-btn'),
    diffResult: document.getElementById('diff-result'),

    // Impact view
    impactInput: document.getElementById('impact-input'),
    impactSubmit: document.getElementById('impact-submit-btn'),
    impactResult: document.getElementById('impact-result'),

    // Ask view
    askTotal: document.getElementById('ask-total-unknowns'),
    askBlocked: document.getElementById('ask-blocked-unknowns'),
    askIdentity: document.getElementById('ask-identity-unknowns'),
    askQuestionList: document.getElementById('ask-question-list'),
  };

  // Initialize
  function init() {
    setupTabNavigation();
    setupMapControls();
    setupExplainView();
    setupDiffView();
    setupImpactView();
    setupAskView();

    // Initial data fetch
    fetchStats();
    loadMapData();
    loadQuestions();
  }

  // Navigation
  function setupTabNavigation() {
    dom.tabs.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        switchTab(targetTab);
      });
    });
  }

  function switchTab(tabName) {
    state.activeTab = tabName;
    dom.tabs.forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
    });
    Object.keys(dom.panels).forEach(key => {
      dom.panels[key].classList.toggle('active', key === tabName);
    });

    if (tabName === 'ask') {
      loadQuestions();
    }
  }

  // API Call helper
  async function apiGet(endpoint, params = {}) {
    const url = new URL(endpoint, window.location.origin);
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        url.searchParams.append(k, v);
      }
    });
    const resp = await fetch(url.toString());
    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(err || resp.statusText);
    }
    return await resp.json();
  }

  async function apiPost(endpoint, body = {}) {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(err || resp.statusText);
    }
    return await resp.json();
  }

  // Stats Loading
  async function fetchStats() {
    try {
      const cov = await apiGet('/api/coverage');
      if (cov) {
        state.totalClaims = cov.total_claims || 0;
        dom.statClaims.textContent = state.totalClaims;
      }
      const unks = await apiGet('/api/unknowns');
      if (unks) {
        state.totalUnknowns = Array.isArray(unks) ? unks.length : 0;
        dom.statUnknowns.textContent = state.totalUnknowns;
        dom.askBadge.textContent = state.totalUnknowns;
        if (dom.askTotal) dom.askTotal.textContent = state.totalUnknowns;
      }
    } catch (e) {
      console.warn('Failed loading initial telemetry statistics:', e);
    }
  }

  // --- MAP & GRAPH RENDERING ---
  function setupMapControls() {
    dom.timeSlider.addEventListener('input', (e) => {
      const val = parseInt(e.target.value, 10);
      if (val === 100) {
        state.isHistorical = false;
        state.historicalCutoff = null;
        dom.timeDisplay.textContent = 'Live / Latest';
        loadMapData();
      } else {
        state.isHistorical = true;
        if (state.timeHistory.length > 0) {
          const idx = Math.floor((val / 100) * (state.timeHistory.length - 1));
          state.historicalCutoff = state.timeHistory[idx];
          dom.timeDisplay.textContent = new Date(state.historicalCutoff).toLocaleString();
          loadMapData(state.historicalCutoff);
        }
      }
    });

    dom.timeResetBtn.addEventListener('click', () => {
      dom.timeSlider.value = 100;
      state.isHistorical = false;
      state.historicalCutoff = null;
      dom.timeDisplay.textContent = 'Live / Latest';
      loadMapData();
    });

    dom.inspectorClose.addEventListener('click', () => {
      dom.inspector.classList.add('hidden');
    });

    dom.inspectorExplain.addEventListener('click', () => {
      if (state.selectedNode) {
        switchTab('explain');
        dom.explainInput.value = state.selectedNode.id;
        runExplain(state.selectedNode.id);
      }
    });

    dom.inspectorImpact.addEventListener('click', () => {
      if (state.selectedNode) {
        switchTab('impact');
        dom.impactInput.value = state.selectedNode.id;
        runImpact(state.selectedNode.id);
      }
    });
  }

  async function loadMapData(at = null) {
    try {
      const params = at ? { at } : {};
      const data = await apiGet('/api/map', params);
      state.graphData = data;
      if (data.timestamps && data.timestamps.length > 0) {
        state.timeHistory = data.timestamps;
      }
      initForceSimulation(data.nodes, data.edges);
      renderMapGraph(data);
    } catch (e) {
      console.error('Failed to load map data:', e);
    }
  }

  // Native lightweight spring-electrical force layout (no D3 or foreign lib)
  function initForceSimulation(nodes, edges) {
    if (state.simulationTimer) {
      clearInterval(state.simulationTimer);
      state.simulationTimer = null;
    }

    const width = 1200;
    const height = 700;
    const centerX = width / 2;
    const centerY = height / 2;

    // Initialize or keep positions
    nodes.forEach((n, idx) => {
      if (!state.nodePositions[n.id]) {
        const angle = (idx / nodes.length) * 2 * Math.PI;
        const radius = 180 + (idx % 3) * 60;
        state.nodePositions[n.id] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          vx: 0,
          vy: 0,
        };
      }
    });

    let iter = 0;
    const maxIter = 85;

    state.simulationTimer = setInterval(() => {
      iter++;
      if (iter > maxIter) {
        clearInterval(state.simulationTimer);
        state.simulationTimer = null;
        return;
      }

      // 1. Repulsion between all node pairs
      for (let i = 0; i < nodes.length; i++) {
        const nA = state.nodePositions[nodes[i].id];
        for (let j = i + 1; j < nodes.length; j++) {
          const nB = state.nodePositions[nodes[j].id];
          const dx = nB.x - nA.x;
          const dy = nB.y - nA.y;
          const distSq = dx * dx + dy * dy + 0.01;
          const dist = Math.sqrt(distSq);
          if (dist < 400) {
            const force = 1800 / distSq;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            nA.vx -= fx;
            nA.vy -= fy;
            nB.vx += fx;
            nB.vy += fy;
          }
        }
      }

      // 2. Attraction along edges (springs)
      edges.forEach(e => {
        const nA = state.nodePositions[e.source];
        const nB = state.nodePositions[e.target];
        if (nA && nB) {
          const dx = nB.x - nA.x;
          const dy = nB.y - nA.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const targetDist = 90;
          const springForce = (dist - targetDist) * 0.05;
          const fx = (dx / dist) * springForce;
          const fy = (dy / dist) * springForce;
          nA.vx += fx;
          nA.vy += fy;
          nB.vx -= fx;
          nB.vy -= fy;
        }
      });

      // 3. Center gravity & position update with damping
      nodes.forEach(n => {
        const p = state.nodePositions[n.id];
        p.vx += (centerX - p.x) * 0.008;
        p.vy += (centerY - p.y) * 0.008;

        p.vx *= 0.65;
        p.vy *= 0.65;

        p.x += p.vx;
        p.y += p.vy;

        // Bounding clamp
        p.x = Math.max(50, Math.min(width - 50, p.x));
        p.y = Math.max(50, Math.min(height - 50, p.y));
      });

      updateSVGPositions();
    }, 20);
  }

  function renderMapGraph(data) {
    // 1. Hatched regions (Not-visible scope)
    dom.graphHatch.innerHTML = '';
    (data.regions || []).forEach(reg => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'graph-hatch');

      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', reg.x || 30);
      rect.setAttribute('y', reg.y || 450);
      rect.setAttribute('width', reg.width || 240);
      rect.setAttribute('height', reg.height || 180);
      rect.setAttribute('rx', '8');

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', (reg.x || 30) + 12);
      text.setAttribute('y', (reg.y || 450) + 24);
      text.textContent = reg.label || 'not visible (scope unobserved)';

      g.appendChild(rect);
      g.appendChild(text);
      dom.graphHatch.appendChild(g);
    });

    // 2. Edges
    dom.graphEdges.innerHTML = '';
    data.edges.forEach(e => {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('id', `edge-${e.source}-${e.target}`);
      line.setAttribute('marker-end', 'url(#arrow)');
      const strength = e.strength || 0.7;
      line.setAttribute('stroke-width', (strength * 2.5).toFixed(1));
      dom.graphEdges.appendChild(line);
    });

    // 3. Nodes
    dom.graphNodes.innerHTML = '';
    data.nodes.forEach(n => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', `graph-node ${n.is_stale ? 'stale' : ''}`);
      g.setAttribute('id', `node-${n.id}`);

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', n.radius || 15);
      
      let fillColor = '#38bdf8';
      if (n.kind === 'service') fillColor = '#a855f7';
      if (n.kind === 'run') fillColor = '#10b981';
      if (n.kind === 'artifact' || n.kind === 'package') fillColor = '#f59e0b';
      circle.setAttribute('fill', fillColor);

      let strokeColor = n.is_stale ? '#f59e0b' : 'rgba(255, 255, 255, 0.2)';
      circle.setAttribute('stroke', strokeColor);
      circle.setAttribute('stroke-width', '2');

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('dy', (n.radius || 15) + 14);
      text.textContent = n.label || n.id;

      g.appendChild(circle);
      g.appendChild(text);

      g.addEventListener('click', (ev) => {
        ev.stopPropagation();
        selectNode(n);
      });

      dom.graphNodes.appendChild(g);
    });

    updateSVGPositions();
  }

  function updateSVGPositions() {
    // Update lines
    state.graphData.edges.forEach(e => {
      const line = document.getElementById(`edge-${e.source}-${e.target}`);
      const pA = state.nodePositions[e.source];
      const pB = state.nodePositions[e.target];
      if (line && pA && pB) {
        line.setAttribute('x1', pA.x);
        line.setAttribute('y1', pA.y);
        line.setAttribute('x2', pB.x);
        line.setAttribute('y2', pB.y);
      }
    });

    // Update node groups
    state.graphData.nodes.forEach(n => {
      const g = document.getElementById(`node-${n.id}`);
      const p = state.nodePositions[n.id];
      if (g && p) {
        const circle = g.querySelector('circle');
        const text = g.querySelector('text');
        if (circle) {
          circle.setAttribute('cx', p.x);
          circle.setAttribute('cy', p.y);
        }
        if (text) {
          text.setAttribute('x', p.x);
          text.setAttribute('y', p.y);
        }
      }
    });
  }

  function selectNode(n) {
    state.selectedNode = n;
    dom.inspectorTitle.textContent = n.id;
    dom.inspector.classList.remove('hidden');

    let html = `
      <div class="inspector-prop">
        <span class="inspector-prop-label">Entity Kind:</span>
        <span class="inspector-prop-val">${escapeHtml(n.kind || 'reference')}</span>
      </div>
      <div class="inspector-prop">
        <span class="inspector-prop-label">Epistemic Status:</span>
        <span class="inspector-prop-val">${n.is_stale ? '<span class="tag-stale">stale (&lt;50% strength)</span>' : '<span class="tag-observed">observed</span>'}</span>
      </div>
      <div class="inspector-prop">
        <span class="inspector-prop-label">Effective Strength:</span>
        <span class="inspector-prop-val">${n.strength ? (n.strength * 100).toFixed(0) + '%' : '100%'}</span>
      </div>
      <div class="inspector-prop">
        <span class="inspector-prop-label">Visibility:</span>
        <span class="inspector-prop-val">${n.not_visible ? '<span class="tag-not-visible">not visible</span>' : 'observed'}</span>
      </div>
    `;

    if (n.attributes) {
      Object.entries(n.attributes).forEach(([k, v]) => {
        html += `
          <div class="inspector-prop">
            <span class="inspector-prop-label">${escapeHtml(k)}:</span>
            <span class="inspector-prop-val">${escapeHtml(v)}</span>
          </div>
        `;
      });
    }

    dom.inspectorBody.innerHTML = html;
  }

  // --- EXPLAIN VIEW ---
  function setupExplainView() {
    dom.explainSubmit.addEventListener('click', () => {
      const ref = dom.explainInput.value.trim();
      if (ref) runExplain(ref);
    });
    dom.explainInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const ref = dom.explainInput.value.trim();
        if (ref) runExplain(ref);
      }
    });
  }

  async function runExplain(ref) {
    dom.explainResult.classList.remove('empty');
    dom.explainResult.innerHTML = '<div class="empty-state">Loading entity lineage and claims...</div>';
    try {
      const data = await apiGet('/api/explain', { ref });
      renderExplainResult(data, ref);
    } catch (e) {
      dom.explainResult.innerHTML = `<div class="empty-state">Error: ${escapeHtml(e.message)} (status: not visible)</div>`;
    }
  }

  function renderExplainResult(data, ref) {
    let html = `
      <div class="card-section" style="margin-bottom: 1.5rem;">
        <div class="card-title">
          <span>Entity Resolution & Members</span>
          <span style="font-family: monospace; font-size: 0.8rem;">${escapeHtml(data.entity_id || 'unresolved')}</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
          Primary Ref: <strong style="color: var(--accent-cyan);">${escapeHtml(data.primary_ref || ref)}</strong>
        </div>
        <div style="font-size: 0.82rem; color: var(--text-muted);">
          Resolved Member Aliases: ${(data.members || [ref]).map(m => `<span class="tag-observed" style="margin-right: 4px;">${escapeHtml(m)}</span>`).join('')}
        </div>
      </div>

      <div class="grid-two-col">
        <div class="card-section">
          <div class="card-title">Effective State & Calibrated Strength</div>
          <table class="card-table">
            <thead>
              <tr>
                <th>Predicate</th>
                <th>Value</th>
                <th>Strength</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${(data.effective_states || []).map(st => `
                <tr>
                  <td><code>${escapeHtml(st.predicate)}</code></td>
                  <td>${escapeHtml(st.object_value)}</td>
                  <td>${(st.decayed_strength * 100).toFixed(0)}%</td>
                  <td>${st.is_contested ? '<span class="tag-not-visible">Contested</span>' : st.is_stale ? '<span class="tag-stale">Stale</span>' : '<span class="tag-observed">Active</span>'}</td>
                </tr>
              `).join('')}
              ${(!data.effective_states || data.effective_states.length === 0) ? '<tr><td colspan="4" style="color: var(--text-muted); text-align: center;">not visible</td></tr>' : ''}
            </tbody>
          </table>
        </div>

        <div class="card-section">
          <div class="card-title">Active Unknowns & Blind Spots</div>
          <table class="card-table">
            <thead>
              <tr>
                <th>Impact</th>
                <th>Predicate</th>
                <th>Reason (status: not visible)</th>
              </tr>
            </thead>
            <tbody>
              ${(data.unknowns || []).map(u => `
                <tr>
                  <td><span class="tag-not-visible">${escapeHtml(u.impact_level || 'Medium')}</span></td>
                  <td><code>${escapeHtml(u.predicate)}</code></td>
                  <td>${escapeHtml(u.reason)}</td>
                </tr>
              `).join('')}
              ${(!data.unknowns || data.unknowns.length === 0) ? '<tr><td colspan="3" style="color: var(--text-muted); text-align: center;">No active unknowns for this reference.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card-section">
        <div class="card-title">Supporting Evidence Lineage (${(data.claims || []).length} Immutable Claims)</div>
        <table class="card-table">
          <thead>
            <tr>
              <th>Claim ID</th>
              <th>Predicate</th>
              <th>Source / Method</th>
              <th>Observed At</th>
              <th>Evidence Hash</th>
            </tr>
          </thead>
          <tbody>
            ${(data.claims || []).map(c => `
              <tr>
                <td><code>${escapeHtml((c.claim_id || '').substring(0, 8))}</code></td>
                <td><code>${escapeHtml(c.predicate)}</code></td>
                <td>${escapeHtml((c.source && c.source.group) || '')} (${escapeHtml((c.source && c.source.method) || '')})</td>
                <td>${escapeHtml(c.observed_at || '')}</td>
                <td><code>${escapeHtml((c.evidence_hash || '').substring(0, 12))}</code></td>
              </tr>
            `).join('')}
            ${(!data.claims || data.claims.length === 0) ? '<tr><td colspan="5" style="color: var(--text-muted); text-align: center;">not visible</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    `;
    dom.explainResult.innerHTML = html;
  }

  // --- DIFF VIEW ---
  function setupDiffView() {
    dom.diffSubmit.addEventListener('click', () => {
      const a = dom.diffTargetA.value.trim();
      const b = dom.diffTargetB.value.trim();
      if (a && b) runDiff(a, b);
    });
  }

  async function runDiff(targetA, targetB) {
    dom.diffResult.classList.remove('empty');
    dom.diffResult.innerHTML = '<div class="empty-state">Computing causal differences and ranking root causes...</div>';
    try {
      const data = await apiGet('/api/diff', { a: targetA, b: targetB });
      renderDiffResult(data);
    } catch (e) {
      dom.diffResult.innerHTML = `<div class="empty-state">Diff failed: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderDiffResult(data) {
    let html = `
      <div class="card-section" style="margin-bottom: 1.5rem;">
        <div class="card-title">
          <span>Ranked Root Causes Backed by Evidence</span>
          <span style="font-size: 0.8rem; color: var(--text-muted);">${(data.ranked_causes || []).length} causes identified</span>
        </div>
        ${(data.ranked_causes || []).map(c => `
          <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.35rem;">
              <strong style="color: var(--accent-cyan);">#${c.rank} ${escapeHtml(c.explanation)}</strong>
              <span class="score-badge">Weight: ${c.weight}</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">
              Attribute: <code>${escapeHtml(c.predicate)}</code> | Baseline: <code>${escapeHtml(c.old_value || 'not visible')}</code> &rarr; Current: <code>${escapeHtml(c.new_value || 'not visible')}</code>
            </div>
          </div>
        `).join('')}
        ${(!data.ranked_causes || data.ranked_causes.length === 0) ? '<div style="color: var(--text-muted); font-size: 0.85rem;">No causal differences identified between targets.</div>' : ''}
      </div>

      <div class="card-section">
        <div class="card-title">Side-by-Side State Comparison (${(data.changes || []).length} Detected Changes)</div>
        <table class="card-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Subject</th>
              <th>Predicate</th>
              <th>Target A (Baseline)</th>
              <th>Target B (Comparison)</th>
            </tr>
          </thead>
          <tbody>
            ${(data.changes || []).map(ch => `
              <tr>
                <td><span class="${ch.status === 'not comparable' ? 'tag-not-visible' : ch.status === 'changed' ? 'tag-stale' : 'tag-observed'}">${escapeHtml(ch.status)}</span></td>
                <td><code>${escapeHtml(ch.subject)}</code></td>
                <td><code>${escapeHtml(ch.predicate)}</code></td>
                <td>${escapeHtml(ch.old_value || 'not visible')}</td>
                <td>${escapeHtml(ch.new_value || 'not visible')}</td>
              </tr>
            `).join('')}
            ${(!data.changes || data.changes.length === 0) ? '<tr><td colspan="5" style="color: var(--text-muted); text-align: center;">Zero state changes detected.</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    `;
    dom.diffResult.innerHTML = html;
  }

  // --- IMPACT VIEW ---
  function setupImpactView() {
    dom.impactSubmit.addEventListener('click', () => {
      const ref = dom.impactInput.value.trim();
      if (ref) runImpact(ref);
    });
    dom.impactInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const ref = dom.impactInput.value.trim();
        if (ref) runImpact(ref);
      }
    });
  }

  async function runImpact(ref) {
    dom.impactResult.classList.remove('empty');
    dom.impactResult.innerHTML = '<div class="empty-state">Tracing reverse dependencies and adjacent blind spots...</div>';
    try {
      const data = await apiGet('/api/impact', { ref });
      renderImpactResult(data);
    } catch (e) {
      dom.impactResult.innerHTML = `<div class="empty-state">Impact analysis failed: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderImpactResult(data) {
    let verdictClass = 'verdict-safe';
    if (data.verdict === 'Proceed with caution') verdictClass = 'verdict-caution';
    if (data.verdict === 'Do not proceed until questions answered') verdictClass = 'verdict-danger';

    let html = `
      <div class="verdict-banner ${verdictClass}">
        <div>
          <div class="verdict-title">${escapeHtml(data.verdict)}</div>
          <div style="font-size: 0.85rem; margin-top: 0.25rem;">${escapeHtml(data.summary_text)}</div>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <span class="score-badge">Known: ${data.known_count || 0}</span>
          <span class="score-badge">Likely: ${data.likely_count || 0}</span>
          <span class="score-badge">Possible: ${data.possible_count || 0}</span>
        </div>
      </div>

      <div class="grid-two-col">
        <div class="card-section">
          <div class="card-title">Reverse Dependents Traversal (${(data.dependents || []).length} Entities)</div>
          <table class="card-table">
            <thead>
              <tr>
                <th>Confidence</th>
                <th>Entity Ref</th>
                <th>Kind</th>
                <th>Via Predicate</th>
                <th>Depth</th>
              </tr>
            </thead>
            <tbody>
              ${(data.dependents || []).map(d => `
                <tr>
                  <td><span class="${d.confidence === 'known' ? 'tag-observed' : d.confidence === 'likely' ? 'tag-stale' : 'tag-not-visible'}">${escapeHtml(d.confidence)}</span></td>
                  <td><code>${escapeHtml(d.ref)}</code></td>
                  <td>${escapeHtml(d.kind)}</td>
                  <td><code>${escapeHtml(d.via_predicate)}</code></td>
                  <td>${d.depth}</td>
                </tr>
              `).join('')}
              ${(!data.dependents || data.dependents.length === 0) ? '<tr><td colspan="5" style="color: var(--text-muted); text-align: center;">No downstream dependents found.</td></tr>' : ''}
            </tbody>
          </table>
        </div>

        <div class="card-section">
          <div class="card-title">Adjacent Blind Spots (status: not visible)</div>
          <table class="card-table">
            <thead>
              <tr>
                <th>Scope Ref</th>
                <th>Kind</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              ${(data.blind_spots || []).map(b => `
                <tr>
                  <td><code>${escapeHtml(b.scope_ref)}</code></td>
                  <td><span class="tag-not-visible">${escapeHtml(b.kind)}</span></td>
                  <td>${escapeHtml(b.reason)}</td>
                </tr>
              `).join('')}
              ${(!data.blind_spots || data.blind_spots.length === 0) ? '<tr><td colspan="3" style="color: var(--text-muted); text-align: center;">Zero blind spots detected adjacent to target.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      </div>
    `;
    dom.impactResult.innerHTML = html;
  }

  // --- ASK & NEXT-BEST-QUESTIONS ---
  function setupAskView() {
    //
  }

  async function loadQuestions() {
    try {
      const questions = await apiGet('/api/ask', { n: 10 });
      renderQuestions(questions);
    } catch (e) {
      dom.askQuestionList.innerHTML = `<div class="empty-state">Error loading questions: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderQuestions(questions) {
    if (!questions || questions.length === 0) {
      dom.askQuestionList.innerHTML = '<div class="empty-state">No active epistemic questions (all observed items verified or zero unknowns).</div>';
      return;
    }

    let html = '';
    questions.forEach(q => {
      html += `
        <div class="question-card" id="q-card-${q.id}">
          <div class="question-header">
            <div class="question-meta">
              <span class="score-badge">Score: ${q.score.toFixed(2)}</span>
              <span style="font-size: 0.78rem; color: var(--text-muted);">Uncertainty: ${(q.uncertainty * 100).toFixed(0)}%</span>
              <span style="font-size: 0.78rem; color: var(--text-muted);">Downstream: ${q.downstream}</span>
              <span style="font-size: 0.78rem; color: var(--text-muted);">Blind: ${q.blind_adjacent}</span>
            </div>
            <code style="font-size: 0.75rem; color: var(--accent-cyan);">${escapeHtml(q.id)}</code>
          </div>
          <div class="question-prompt">${escapeHtml(q.prompt)}</div>
          <div class="question-actions">
            <button class="btn-ans" onclick="window.BokueiApp.submitAnswer('${q.id}', 'yes')">Yes</button>
            <button class="btn-ans" onclick="window.BokueiApp.submitAnswer('${q.id}', 'no')">No</button>
            <input type="text" id="ans-text-${q.id}" placeholder="Or enter custom name / text..." class="ans-input-text" />
            <button class="btn-ans" onclick="window.BokueiApp.submitTextAnswer('${q.id}')">Submit</button>
          </div>
        </div>
      `;
    });
    dom.askQuestionList.innerHTML = html;
  }

  async function submitAnswer(id, text) {
    try {
      const res = await apiPost('/api/answer', { id, answer: text });
      const card = document.getElementById(`q-card-${id}`);
      if (card) {
        card.innerHTML = `
          <div style="color: var(--accent-emerald); font-weight: 700; margin-bottom: 0.25rem;">
            &check; Verification Recorded (${res.claims_added} claim appended)
          </div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">
            Unknowns: ${res.unknowns_before} &rarr; ${res.unknowns_after} (${res.reduction_percent.toFixed(1)}% reduction) | Strength: ${res.new_strength.toFixed(2)}
          </div>
        `;
      }
      fetchStats();
      setTimeout(loadQuestions, 800);
    } catch (e) {
      alert('Failed submitting verification: ' + e.message);
    }
  }

  function submitTextAnswer(id) {
    const input = document.getElementById(`ans-text-${id}`);
    if (input && input.value.trim()) {
      submitAnswer(id, input.value.trim());
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Global interface for onclick actions
  window.BokueiApp = {
    submitAnswer,
    submitTextAnswer,
  };

  // Launch on DOM ready
  document.addEventListener('DOMContentLoaded', init);
})();
