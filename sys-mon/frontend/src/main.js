// sys-mon panel — frontend entry point
// Uses vanilla JS + DOM manipulation (no framework needed for this simple UI)

import { invoke } from '@wailsapp/runtime';

let state = {
  anomalies: [],
  activePorts: [],
  running: false,
  interval: 30,
  lastCheck: '',
  selectedBaseline: 'default',
  threatCounts: { critical: 0, high: 0, medium: 0, low: 0, gone: 0, info: 0 },
};

let timerId = null;

// DOM refs
const appEl = document.getElementById('app');

function render() {
  const totalAnomalies = state.threatCounts.critical + state.threatCounts.high + state.threatCounts.medium;

  appEl.innerHTML = `
    <div class="app">
      <!-- Title bar -->
      <div class="titlebar">
        <span class="titlebar-title">SYS-MON</span>
        <div style="display:flex;align-items:center;gap:8px;">
          <select id="baseline-select" class="btn" style="font-size:10px;">
            <option value="default" ${state.selectedBaseline === 'default' ? 'selected' : ''}>default</option>
          </select>
          ${totalAnomalies > 0
            ? `<span class="titlebar-badge">● ${totalAnomalies}</span>`
            : ''}
        </div>
      </div>

      <!-- Threat summary -->
      <div class="threat-bar">
        <span class="threat-item">🔴 Critical: ${state.threatCounts.critical}</span>
        <span class="threat-item">🟠 High: ${state.threatCounts.high}</span>
        <span class="threat-item">🟡 Medium: ${state.threatCounts.medium}</span>
        <span class="threat-item">🟢 Low: ${state.threatCounts.low}</span>
        <span class="threat-item">⚪ Gone: ${state.threatCounts.gone}</span>
        <span class="threat-item">🔵 Info: ${state.threatCounts.info}</span>
      </div>

      <!-- Main -->
      <div class="main">
        <!-- Anomalies panel -->
        <div class="panel">
          <div class="panel-header">Anomalies (${state.anomalies.length})</div>
          <div class="panel-body">
            ${state.anomalies.length === 0
              ? '<div class="empty">✓ No anomalies detected</div>'
              : state.anomalies.map(a => renderAnomalyRow(a)).join('')}
          </div>
        </div>

        <!-- Active ports panel -->
        <div class="panel">
          <div class="panel-header">Active Ports (${state.activePorts.length})</div>
          <div class="panel-body">
            ${state.activePorts.length === 0
              ? '<div class="empty">No ports found</div>'
              : state.activePorts.map(p => renderPortRow(p)).join('')}
          </div>
        </div>
      </div>

      <!-- Status bar -->
      <div class="statusbar">
        <div class="status-left">
          <span><span class="status-dot ${state.running ? 'running' : 'paused'}"></span> ${state.running ? 'Running' : 'Paused'}</span>
          <span>Last: ${state.lastCheck || 'never'}</span>
        </div>
        <div class="status-right">
          <span>Every: <input class="interval-input" type="number" id="interval-input" value="${state.interval}" min="5" max="300" step="5" />s</span>
          <button class="btn ${state.running ? 'btn-danger' : 'btn-primary'}" id="toggle-btn">
            ${state.running ? 'Stop' : 'Start'}
          </button>
          <button class="btn" id="refresh-btn">Refresh</button>
        </div>
      </div>
    </div>
  `;

  // Bind events
  document.getElementById('baseline-select').addEventListener('change', (e) => {
    state.selectedBaseline = e.target.value;
  });

  document.getElementById('interval-input').addEventListener('change', (e) => {
    state.interval = parseInt(e.target.value) || 30;
    restartTimer();
  });

  document.getElementById('toggle-btn').addEventListener('click', toggleScan);
  document.getElementById('refresh-btn').addEventListener('click', () => {
    scanPorts();
  });
}

function renderAnomalyRow(a) {
  const p = a.port;
  const wslTag = p.wsl2 ? ' <span class="wsl-tag">WSL2</span>' : '';
  const sig = p.signed
    ? ' <span class="signed">✓ signed</span>'
    : ' <span class="unsigned">✕ unsigned</span>';

  return `
    <div class="port-row">
      <span class="threat-dot ${a.threat}"></span>
      <span class="port-addr">${formatAddr(p)}${wslTag}</span>
      <span class="port-process">${p.process || 'unknown'}${sig}</span>
      <span class="port-pid">PID ${p.pid}</span>
      <span class="port-tag">${a.threat}</span>
      <div class="port-actions">
        <button class="btn btn-success" onclick="whitelistPort(${JSON.stringify(p).replace(/"/g, '&quot;')})">✓</button>
        <button class="btn btn-danger" onclick="blockPort(${JSON.stringify(p).replace(/"/g, '&quot;')})">✕</button>
      </div>
    </div>
  `;
}

function renderPortRow(p) {
  const wslTag = p.wsl2 ? ' <span class="wsl-tag">WSL2</span>' : '';
  const sig = p.signed
    ? ' <span class="signed">✓ signed</span>'
    : ' <span class="unsigned">✕ unsigned</span>';

  return `
    <div class="port-row">
      <span class="threat-dot low"></span>
      <span class="port-addr">${formatAddr(p)}${wslTag}</span>
      <span class="port-process">${p.process || 'unknown'}${sig}</span>
      <span class="port-pid">PID ${p.pid}</span>
      <span class="port-tag">${p.family}</span>
      <div class="port-actions">
        <button class="btn" onclick="showPortInfo(${JSON.stringify(p).replace(/"/g, '&quot;')})">i</button>
      </div>
    </div>
  `;
}

function formatAddr(p) {
  const addr = p.address;
  if (p.family === 'ipv6' && addr !== '::' && addr !== '::1') {
    return `[${addr}]:${p.port}`;
  }
  return `${addr}:${p.port}`;
}

// Expose to global scope for inline onclick handlers
window.whitelistPort = async (p) => {
  await invoke('whitelist_port', { port: JSON.stringify(p) });
  await scanPorts();
};

window.blockPort = async (p) => {
  await invoke('block_port', { port: JSON.stringify(p) });
  await scanPorts();
};

window.showPortInfo = async (p) => {
  const info = [
    `Address: ${p.address}:${p.port}/${p.protocol}`,
    `Family: ${p.family}`,
    `PID: ${p.pid}`,
    `Process: ${p.process || 'unknown'}`,
    `Path: ${p.path || 'N/A'}`,
    `Signed: ${p.signed ? 'Yes' : 'No'}`,
    `WSL2: ${p.wsl2 ? 'Yes' : 'No'}`,
    `Parent PID: ${p.parent_pid || 'N/A'}`,
    `Command: ${p.command_line || 'N/A'}`,
  ].join('\n');
  alert(info);
};

async function scanPorts() {
  try {
    const result = await invoke('scan_and_compare', { baseline: state.selectedBaseline });
    const data = JSON.parse(result);
    state.anomalies = data.anomalies || [];
    state.activePorts = data.ports || [];
    state.lastCheck = new Date().toLocaleTimeString();
    state.threatCounts = {
      critical: state.anomalies.filter(a => a.threat === 'critical').length,
      high: state.anomalies.filter(a => a.threat === 'high').length,
      medium: state.anomalies.filter(a => a.threat === 'medium').length,
      low: state.anomalies.filter(a => a.threat === 'low').length,
      gone: state.anomalies.filter(a => a.threat === 'gone').length,
      info: state.anomalies.filter(a => a.threat === 'info').length,
    };
    render();

    // Update tray icon color
    const total = state.threatCounts.critical + state.threatCounts.high + state.threatCounts.medium;
    invoke('update_tray_icon', { count: total });
  } catch (e) {
    console.error('Scan failed:', e);
  }
}

async function toggleScan() {
  state.running = !state.running;
  if (state.running) {
    await scanPorts();
    startTimer();
  } else {
    if (timerId) clearInterval(timerId);
    timerId = null;
  }
  render();
}

function startTimer() {
  if (timerId) clearInterval(timerId);
  timerId = setInterval(async () => {
    if (state.running) await scanPorts();
  }, state.interval * 1000);
}

// Initial render
render();
