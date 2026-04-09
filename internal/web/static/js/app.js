/* Coldcrypt SPA */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let currentSection = 'dashboard';
let restoreFileID = null;
let restoreVersionNum = null;
let jobRefreshTimer = null;

// ── Bootstrap modal handles ────────────────────────────────────────────────
let versionsModal, restoreModal, scheduleModal;

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  versionsModal  = new bootstrap.Modal(document.getElementById('versionsModal'));
  restoreModal   = new bootstrap.Modal(document.getElementById('restoreModal'));
  scheduleModal  = new bootstrap.Modal(document.getElementById('scheduleModal'));

  bindNav();
  bindGlobal();
  init();
});

async function init() {
  // Probe auth status by calling a protected endpoint
  try {
    const r = await fetch('/api/jobs?limit=1');
    if (r.status === 401) {
      showLogin();
    } else {
      showApp();
    }
  } catch {
    showLogin();
  }
}

// ── Auth ───────────────────────────────────────────────────────────────────
function showLogin() {
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('app').classList.add('d-none');
}

function showApp() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').classList.remove('d-none');
  navigateTo('dashboard');
}

async function login(password) {
  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  if (r.ok) {
    showApp();
    document.getElementById('login-error').classList.add('d-none');
  } else {
    const data = await r.json().catch(() => ({ error: 'Login failed' }));
    const el = document.getElementById('login-error');
    el.textContent = data.error || 'Invalid password';
    el.classList.remove('d-none');
  }
}

async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  showLogin();
  stopJobRefresh();
}

// ── Navigation ─────────────────────────────────────────────────────────────
function bindNav() {
  document.querySelectorAll('.nav-item-link').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.section));
  });
}

function navigateTo(section) {
  currentSection = section;
  document.querySelectorAll('.nav-item-link').forEach(el => {
    el.classList.toggle('active', el.dataset.section === section);
  });
  document.querySelectorAll('.section').forEach(el => {
    el.classList.toggle('active', el.id === `section-${section}`);
  });
  const names = {
    dashboard: 'Dashboard', files: 'Files', jobs: 'Backup Jobs',
    schedules: 'Schedules', settings: 'Settings'
  };
  document.getElementById('topbar-section-name').textContent = names[section] || section;

  stopJobRefresh();
  switch (section) {
    case 'dashboard': loadDashboard(); break;
    case 'files':     loadFiles(); break;
    case 'jobs':      loadJobs(); startJobRefresh(); break;
    case 'schedules': loadSchedules(); break;
    case 'settings':  loadSettings(); break;
  }
}

// ── Global bindings ────────────────────────────────────────────────────────
function bindGlobal() {
  // Login form
  document.getElementById('login-form').addEventListener('submit', e => {
    e.preventDefault();
    login(document.getElementById('login-password').value);
  });

  // Logout
  document.getElementById('logout-btn').addEventListener('click', logout);

  // Dashboard buttons
  document.getElementById('dash-run-now').addEventListener('click', () => runBackupNow());
  document.getElementById('dash-refresh').addEventListener('click', loadDashboard);

  // Jobs section run now
  document.getElementById('jobs-run-now').addEventListener('click', () => runBackupNow());

  // File search
  document.getElementById('file-search-btn').addEventListener('click', () => {
    loadFiles(document.getElementById('file-search').value);
  });
  document.getElementById('file-search').addEventListener('keydown', e => {
    if (e.key === 'Enter') loadFiles(document.getElementById('file-search').value);
  });

  // Schedule add
  document.getElementById('schedule-add-btn').addEventListener('click', openScheduleModal);
  document.getElementById('sched-save-btn').addEventListener('click', saveSchedule);

  // Restore confirm
  document.getElementById('restore-confirm-btn').addEventListener('click', doRestore);

  // Settings save / password change
  document.getElementById('cfg-save-btn').addEventListener('click', saveConfig);
  document.getElementById('cfg-pwd-btn').addEventListener('click', changePassword);
}

// ── Dashboard ──────────────────────────────────────────────────────────────
async function loadDashboard() {
  const [files, jobs, schedules] = await Promise.all([
    apiFetch('/api/files'),
    apiFetch('/api/jobs'),
    apiFetch('/api/schedules')
  ]);

  document.getElementById('dash-total-files').textContent = (files || []).length;

  const completedJobs = (jobs || []).filter(j => j.Status === 'completed');
  if (completedJobs.length > 0) {
    document.getElementById('dash-last-backup').textContent = fmtDate(completedJobs[0].StartedAt);
  } else {
    document.getElementById('dash-last-backup').textContent = 'Never';
  }

  const activeSchedules = (schedules || []).filter(s => s.Enabled).length;
  document.getElementById('dash-next-backup').textContent = activeSchedules;

  const tbody = document.getElementById('dash-jobs-tbody');
  tbody.innerHTML = '';
  (jobs || []).slice(0, 5).forEach(job => {
    tbody.insertAdjacentHTML('beforeend', jobRow(job));
  });
}

// ── Files ──────────────────────────────────────────────────────────────────
async function loadFiles(search = '') {
  const url = search ? `/api/files?search=${encodeURIComponent(search)}` : '/api/files';
  const files = await apiFetch(url) || [];
  const tbody = document.getElementById('files-tbody');
  tbody.innerHTML = '';
  if (files.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="text-muted text-center py-3">No files found</td></tr>';
    return;
  }
  files.forEach(f => {
    const tr = document.createElement('tr');
    tr.className = 'file-row';
    tr.innerHTML = `
      <td><i class="fa fa-file me-2 text-muted"></i>${esc(f.DisplayPath)}</td>
      <td class="text-muted small">${esc(f.SourcePath)}</td>
      <td>
        <button class="btn btn-sm btn-outline-info py-0 px-2" onclick="showVersions(${f.ID}, '${esc(f.DisplayPath)}')">
          <i class="fa fa-clock-rotate-left me-1"></i>Versions
        </button>
      </td>`;
    tbody.appendChild(tr);
  });
}

async function showVersions(fileID, displayPath) {
  document.getElementById('versionsModalLabel').textContent = `Versions — ${displayPath}`;
  const body = document.getElementById('versions-modal-body');
  body.innerHTML = '<div class="text-muted small">Loading…</div>';
  versionsModal.show();

  const versions = await apiFetch(`/api/files/${fileID}/versions`) || [];
  if (versions.length === 0) {
    body.innerHTML = '<div class="text-muted small">No versions found.</div>';
    return;
  }

  body.innerHTML = '';
  versions.forEach((v, i) => {
    const div = document.createElement('div');
    div.className = 'version-item d-flex align-items-center justify-content-between';
    div.innerHTML = `
      <div>
        <span class="badge bg-secondary me-2">v${v.VersionNum}</span>
        <span class="small">${fmtDate(v.EncryptedAt)}</span>
        <span class="text-muted small ms-3">${fmtSize(v.Size)}</span>
        <span class="text-muted small ms-3 font-monospace" title="${esc(v.Hash)}">${v.Hash.substring(0,12)}…</span>
      </div>
      <button class="btn btn-sm btn-outline-success py-0 px-2"
        onclick="promptRestore(${fileID}, ${v.VersionNum}, '${esc(displayPath)}')">
        <i class="fa fa-download me-1"></i>Restore
      </button>`;
    body.appendChild(div);
  });
}

function promptRestore(fileID, versionNum, displayPath) {
  restoreFileID = fileID;
  restoreVersionNum = versionNum;
  versionsModal.hide();
  document.getElementById('restore-out-path').value = '';
  document.getElementById('restore-msg').classList.add('d-none');
  restoreModal.show();
}

async function doRestore() {
  const outPath = document.getElementById('restore-out-path').value.trim();
  if (!outPath) {
    showMsg('restore-msg', 'Please enter an output path.', 'danger');
    return;
  }
  const r = await fetch(`/api/files/${restoreFileID}/restore`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version_num: restoreVersionNum, out_path: outPath })
  });
  if (r.ok) {
    showMsg('restore-msg', `Restore started. File will appear at: ${outPath}`, 'success');
    setTimeout(() => restoreModal.hide(), 2000);
  } else {
    const d = await r.json().catch(() => ({ error: 'Restore failed' }));
    showMsg('restore-msg', d.error || 'Restore failed', 'danger');
  }
}

// ── Jobs ───────────────────────────────────────────────────────────────────
async function loadJobs() {
  const jobs = await apiFetch('/api/jobs') || [];
  const tbody = document.getElementById('jobs-tbody');
  tbody.innerHTML = '';
  if (jobs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted text-center py-3">No jobs yet</td></tr>';
    return;
  }
  jobs.forEach(job => {
    tbody.insertAdjacentHTML('beforeend', jobRowFull(job));
  });
}

function jobRow(job) {
  return `<tr>
    <td class="text-muted small">#${job.ID}</td>
    <td>${statusBadge(job.Status)}</td>
    <td class="small">${fmtDate(job.StartedAt)}</td>
    <td class="small">${job.FilesProcessed}</td>
    <td class="small">${fmtSize(job.BytesTransferred)}</td>
  </tr>`;
}

function jobRowFull(job) {
  return `<tr>
    <td class="text-muted small">#${job.ID}</td>
    <td>${statusBadge(job.Status)}</td>
    <td class="small">${fmtDate(job.StartedAt)}</td>
    <td class="small">${job.CompletedAt ? fmtDate(job.CompletedAt) : '—'}</td>
    <td class="small">${job.FilesProcessed}</td>
    <td class="small">${fmtSize(job.BytesTransferred)}</td>
    <td class="small text-danger">${esc(job.ErrorMessage || '')}</td>
  </tr>`;
}

function statusBadge(status) {
  const cls = { running: 'badge-running', completed: 'badge-completed', failed: 'badge-failed' }[status] || 'bg-secondary';
  return `<span class="badge ${cls}">${status}</span>`;
}

function startJobRefresh() {
  jobRefreshTimer = setInterval(loadJobs, 5000);
}

function stopJobRefresh() {
  if (jobRefreshTimer) { clearInterval(jobRefreshTimer); jobRefreshTimer = null; }
}

async function runBackupNow() {
  const r = await fetch('/api/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_dirs: [] })
  });
  if (r.ok) {
    const d = await r.json();
    alert(`Backup job started (ID: ${d.job_id})`);
    if (currentSection === 'jobs') loadJobs();
    else if (currentSection === 'dashboard') loadDashboard();
  } else {
    const d = await r.json().catch(() => ({ error: 'Unknown error' }));
    alert('Error: ' + (d.error || 'Failed to start backup'));
  }
}

// ── Schedules ──────────────────────────────────────────────────────────────
async function loadSchedules() {
  const schedules = await apiFetch('/api/schedules') || [];
  const container = document.getElementById('schedules-list');
  container.innerHTML = '';

  if (schedules.length === 0) {
    container.innerHTML = '<div class="text-muted">No schedules configured. Click "Add Schedule" to create one.</div>';
    return;
  }

  schedules.forEach(s => {
    const card = document.createElement('div');
    card.className = 'stat-card mb-3';
    card.innerHTML = `
      <div class="d-flex align-items-start justify-content-between">
        <div>
          <div class="fw-semibold mb-1">${esc(s.Name)}
            <span class="badge ${s.Enabled ? 'badge-completed' : 'bg-secondary'} ms-2">${s.Enabled ? 'Enabled' : 'Disabled'}</span>
          </div>
          <div class="text-muted small mb-1">
            <i class="fa fa-clock me-1"></i><code>${esc(s.CronExpr)}</code>
          </div>
          <div class="text-muted small mb-1">
            <i class="fa fa-folder me-1"></i>${(s.SourceDirs || []).map(d => esc(d)).join(', ') || '(configured source dirs)'}
          </div>
          ${s.LastRunAt ? `<div class="text-muted small">Last run: ${fmtDate(s.LastRunAt)}</div>` : ''}
        </div>
        <div class="d-flex gap-2">
          <button class="btn btn-sm btn-outline-secondary py-0 px-2" onclick="editSchedule(${s.ID})">
            <i class="fa fa-pencil"></i>
          </button>
          <button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="deleteSchedule(${s.ID})">
            <i class="fa fa-trash"></i>
          </button>
        </div>
      </div>`;
    container.appendChild(card);
  });
}

function openScheduleModal(scheduleData) {
  document.getElementById('scheduleModalTitle').textContent = 'Add Schedule';
  document.getElementById('sched-edit-id').value = '';
  document.getElementById('sched-name').value = '';
  document.getElementById('sched-cron').value = '';
  document.getElementById('sched-dirs').value = '';
  document.getElementById('sched-enabled').checked = true;
  document.getElementById('sched-msg').classList.add('d-none');
  scheduleModal.show();
}

async function editSchedule(id) {
  const schedules = await apiFetch('/api/schedules') || [];
  const s = schedules.find(x => x.ID === id);
  if (!s) return;

  document.getElementById('scheduleModalTitle').textContent = 'Edit Schedule';
  document.getElementById('sched-edit-id').value = id;
  document.getElementById('sched-name').value = s.Name;
  document.getElementById('sched-cron').value = s.CronExpr;
  document.getElementById('sched-dirs').value = (s.SourceDirs || []).join('\n');
  document.getElementById('sched-enabled').checked = s.Enabled;
  document.getElementById('sched-msg').classList.add('d-none');
  scheduleModal.show();
}

async function saveSchedule() {
  const id = document.getElementById('sched-edit-id').value;
  const body = {
    name: document.getElementById('sched-name').value.trim(),
    cron_expr: document.getElementById('sched-cron').value.trim(),
    source_dirs: document.getElementById('sched-dirs').value.split('\n').map(s => s.trim()).filter(Boolean),
    enabled: document.getElementById('sched-enabled').checked
  };
  if (!body.name || !body.cron_expr) {
    showMsg('sched-msg', 'Name and cron expression are required.', 'danger');
    return;
  }

  const url  = id ? `/api/schedules/${id}` : '/api/schedules';
  const method = id ? 'PUT' : 'POST';
  const r = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (r.ok) {
    scheduleModal.hide();
    loadSchedules();
  } else {
    const d = await r.json().catch(() => ({ error: 'Save failed' }));
    showMsg('sched-msg', d.error || 'Save failed', 'danger');
  }
}

async function deleteSchedule(id) {
  if (!confirm('Delete this schedule?')) return;
  const r = await fetch(`/api/schedules/${id}`, { method: 'DELETE' });
  if (r.ok) loadSchedules();
}

// ── Settings ───────────────────────────────────────────────────────────────
async function loadSettings() {
  const cfg = await apiFetch('/api/config');
  if (!cfg) return;
  document.getElementById('cfg-remote-host').value = cfg.remote_host || '';
  document.getElementById('cfg-remote-port').value = cfg.remote_port || 22;
  document.getElementById('cfg-remote-user').value = cfg.remote_user || '';
  document.getElementById('cfg-key-path').value    = cfg.remote_key_path || '';
  document.getElementById('cfg-remote-path').value = cfg.remote_base_path || '';
  document.getElementById('cfg-source-dirs').value = (cfg.source_dirs || []).join('\n');
}

async function saveConfig() {
  const body = {
    remote_host:      document.getElementById('cfg-remote-host').value.trim(),
    remote_port:      parseInt(document.getElementById('cfg-remote-port').value) || 22,
    remote_user:      document.getElementById('cfg-remote-user').value.trim(),
    remote_key_path:  document.getElementById('cfg-key-path').value.trim(),
    remote_base_path: document.getElementById('cfg-remote-path').value.trim(),
    source_dirs:      document.getElementById('cfg-source-dirs').value.split('\n').map(s => s.trim()).filter(Boolean)
  };
  const r = await fetch('/api/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (r.ok) {
    alert('Configuration saved.');
  } else {
    const d = await r.json().catch(() => ({ error: 'Save failed' }));
    alert('Error: ' + (d.error || 'Save failed'));
  }
}

async function changePassword() {
  const p1 = document.getElementById('cfg-new-pwd').value;
  const p2 = document.getElementById('cfg-confirm-pwd').value;
  if (!p1) { showMsg('pwd-msg', 'Password cannot be empty.', 'danger'); return; }
  if (p1 !== p2) { showMsg('pwd-msg', 'Passwords do not match.', 'danger'); return; }
  const r = await fetch('/api/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: p1 })
  });
  if (r.ok) {
    showMsg('pwd-msg', 'Password changed successfully.', 'success');
    document.getElementById('cfg-new-pwd').value = '';
    document.getElementById('cfg-confirm-pwd').value = '';
  } else {
    const d = await r.json().catch(() => ({ error: 'Change failed' }));
    showMsg('pwd-msg', d.error || 'Change failed', 'danger');
  }
}

// ── Utilities ──────────────────────────────────────────────────────────────
async function apiFetch(url) {
  try {
    const r = await fetch(url);
    if (r.status === 401) { showLogin(); return null; }
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function fmtSize(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtDate(d) {
  if (!d) return '—';
  try {
    return new Date(d).toLocaleString();
  } catch { return String(d); }
}

function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function showMsg(elID, msg, type) {
  const el = document.getElementById(elID);
  el.textContent = msg;
  el.className = `small alert alert-${type} py-1 mt-2`;
  el.classList.remove('d-none');
}
