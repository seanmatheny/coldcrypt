/* Coldcrypt SPA */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let currentSection = 'dashboard';
let restoreFileID = null;
let restoreVersionNum = null;
let restoreDisplayPrefix = null;
let purgeDisplayPrefix = null;
let jobRefreshTimer = null;
let activeJobTimer = null;
let rateSamples = [];       // [{t: number, bytes: number}]
let lastActiveJobId = null;
const RATE_WINDOW_MS = 15000;

// Tracks which directory paths are expanded in the tree view.
const expandedDirs = new Set();

// ── Bootstrap modal handles ────────────────────────────────────────────────
let versionsModal, restoreModal, scheduleModal, purgeModal, jobFilesModal;

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  versionsModal  = new bootstrap.Modal(document.getElementById('versionsModal'));
  restoreModal   = new bootstrap.Modal(document.getElementById('restoreModal'));
  scheduleModal  = new bootstrap.Modal(document.getElementById('scheduleModal'));
  purgeModal     = new bootstrap.Modal(document.getElementById('purgeModal'));
  jobFilesModal  = new bootstrap.Modal(document.getElementById('jobFilesModal'));

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
    dashboard: 'Dashboard', files: 'Files', jobs: 'Jobs',
    schedules: 'Schedules', settings: 'Settings'
  };
  document.getElementById('topbar-section-name').textContent = names[section] || section;

  stopJobRefresh();
  stopActiveJobPolling();
  switch (section) {
    case 'dashboard': loadDashboard(); startActiveJobPolling(); break;
    case 'files':     loadFiles(); break;
    case 'jobs':      loadJobs(); loadStorage(); startJobRefresh(); startActiveJobPolling(); break;
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

  // Stop backup buttons
  document.getElementById('stop-job-btn').addEventListener('click', stopJob);
  document.getElementById('dash-stop-btn').addEventListener('click', stopJob);

  // File search
  document.getElementById('file-search-btn').addEventListener('click', () => {
    loadFiles(document.getElementById('file-search').value);
  });
  document.getElementById('file-search').addEventListener('keydown', e => {
    if (e.key === 'Enter') loadFiles(document.getElementById('file-search').value);
  });
  document.getElementById('file-clear-btn').addEventListener('click', () => {
    document.getElementById('file-search').value = '';
    loadFiles('');
  });

  // Restore All button
  document.getElementById('files-restore-all-btn').addEventListener('click', () => promptRestoreDir(''));

  // Purge All button
  document.getElementById('files-purge-all-btn').addEventListener('click', () => promptPurgeDir(''));

  // Schedule add
  document.getElementById('schedule-add-btn').addEventListener('click', openScheduleModal);
  document.getElementById('sched-save-btn').addEventListener('click', saveSchedule);

  // Restore confirm
  document.getElementById('restore-confirm-btn').addEventListener('click', doRestore);

  // Purge confirm
  document.getElementById('purge-confirm-btn').addEventListener('click', doPurge);

  // Settings save / password change
  document.getElementById('cfg-save-btn').addEventListener('click', saveConfig);
  document.getElementById('cfg-pwd-btn').addEventListener('click', changePassword);
  document.getElementById('cfg-del-retain-enabled').addEventListener('change', toggleDeletedRetentionFields);
}

// ── Dashboard ──────────────────────────────────────────────────────────────
async function loadDashboard() {
  const [stats, jobs, schedules] = await Promise.all([
    apiFetch('/api/stats'),
    apiFetch('/api/jobs'),
    apiFetch('/api/schedules')
  ]);

  document.getElementById('dash-total-files').textContent =
    (stats && stats.total_files != null) ? stats.total_files : 0;

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

// ── Files – lazy tree view ─────────────────────────────────────────────────
async function loadFiles(search = '') {
  const treeEl = document.getElementById('files-tree');
  const flatEl = document.getElementById('files-flat');
  const noteEl = document.getElementById('files-limit-note');

  if (noteEl) noteEl.classList.add('d-none');

  if (search) {
    // Flat search mode – use the existing search endpoint.
    treeEl.classList.add('d-none');
    flatEl.classList.remove('d-none');
    const url = `/api/files?search=${encodeURIComponent(search)}`;
    const resp = await apiFetch(url) || { files: [] };
    renderFlatList(resp.files || []);
    return;
  }

  // Tree mode: load root-level children and expand lazily.
  flatEl.classList.add('d-none');
  treeEl.classList.remove('d-none');
  treeEl.innerHTML = '<div class="text-muted small p-2"><i class="fa fa-spinner fa-spin me-1"></i>Loading…</div>';

  const resp = await apiFetch('/api/files/children?prefix=');
  if (!resp || ((resp.dirs || []).length === 0 && (resp.files || []).length === 0)) {
    treeEl.innerHTML = '<div class="text-muted text-center py-4">No files backed up yet.</div>';
    return;
  }

  treeEl.innerHTML = '';
  renderLazyLevel(resp.dirs || [], resp.files || [], treeEl, '', 0);
}

function renderFlatList(files) {
  const tbody = document.getElementById('files-tbody');
  tbody.innerHTML = '';
  if (files.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" class="text-muted text-center py-3">No files found</td></tr>';
    return;
  }
  files.forEach(f => {
    const fileMeta = [fmtSize(f.Size || 0), fmtMtimeNS(f.MtimeNS)].join(' • ');
    const tr = document.createElement('tr');
    tr.className = 'file-row';
    tr.innerHTML = `
      <td>
        <i class="fa fa-file me-2 text-muted"></i>${esc(f.DisplayPath)}
        <span class="text-muted small ms-2">${esc(fileMeta)}</span>
      </td>
      <td>
        <button class="btn btn-sm btn-outline-info py-0 px-2" onclick="showVersions(${f.ID}, '${esc(f.DisplayPath)}')">
          <i class="fa fa-clock-rotate-left me-1"></i>Versions
        </button>
      </td>`;
    tbody.appendChild(tr);
  });
}

// renderLazyLevel renders one level of the file tree.
// dirs/files come from GET /api/files/children.
// pathPrefix is the display-path prefix for this level; depth controls indentation.
function renderLazyLevel(dirs, files, container, pathPrefix, depth) {
  const indent = depth * 20 + 8;

  dirs.forEach(dir => {
    const fullPath = dir.path; // already ends with "/"
    const dirName = dir.name;
    const isExpanded = expandedDirs.has(fullPath);

    const rowEl = document.createElement('div');
    rowEl.className = 'tree-row tree-dir';
    rowEl.style.paddingLeft = indent + 'px';
    rowEl.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    rowEl.innerHTML = `
      <span class="tree-toggle" aria-hidden="true">${isExpanded ? '▾' : '▸'}</span>
      <i class="fa ${isExpanded ? 'fa-folder-open' : 'fa-folder'} text-warning me-1 tree-folder-icon" aria-hidden="true"></i>
      <span class="tree-name">${esc(dirName)}</span>
      <span class="tree-actions">
        <button class="btn btn-xs btn-outline-success ms-2"
          title="Restore this directory"
          onclick="event.stopPropagation(); promptRestoreDir('${esc(fullPath)}')">
          <i class="fa fa-download me-1"></i>Restore
        </button>
        <button class="btn btn-xs btn-outline-danger ms-1"
          title="Purge this directory"
          onclick="event.stopPropagation(); promptPurgeDir('${esc(fullPath)}')">
          <i class="fa fa-trash me-1"></i>Purge
        </button>
      </span>`;

    const childrenEl = document.createElement('div');
    childrenEl.className = isExpanded ? '' : 'd-none';

    async function loadChildren() {
      if (childrenEl.dataset.loaded) return;
      childrenEl.innerHTML = `<div class="text-muted small" style="padding-left:${indent + 20}px"><i class="fa fa-spinner fa-spin me-1"></i>Loading…</div>`;
      const r = await apiFetch('/api/files/children?prefix=' + encodeURIComponent(fullPath));
      childrenEl.innerHTML = '';
      if (r) {
        renderLazyLevel(r.dirs || [], r.files || [], childrenEl, fullPath, depth + 1);
      }
      childrenEl.dataset.loaded = '1';
    }

    rowEl.addEventListener('click', async () => {
      if (expandedDirs.has(fullPath)) {
        expandedDirs.delete(fullPath);
        rowEl.setAttribute('aria-expanded', 'false');
        rowEl.querySelector('.tree-toggle').textContent = '▸';
        rowEl.querySelector('.tree-folder-icon').className = 'fa fa-folder text-warning me-1 tree-folder-icon';
        childrenEl.classList.add('d-none');
      } else {
        expandedDirs.add(fullPath);
        rowEl.setAttribute('aria-expanded', 'true');
        rowEl.querySelector('.tree-toggle').textContent = '▾';
        rowEl.querySelector('.tree-folder-icon').className = 'fa fa-folder-open text-warning me-1 tree-folder-icon';
        childrenEl.classList.remove('d-none');
        await loadChildren();
      }
    });

    container.appendChild(rowEl);
    container.appendChild(childrenEl);

    // If this directory was expanded in a previous visit, reload its children now.
    if (isExpanded) loadChildren();
  });

  // Files at this level.
  files.forEach(f => {
    const rowEl = document.createElement('div');
    rowEl.className = 'tree-row tree-file';
    rowEl.style.paddingLeft = indent + 'px';
    const fileMeta = [fmtSize(f.size || 0), fmtMtimeNS(f.mtime_ns)].join(' • ');
    rowEl.innerHTML = `
      <span class="tree-toggle invisible" aria-hidden="true">▸</span>
      <i class="fa fa-file text-muted me-1"></i>
      <span class="tree-name">${esc(f.basename)} <span class="text-muted small ms-2">${esc(fileMeta)}</span></span>
      <span class="tree-actions">
        <button class="btn btn-xs btn-outline-info ms-2"
          onclick="event.stopPropagation(); showVersions(${f.id}, '${esc(f.display_path)}')">
          <i class="fa fa-clock-rotate-left me-1"></i>Versions
        </button>
      </span>`;
    container.appendChild(rowEl);
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
    const mtime = fmtMtimeNS(v.MtimeNS);
    div.innerHTML = `
      <div>
        <span class="badge bg-secondary me-2">v${v.VersionNum}</span>
        <span class="small">${fmtDate(v.EncryptedAt)}</span>
        <span class="text-muted small ms-3">${fmtSize(v.Size)}</span>
        <span class="text-muted small ms-3">${mtime}</span>
        <span class="text-muted small ms-3 font-monospace" title="${esc(v.Hash)}">${v.Hash.substring(0,12)}…</span>
      </div>
      <div class="d-flex gap-2">
        <button class="btn btn-sm btn-outline-success py-0 px-2"
          onclick="promptRestore(${fileID}, ${v.VersionNum}, '${esc(displayPath)}')">
          <i class="fa fa-download me-1"></i>Restore
        </button>
        <button class="btn btn-sm btn-outline-danger py-0 px-2"
          title="Purge this version permanently"
          onclick="purgeVersion(${fileID}, ${v.VersionNum}, '${esc(displayPath)}')">
          <i class="fa fa-trash"></i>
        </button>
      </div>`;
    body.appendChild(div);
  });
}

async function purgeVersion(fileID, versionNum, displayPath) {
  const ok = window.confirm(`Purge version v${versionNum} for ${displayPath}? This cannot be undone.`);
  if (!ok) return;

  const r = await fetch(`/api/files/${fileID}/purge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version_num: versionNum })
  });
  if (r.ok) {
    const d = await r.json().catch(() => ({}));
    if (d.warning) alert(d.warning);
    await showVersions(fileID, displayPath);
    loadFiles();
  } else {
    const d = await r.json().catch(() => ({ error: 'Version purge failed' }));
    alert(d.error || 'Version purge failed');
  }
}

// Prompt to restore a single file version.
function promptRestore(fileID, versionNum, displayPath) {
  restoreFileID = fileID;
  restoreVersionNum = versionNum;
  restoreDisplayPrefix = null;
  versionsModal.hide();
  document.getElementById('restoreModalLabel').textContent = `Restore: ${displayPath}`;
  document.getElementById('restore-path-hint').textContent =
    'Enter the full path on this machine where the file should be restored. ' +
    'If you enter a directory path, the original filename will be appended.';
  document.getElementById('restore-out-path').value = '/Universe/Customs';
  document.getElementById('restore-msg').classList.add('d-none');
  restoreModal.show();
}

// Prompt to restore a whole directory (or everything when prefix is '').
function promptRestoreDir(displayPrefix) {
  restoreFileID = null;
  restoreVersionNum = 0;
  restoreDisplayPrefix = displayPrefix;
  const label = displayPrefix ? `Restore directory: ${displayPrefix}` : 'Restore All Files';
  document.getElementById('restoreModalLabel').textContent = label;
  document.getElementById('restore-path-hint').textContent =
    'Enter the root output directory on this machine. All files will be restored here, preserving their directory structure.';
  document.getElementById('restore-out-path').value = '/Universe/Customs';
  document.getElementById('restore-msg').classList.add('d-none');
  restoreModal.show();
}

async function doRestore() {
  const outPath = document.getElementById('restore-out-path').value.trim();
  if (!outPath) {
    showMsg('restore-msg', 'Please enter an output path.', 'danger');
    return;
  }

  let r;
  if (restoreFileID !== null) {
    // Single-file restore.
    r = await fetch(`/api/files/${restoreFileID}/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version_num: restoreVersionNum, out_path: outPath })
    });
  } else {
    // Directory / bulk restore.
    r = await fetch('/api/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ display_prefix: restoreDisplayPrefix || '', out_path: outPath, version_num: 0 })
    });
  }

  if (r.ok) {
    const d = await r.json().catch(() => ({}));
    const idPart = d.job_id ? ` (Job #${d.job_id})` : '';
    const msg = restoreFileID !== null
      ? `Restore started${idPart}. File will appear at: ${outPath}`
      : `Restore started${idPart}. Files will appear in: ${outPath}`;
    showMsg('restore-msg', msg, 'success');
    setTimeout(() => restoreModal.hide(), 2000);
    if (currentSection === 'jobs') loadJobs();
    if (currentSection === 'dashboard') loadDashboard();
  } else {
    const d = await r.json().catch(() => ({ error: 'Restore failed' }));
    showMsg('restore-msg', d.error || 'Restore failed', 'danger');
  }
}

// Prompt to purge a directory (or everything when prefix is '').
function promptPurgeDir(displayPrefix) {
  purgeDisplayPrefix = displayPrefix;
  const label = displayPrefix ? `Purge directory: ${displayPrefix}` : 'Purge All Backups';
  document.getElementById('purgeModalLabel').textContent = label;
  const desc = displayPrefix
    ? `All backed-up blobs under <strong>${esc(displayPrefix)}</strong> will be permanently deleted from the remote server and removed from the local database.`
    : 'All backed-up blobs will be permanently deleted from the remote server and the local database will be cleared.';
  document.getElementById('purge-target-desc').innerHTML = desc;
  document.getElementById('purge-confirm-input').value = '';
  document.getElementById('purge-msg').classList.add('d-none');
  purgeModal.show();
}

async function doPurge() {
  const input = document.getElementById('purge-confirm-input').value.trim();
  if (input !== 'DELETE ALL') {
    showMsg('purge-msg', 'You must type DELETE ALL to confirm.', 'danger');
    return;
  }

  const btn = document.getElementById('purge-confirm-btn');
  btn.disabled = true;
  btn.textContent = 'Purging…';

  const r = await fetch('/api/purge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ display_prefix: purgeDisplayPrefix || '' })
  });

  btn.disabled = false;
  btn.innerHTML = '<i class="fa fa-trash me-1"></i>Purge';

  if (r.ok) {
    const d = await r.json().catch(() => ({}));
    if (d.warning) showMsg('purge-msg', d.warning, 'warning');
    else showMsg('purge-msg', 'Purge completed successfully.', 'success');
    setTimeout(() => { purgeModal.hide(); loadFiles(); }, 1500);
  } else {
    const d = await r.json().catch(() => ({ error: 'Purge failed' }));
    showMsg('purge-msg', d.error || 'Purge failed', 'danger');
  }
}

// ── Jobs ───────────────────────────────────────────────────────────────────
async function loadJobs() {
  const jobs = await apiFetch('/api/jobs') || [];
  const tbody = document.getElementById('jobs-tbody');
  tbody.innerHTML = '';
  if (jobs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center py-3">No jobs yet</td></tr>';
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
    <td>${jobTypeBadge(job.JobType)}</td>
    <td class="small">${fmtDate(job.StartedAt)}</td>
    <td class="small">${job.FilesProcessed}</td>
    <td class="small">${fmtSize(job.BytesTransferred)}</td>
  </tr>`;
}

function jobRowFull(job) {
  return `<tr>
    <td class="text-muted small">#${job.ID}</td>
    <td>${statusBadge(job.Status)}</td>
    <td>${jobTypeBadge(job.JobType)}</td>
    <td class="small">${fmtDate(job.StartedAt)}</td>
    <td class="small">${job.CompletedAt ? fmtDate(job.CompletedAt) : '—'}</td>
    <td class="small">${job.FilesProcessed}</td>
    <td class="small">${fmtSize(job.BytesTransferred)}</td>
    <td class="small text-danger">${esc(job.ErrorMessage || '')}</td>
    <td class="small"><button class="btn btn-sm btn-outline-secondary py-0 px-2" onclick="openJobFiles(${job.ID})" title="View files transferred"><i class="fa fa-list"></i></button></td>
  </tr>`;
}

function jobTypeBadge(type) {
  if (type === 'restore') {
    return '<span class="badge bg-info text-dark">restore</span>';
  }
  return '<span class="badge bg-primary">backup</span>';
}

function statusBadge(status) {
  const cls = {
    running: 'badge-running',
    completed: 'badge-completed',
    failed: 'badge-failed',
    stopped: 'badge-stopped',
    completed_with_errors: 'badge-warning'
  }[status] || 'bg-secondary';
  return `<span class="badge ${cls}">${status}</span>`;
}

function startJobRefresh() {
  jobRefreshTimer = setInterval(loadJobs, 5000);
}

function stopJobRefresh() {
  if (jobRefreshTimer) { clearInterval(jobRefreshTimer); jobRefreshTimer = null; }
}

// Opens a modal showing all files processed by a specific job.
async function openJobFiles(jobID) {
  document.getElementById('job-files-id').textContent = jobID;
  document.getElementById('job-files-body').innerHTML =
    '<div class="text-center text-muted py-4"><i class="fa fa-spinner fa-spin me-2"></i>Loading…</div>';
  document.getElementById('job-files-count').textContent = '';
  jobFilesModal.show();

  const files = await apiFetch(`/api/jobs/${jobID}/files`);
  if (!files) {
    document.getElementById('job-files-body').innerHTML =
      '<div class="text-muted text-center py-3">Failed to load files.</div>';
    return;
  }
  if (files.length === 0) {
    document.getElementById('job-files-body').innerHTML =
      '<div class="text-muted text-center py-3">No file-level detail is recorded for this job. ' +
      '(File tracking is only available for backup jobs.)</div>';
    return;
  }

  document.getElementById('job-files-count').textContent = `${files.length.toLocaleString()} file(s)`;

  let html = `<table class="table table-dark table-sm mb-0" style="font-size:0.82rem;">
    <thead><tr>
      <th>File</th>
      <th class="text-end" style="white-space:nowrap;">Size</th>
      <th class="text-end" style="white-space:nowrap;">Processed At</th>
    </tr></thead><tbody>`;
  for (const f of files) {
    html += `<tr>
      <td style="word-break:break-all;font-family:monospace;font-size:0.78rem;">${esc(f.DisplayPath)}</td>
      <td class="text-end text-muted" style="white-space:nowrap;">${fmtSize(f.Size)}</td>
      <td class="text-end text-muted" style="white-space:nowrap;">${fmtDate(f.EncryptedAt)}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  document.getElementById('job-files-body').innerHTML = html;
}

// Loads remote storage utilisation and renders the gauge card in the Jobs section.
async function loadStorage() {
  const card = document.getElementById('storage-gauge-card');
  if (!card) return;
  const data = await apiFetch('/api/storage');
  if (!data) {
    // Not configured or unreachable — keep the card hidden.
    card.classList.add('d-none');
    return;
  }
  card.classList.remove('d-none');

  const pctUsed = data.percent_used || 0;
  const pctFree = data.percent_free != null ? data.percent_free : (100 - pctUsed);

  // Colour thresholds: green ≥ 30 % free, orange 10–29 %, red 0–9 %.
  // The red/notification boundary (9 %) must stay in sync with
  // storageLowPctThreshold in internal/web/handlers.go.
  let colour;
  if (pctFree >= 30) colour = '#238636';       // green
  else if (pctFree >= 10) colour = '#d29922';  // orange
  else colour = '#da3633';                      // red

  const bar = document.getElementById('storage-bar');
  bar.style.width = pctUsed + '%';
  bar.style.backgroundColor = colour;
  bar.setAttribute('aria-valuenow', pctUsed);

  const freeStr  = fmtSize((data.free_kb  || 0) * 1024);
  const totalStr = fmtSize((data.total_kb || 0) * 1024);
  document.getElementById('storage-detail').textContent =
    `${freeStr} free of ${totalStr} (${pctFree}% free)`;
  document.getElementById('storage-mount').textContent =
    `${data.filesystem || ''} → mounted at ${data.mount_point || ''}`;
}

// ── Active job polling ─────────────────────────────────────────────────────
function startActiveJobPolling() {
  pollActiveJob(); // immediate first hit
  activeJobTimer = setInterval(pollActiveJob, 2000);
}

function stopActiveJobPolling() {
  if (activeJobTimer) { clearInterval(activeJobTimer); activeJobTimer = null; }
}

async function pollActiveJob() {
  const status = await apiFetch('/api/jobs/active');
  if (!status) return;
  updateActiveJobUI(status);
}

function updateActiveJobUI(status) {
  const isRunning = status.running;
  const isBackupJob = (status.job_type || 'backup') === 'backup';
  const runningLabel = isBackupJob ? 'BACKUP RUNNING' : 'RESTORE RUNNING';

  // Accumulate rate samples.
  if (isRunning) {
    if (status.job_id !== lastActiveJobId) {
      rateSamples = [];
      lastActiveJobId = status.job_id;
    }
    rateSamples.push({ t: Date.now(), bytes: status.bytes_transferred || 0 });
    if (rateSamples.length > 120) rateSamples.shift();
  }

  // Compute transfer rate from a rolling window to reduce burst spikes.
  let rateStr = '—';
  if (rateSamples.length >= 2) {
    const last = rateSamples[rateSamples.length - 1];
    let prev = rateSamples[0];
    for (let i = rateSamples.length - 2; i >= 0; i--) {
      if (last.t - rateSamples[i].t >= RATE_WINDOW_MS) {
        break;
      }
      prev = rateSamples[i];
    }
    const dt = (last.t - prev.t) / 1000;
    if (dt > 0) {
      const rateVal = Math.max(0, (last.bytes - prev.bytes) / dt);
      rateStr = fmtSize(rateVal) + '/s';
    }
  }

  // Update the Jobs section active-job panel.
  const panel = document.getElementById('active-job-panel');
  if (panel) {
    if (isRunning) {
      panel.classList.remove('d-none');
      const badgeEl = panel.querySelector('.badge');
      if (badgeEl) badgeEl.textContent = runningLabel;
      const jobIdEl = document.getElementById('active-job-id');
      if (jobIdEl) jobIdEl.textContent = `Job #${status.job_id}`;
      const stopBtn = document.getElementById('stop-job-btn');
      if (stopBtn) stopBtn.classList.toggle('d-none', !isBackupJob);
      const fileEl = document.getElementById('active-job-file');
      if (fileEl) fileEl.textContent = status.current_file || '—';
      const filesEl = document.getElementById('active-job-files');
      if (filesEl) filesEl.textContent = (status.files_processed || 0).toLocaleString();
      const bytesEl = document.getElementById('active-job-bytes');
      if (bytesEl) bytesEl.textContent = fmtSize(status.bytes_transferred || 0);
      const rateEl = document.getElementById('active-job-rate');
      if (rateEl) rateEl.textContent = rateStr;
      const canvas = document.getElementById('rate-graph');
      if (canvas) drawRateGraph(canvas, rateSamples);
    } else {
      panel.classList.add('d-none');
    }
  }

  // Update the Dashboard active-job indicator.
  const dashPanel = document.getElementById('dash-active-job');
  if (dashPanel) {
    if (isRunning) {
      dashPanel.classList.remove('d-none');
      const badgeEl = dashPanel.querySelector('.badge');
      if (badgeEl) badgeEl.textContent = runningLabel;
      const el = document.getElementById('dash-active-job-id');
      if (el) el.textContent = `Job #${status.job_id}`;
      const stopBtn = document.getElementById('dash-stop-btn');
      if (stopBtn) stopBtn.classList.toggle('d-none', !isBackupJob);
      const fileEl = document.getElementById('dash-active-file');
      if (fileEl) fileEl.textContent = status.current_file || '—';
      const filesEl = document.getElementById('dash-active-files');
      if (filesEl) filesEl.textContent = (status.files_processed || 0).toLocaleString();
      const bytesEl = document.getElementById('dash-active-bytes');
      if (bytesEl) bytesEl.textContent = fmtSize(status.bytes_transferred || 0);
      const rateEl = document.getElementById('dash-active-rate');
      if (rateEl) rateEl.textContent = rateStr;
    } else {
      dashPanel.classList.add('d-none');
    }
  }
}

async function stopJob() {
  const r = await fetch('/api/jobs/active/stop', { method: 'POST' });
  if (!r.ok) {
    const d = await r.json().catch(() => ({ error: 'Stop failed' }));
    alert('Error: ' + (d.error || 'Stop failed'));
    return;
  }
  // Poll immediately so the UI updates quickly.
  setTimeout(pollActiveJob, 500);
}

function drawRateGraph(canvas, samples) {
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth;
  const cssH = canvas.clientHeight;
  if (cssW === 0 || cssH === 0) return;

  const W = Math.round(cssW * dpr);
  const H = Math.round(cssH * dpr);
  if (canvas.width !== W || canvas.height !== H) {
    canvas.width = W;
    canvas.height = H;
  }

  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);

  if (samples.length < 2) return;

  // Compute per-sample rates (bytes/sec).
  const rates = [];
  for (let i = 1; i < samples.length; i++) {
    const dt = (samples[i].t - samples[i - 1].t) / 1000;
    const db = samples[i].bytes - samples[i - 1].bytes;
    if (dt > 0) rates.push(Math.max(0, db / dt));
  }
  if (rates.length < 1) return;

  const maxRate = Math.max(...rates, 1);
  const pad = 4 * dpr;
  const plotW = W - pad * 2;
  const plotH = H - pad * 2;
  const n = rates.length;
  const xOf = i => pad + (n > 1 ? i / (n - 1) : 0) * plotW;
  const yOf = r => pad + plotH - (r / maxRate) * plotH;

  // Filled area under the curve.
  ctx.fillStyle = 'rgba(88,166,255,0.12)';
  ctx.beginPath();
  ctx.moveTo(xOf(0), H - pad);
  rates.forEach((r, i) => ctx.lineTo(xOf(i), yOf(r)));
  ctx.lineTo(xOf(n - 1), H - pad);
  ctx.closePath();
  ctx.fill();

  // Line.
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 2 * dpr;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  rates.forEach((r, i) => {
    if (i === 0) ctx.moveTo(xOf(i), yOf(r));
    else ctx.lineTo(xOf(i), yOf(r));
  });
  ctx.stroke();

  // Current rate label in top-right corner.
  const currentRate = rates[n - 1];
  ctx.fillStyle = '#58a6ff';
  ctx.font = `${Math.round(11 * dpr)}px monospace`;
  ctx.textAlign = 'right';
  ctx.fillText(fmtSize(currentRate) + '/s', W - pad, pad + Math.round(12 * dpr));
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
  document.getElementById('cfg-exclude-paths').value = (cfg.exclude_paths || []).join('\n');
  document.getElementById('cfg-exclude-regexes').value = (cfg.exclude_regexes || []).join('\n');
  document.getElementById('cfg-del-retain-enabled').checked = !!cfg.deleted_retention_enabled;
  document.getElementById('cfg-del-retain-value').value = cfg.deleted_retention_value || 14;
  document.getElementById('cfg-del-retain-unit').value = cfg.deleted_retention_unit || 'days';
  toggleDeletedRetentionFields();
}

async function saveConfig() {
  const body = {
    remote_host:      document.getElementById('cfg-remote-host').value.trim(),
    remote_port:      parseInt(document.getElementById('cfg-remote-port').value) || 22,
    remote_user:      document.getElementById('cfg-remote-user').value.trim(),
    remote_key_path:  document.getElementById('cfg-key-path').value.trim(),
    remote_base_path: document.getElementById('cfg-remote-path').value.trim(),
    source_dirs:      document.getElementById('cfg-source-dirs').value.split('\n').map(s => s.trim()).filter(Boolean),
    exclude_paths:    document.getElementById('cfg-exclude-paths').value.split('\n').map(s => s.trim()).filter(Boolean),
    exclude_regexes:  document.getElementById('cfg-exclude-regexes').value.split('\n').map(s => s.trim()).filter(Boolean),
    deleted_retention_enabled: document.getElementById('cfg-del-retain-enabled').checked,
    deleted_retention_value: Math.max(0, parseInt(document.getElementById('cfg-del-retain-value').value, 10) || 0),
    deleted_retention_unit: document.getElementById('cfg-del-retain-unit').value
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

function fmtMtimeNS(ns) {
  if (!ns) return 'unknown time';
  return fmtDate(new Date(ns / 1e6).toISOString());
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

function toggleDeletedRetentionFields() {
  const enabled = document.getElementById('cfg-del-retain-enabled').checked;
  document.getElementById('cfg-del-retain-value').disabled = !enabled;
  document.getElementById('cfg-del-retain-unit').disabled = !enabled;
}
