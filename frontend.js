'use strict';

// Replace this public URL with the workers.dev URL printed by `wrangler deploy`.
const API_BASE = 'https://kaischrodter3-bit.github.io/down/';
const TOKEN_KEY = 'postfach_access_token';
const state = { token: sessionStorage.getItem(TOKEN_KEY), uploads: [], busy: false };
const authView = document.getElementById('auth-view');
const dashboardView = document.getElementById('dashboard-view');
const authForm = document.getElementById('unlock-form');
const authMessage = document.getElementById('auth-message');
const icons = {
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z"/><path d="M13 3v7h7M[...]
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 7h16M10 11v6m4-6v6M5.5 7l1 14h11l1-14M9 7V4h6v3"/></svg>'
};

function apiUrl(path) {
  if (API_BASE.includes('CHANGE-ME')) throw new Error('Die Worker-Adresse fehlt noch. Trage die URL aus `wrangler deploy` in frontend.js ein.');
  return `${API_BASE.replace(/\/$/, '')}${path}`;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const response = await fetch(apiUrl(path), { ...options, headers, mode: 'cors' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && state.token) lockApp();
    throw new Error(data.error || 'Die Anfrage konnte nicht verarbeitet werden.');
  }
  return data;
}

function setMessage(message, success = false) {
  authMessage.textContent = message;
  authMessage.className = success ? 'form-message success' : 'form-message';
}

function lockApp() {
  const previousToken = state.token;
  state.token = null;
  state.uploads = [];
  sessionStorage.removeItem(TOKEN_KEY);
  dashboardView.classList.add('hidden');
  authView.classList.remove('hidden');
  document.getElementById('access-password').value = '';
  document.getElementById('header-note').textContent = 'Privater Dateitransfer';
  document.getElementById('file-list').replaceChildren();
  setMessage('Deine Sitzung ist abgelaufen. Bitte gib das Passwort erneut ein.');
  if (previousToken) {
    fetch(apiUrl('/api/logout'), { method: 'POST', headers: { Authorization: `Bearer ${previousToken}` } }).catch(() => {});
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.hidden = true; }, 3800);
}

function renderUploads() {
  const list = document.getElementById('file-list');
  const count = state.uploads.length;
  document.getElementById('file-count').textContent = `${count} ${count === 1 ? 'Datei' : 'Dateien'}`;
  if (!count) {
    list.innerHTML = `<div class="empty">${icons.file}<p>Noch keine Uploads vorhanden.</p></div>`;
    return;
  }
  list.innerHTML = state.uploads.map(file => {
    const date = new Date(file.uploadedAt).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
    const sent = file.status === 'email_sent';
    const status = sent ? 'Per E-Mail gesendet' : 'E-Mail fehlgeschlagen';
    return `<article class="file-row"><div class="file-info"><span class="file-type-icon">${icons.file}</span><div class="file-details"><div class="file-name" title="${escapeHtml(file.originalName)}">${escapeHtml(file.originalName)}</div><div class="file-meta">${formatSize(file.size)} • ${date} • ${status}</div></div></div><button class="delete-button" data-delete="${escapeHtml(file.id)}" aria-label="Löschen">${icons.trash}</button></article>`;
  }).join('');
}

async function loadDashboard() {
  const data = await request('/api/uploads');
  state.uploads = data.uploads;
  authView.classList.add('hidden');
  dashboardView.classList.remove('hidden');
  document.getElementById('header-note').textContent = 'Privater Dateitransfer';
  renderUploads();
}

authForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!authForm.reportValidity()) return;
  const button = document.getElementById('unlock-submit');
  button.disabled = true;
  setMessage('');
  try {
    const password = document.getElementById('access-password').value;
    const result = await request('/api/unlock', { method: 'POST', body: JSON.stringify({ password }) });
    state.token = result.token;
    sessionStorage.setItem(TOKEN_KEY, result.token);
    document.getElementById('access-password').value = '';
    setMessage('');
    await loadDashboard();
  } catch (error) {
    setMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

document.getElementById('logout-button').addEventListener('click', lockApp);

async function uploadFile(file) {
  if (state.busy) return;
  const maxBytes = 100_000_000;
  const progress = document.getElementById('upload-progress');
  const notice = document.getElementById('upload-notice');
  const progressBar = document.getElementById('progress-bar');
  const progressName = document.getElementById('progress-name');
  const progressValue = document.getElementById('progress-value');
  if (file.size > maxBytes) {
    notice.textContent = 'Die Datei ist zu groß. Erlaubt sind maximal 100 MB.';
    notice.className = 'notice error visible';
    return;
  }
  state.busy = true;
  notice.className = 'notice';
  notice.textContent = '';
  progress.classList.add('visible');
  progressName.textContent = file.name;
  progressBar.value = 0;
  progressValue.textContent = '0%';
  try {
    const result = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', apiUrl('/api/uploads'));
      xhr.setRequestHeader('Authorization', `Bearer ${state.token}`);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
      xhr.setRequestHeader('X-File-Size', String(file.size));
      xhr.upload.addEventListener('progress', event => {
        if (!event.lengthComputable) return;
        const percent = Math.round((event.loaded / event.total) * 100);
        progressBar.value = percent;
        progressValue.textContent = `${percent}%`;
      });
      xhr.addEventListener('load', () => {
        let data;
        try { data = JSON.parse(xhr.responseText); } catch { data = {}; }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error(data.error || 'Der Upload ist fehlgeschlagen.'));
      });
      xhr.addEventListener('error', () => reject(new Error('Keine Verbindung zum Server.')));
      xhr.send(file);
    });
    progressBar.value = 100;
    progressValue.textContent = '100%';
    notice.textContent = result.emailSent ? 'Datei hochgeladen und per E-Mail gesendet.' : `Datei gespeichert, aber E-Mail fehlgeschlagen: ${result.error || 'Bitte SMTP-Dienst prüfen.'}`;
    notice.className = `notice ${result.emailSent ? 'success' : 'error'} visible`;
    await loadDashboard();
  } catch (error) {
    notice.textContent = error.message;
    notice.className = 'notice error visible';
  } finally {
    state.busy = false;
    window.setTimeout(() => progress.classList.remove('visible'), 1400);
    document.getElementById('file-input').value = '';
  }
}

const fileInput = document.getElementById('file-input');
const dropzone = document.getElementById('dropzone');
fileInput.addEventListener('change', () => { if (fileInput.files[0]) uploadFile(fileInput.files[0]); });
for (const eventName of ['dragenter', 'dragover']) dropzone.addEventListener(eventName, event => { event.preventDefault(); dropzone.classList.add('dragover'); });
for (const eventName of ['dragleave', 'drop']) dropzone.addEventListener(eventName, event => { event.preventDefault(); dropzone.classList.remove('dragover'); });
dropzone.addEventListener('drop', event => { const file = event.dataTransfer.files[0]; if (file) uploadFile(file); });

document.getElementById('file-list').addEventListener('click', async event => {
  const button = event.target.closest('[data-delete]');
  if (!button || !window.confirm('Diesen Upload dauerhaft löschen?')) return;
  button.disabled = true;
  try {
    await request(`/api/uploads/${encodeURIComponent(button.dataset.delete)}`, { method: 'DELETE' });
    state.uploads = state.uploads.filter(file => file.id !== button.dataset.delete);
    renderUploads();
    showToast('Upload wurde gelöscht.');
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
});

if (state.token) loadDashboard().catch(() => lockApp());
