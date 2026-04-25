(function () {
  const DEFAULTS = {
    repoOwner: 'linxingaifei',
    repoName: 'ikguard-core',
    repoRef: 'main',
    workflowFile: 'license.yml',
    licensePath: 'licenses/license.json',
    publicKeyPath: 'license/public_key.json',
    subject: 'customer-a',
    licenseOwner: 'linxingaifei',
    licenseRepo: 'linxingaifei/ikguard-core',
    pluginName: 'ikguard',
    deviceId: '',
    features: 'scan,clean,validate',
    expiresInDays: '90',
    note: '',
  };

  const STORAGE_KEYS = {
    token: 'ikguard.pages.token',
    rememberToken: 'ikguard.pages.rememberToken',
    settings: 'ikguard.pages.settings',
  };

  const state = {
    licenseJson: null,
    currentLicenseText: '',
    currentPublicKey: null,
    lastWorkflowRunUrl: '',
  };

  function $(id) {
    const el = document.getElementById(id);
    if (!el) throw new Error(`Missing element: ${id}`);
    return el;
  }

  function readSettings() {
    const raw = localStorage.getItem(STORAGE_KEYS.settings);
    const saved = raw ? JSON.parse(raw) : {};
    return { ...DEFAULTS, ...saved };
  }

  function writeSettings(settings) {
    localStorage.setItem(STORAGE_KEYS.settings, JSON.stringify(settings));
  }

  function getToken() {
    const remember = $('rememberToken').checked;
    if (remember) {
      return localStorage.getItem(STORAGE_KEYS.token) || '';
    }
    return sessionStorage.getItem(STORAGE_KEYS.token) || '';
  }

  function setToken(value) {
    const remember = $('rememberToken').checked;
    sessionStorage.setItem(STORAGE_KEYS.token, value);
    if (remember) {
      localStorage.setItem(STORAGE_KEYS.token, value);
    } else {
      localStorage.removeItem(STORAGE_KEYS.token);
    }
  }

  function setBadge(id, text, kind) {
    const el = $(id);
    el.textContent = text;
    el.className = kind ? kind : '';
  }

  function log(message, kind) {
    const panel = $('logPanel');
    const now = new Date().toLocaleString('zh-CN', { hour12: false });
    const line = `[${now}] ${message}`;
    panel.textContent = panel.textContent ? `${panel.textContent}\n${line}` : line;
    if (kind === 'error') {
      setBadge('stateBadge', '错误', 'bad');
    }
  }

  function setLicensePreview(text) {
    $('licensePreview').textContent = text;
  }

  function formatDate(value) {
    if (!value) return '-';
    const date = new Date(Number(value) * 1000);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString('zh-CN', { hour12: false });
  }

  function normalizeText(value) {
    return String(value || '').trim();
  }

  function encodePath(path) {
    return path.split('/').map(encodeURIComponent).join('/');
  }

  function splitFeatures(value) {
    return normalizeText(value)
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function canonicalize(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) {
      return `[${value.map(canonicalize).join(',')}]`;
    }
    const type = typeof value;
    if (type === 'string' || type === 'number' || type === 'boolean') {
      return JSON.stringify(value);
    }
    if (type === 'object') {
      const keys = Object.keys(value).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
    }
    return 'null';
  }

  function base64UrlToBytes(text) {
    const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function uintToBase64Url(value) {
    let num = Number(value);
    if (!Number.isFinite(num) || num <= 0) {
      throw new Error('Invalid RSA exponent');
    }
    const bytes = [];
    while (num > 0) {
      bytes.unshift(num & 0xff);
      num >>= 8;
    }
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function toJwk(publicKey) {
    const exponent = typeof publicKey.e === 'number' ? uintToBase64Url(publicKey.e) : normalizeText(publicKey.e);
    const jwk = {
      kty: 'RSA',
      alg: publicKey.alg || 'RS256',
      ext: true,
      n: normalizeText(publicKey.n),
      e: exponent,
    };
    if (normalizeText(publicKey.kid)) {
      jwk.kid = normalizeText(publicKey.kid);
    }
    return jwk;
  }

  async function githubRequest(method, path, token, body) {
    const headers = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const options = { method, headers, mode: 'cors' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    const response = await fetch(`https://api.github.com${path}`, options);
    const text = await response.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (err) {
        payload = { raw: text };
      }
    }
    if (!response.ok) {
      const message = payload && payload.message ? payload.message : `${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    return payload;
  }

  async function readRepoJson(owner, repo, ref, path, token) {
    const payload = await githubRequest(
      'GET',
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodePath(path)}?ref=${encodeURIComponent(ref)}`,
      token
    );
    if (!payload || typeof payload.content !== 'string') {
      throw new Error(`无法读取 ${path}`);
    }
    const raw = atob(payload.content.replace(/\n/g, ''));
    return JSON.parse(raw);
  }

  async function readRepoText(owner, repo, ref, path, token) {
    const payload = await githubRequest(
      'GET',
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodePath(path)}?ref=${encodeURIComponent(ref)}`,
      token
    );
    if (!payload || typeof payload.content !== 'string') {
      throw new Error(`无法读取 ${path}`);
    }
    return atob(payload.content.replace(/\n/g, ''));
  }

  async function verifyLicenseArtifact(artifact, publicKey, expected) {
    if (!artifact || artifact.format !== 'ikguard-license-v1') {
      return { ok: false, reason: 'invalid license format' };
    }
    if (artifact.alg !== 'RS256') {
      return { ok: false, reason: 'unsupported license algorithm' };
    }
    if (publicKey.kid && artifact.kid && publicKey.kid !== artifact.kid) {
      return { ok: false, reason: 'license kid mismatch' };
    }
    if (!artifact.license || !artifact.signature) {
      return { ok: false, reason: 'invalid license artifact' };
    }

    const payload = artifact.license;
    const now = Math.floor(Date.now() / 1000);
    if (Number(payload.exp || 0) <= now) {
      return { ok: false, reason: 'license expired' };
    }

    for (const key of ['plugin', 'owner', 'repo', 'device']) {
      const wanted = normalizeText(expected[key]);
      const actual = normalizeText(payload[key]);
      if (wanted && actual && wanted !== actual) {
        return { ok: false, reason: `${key} mismatch` };
      }
    }

    const jwk = toJwk(publicKey);
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const signature = base64UrlToBytes(artifact.signature);
    const message = new TextEncoder().encode(canonicalize(payload));
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, message);
    if (!ok) {
      return { ok: false, reason: 'signature verification failed' };
    }

    return {
      ok: true,
      reason: 'authorized',
      result: {
        license_id: payload.jti || '',
        subject: payload.sub || '',
        owner: payload.owner || '',
        repo: payload.repo || '',
        plugin: payload.plugin || '',
        device: payload.device || '',
        features: payload.features || [],
        issued_at: payload.iat || 0,
        expires_at: payload.exp || 0,
      },
    };
  }

  function getConnectionConfig() {
    return {
      owner: normalizeText($('repoOwner').value),
      repo: normalizeText($('repoName').value),
      ref: normalizeText($('repoRef').value),
      workflow: normalizeText($('workflowFile').value),
      licensePath: normalizeText($('licensePath').value),
      publicKeyPath: normalizeText($('publicKeyPath').value),
      token: getToken(),
    };
  }

  function getIssueConfig() {
    return {
      subject: normalizeText($('subject').value),
      owner: normalizeText($('licenseOwner').value),
      repo: normalizeText($('licenseRepo').value),
      plugin: normalizeText($('pluginName').value) || 'ikguard',
      device: normalizeText($('deviceId').value),
      features: splitFeatures($('features').value).join(','),
      expires_in_days: normalizeText($('expiresInDays').value) || '90',
      note: normalizeText($('note').value),
      license_path: normalizeText($('dispatchLicensePath').value),
    };
  }

  function updateHeroState(connected) {
    setBadge('stateBadge', connected ? '已连接' : '未连接', connected ? 'ok' : '');
    $('openActions').href = `https://github.com/${encodeURIComponent($('repoOwner').value)}/${encodeURIComponent($('repoName').value)}/actions/workflows/${encodeURIComponent($('workflowFile').value)}`;
  }

  function applySettings() {
    const settings = readSettings();
    $('repoOwner').value = settings.repoOwner;
    $('repoName').value = settings.repoName;
    $('repoRef').value = settings.repoRef;
    $('workflowFile').value = settings.workflowFile;
    $('licensePath').value = settings.licensePath;
    $('publicKeyPath').value = settings.publicKeyPath;
    $('subject').value = settings.subject;
    $('licenseOwner').value = settings.licenseOwner;
    $('licenseRepo').value = settings.licenseRepo;
    $('pluginName').value = settings.pluginName;
    $('deviceId').value = settings.deviceId;
    $('features').value = settings.features;
    $('expiresInDays').value = settings.expiresInDays;
    $('note').value = settings.note;
    $('dispatchLicensePath').value = settings.licensePath;

    $('rememberToken').checked = localStorage.getItem(STORAGE_KEYS.rememberToken) === '1';
    const token = localStorage.getItem(STORAGE_KEYS.token) || sessionStorage.getItem(STORAGE_KEYS.token) || '';
    $('githubToken').value = token;
    updateHeroState(Boolean(settings.repoOwner && settings.repoName));
  }

  function saveSettings() {
    const settings = {
      repoOwner: normalizeText($('repoOwner').value),
      repoName: normalizeText($('repoName').value),
      repoRef: normalizeText($('repoRef').value),
      workflowFile: normalizeText($('workflowFile').value),
      licensePath: normalizeText($('licensePath').value),
      publicKeyPath: normalizeText($('publicKeyPath').value),
      subject: normalizeText($('subject').value),
      licenseOwner: normalizeText($('licenseOwner').value),
      licenseRepo: normalizeText($('licenseRepo').value),
      pluginName: normalizeText($('pluginName').value),
      deviceId: normalizeText($('deviceId').value),
      features: normalizeText($('features').value),
      expiresInDays: normalizeText($('expiresInDays').value),
      note: normalizeText($('note').value),
    };
    writeSettings(settings);
    $('dispatchLicensePath').value = settings.licensePath;
    localStorage.setItem(STORAGE_KEYS.rememberToken, $('rememberToken').checked ? '1' : '0');
    setToken(normalizeText($('githubToken').value));
    setBadge('stateBadge', '已保存', 'ok');
    log('配置已保存到浏览器本地。');
  }

  async function loadLicense() {
    try {
      const cfg = getConnectionConfig();
      if (!cfg.owner || !cfg.repo) throw new Error('请先填写仓库 owner/repo');
      setBadge('stateBadge', '读取中...', '');
      log(`读取授权：${cfg.owner}/${cfg.repo}@${cfg.ref} -> ${cfg.licensePath}`);
      const artifact = await readRepoJson(cfg.owner, cfg.repo, cfg.ref, cfg.licensePath, cfg.token);
      const publicKey = await readRepoJson(cfg.owner, cfg.repo, cfg.ref, cfg.publicKeyPath, cfg.token);
      state.licenseJson = artifact;
      state.currentPublicKey = publicKey;
      state.currentLicenseText = JSON.stringify(artifact, null, 2);
      setLicensePreview(state.currentLicenseText);
      $('licenseId').textContent = artifact.license && artifact.license.jti ? artifact.license.jti : '-';
      $('licenseExp').textContent = artifact.license ? formatDate(artifact.license.exp) : '-';
      $('licenseSubject').textContent = artifact.license && artifact.license.sub ? artifact.license.sub : '-';
      $('licenseFeatures').textContent = artifact.license && Array.isArray(artifact.license.features) ? artifact.license.features.join(', ') : '-';
      setBadge('stateBadge', '已读取', 'ok');
      setBadge('verifyBadge', '待验证', 'warn');
      log('授权文件与公钥读取成功。');
    } catch (error) {
      state.licenseJson = null;
      state.currentPublicKey = null;
      state.currentLicenseText = '';
      setLicensePreview(`读取失败：${error.message}`);
      setBadge('stateBadge', '失败', 'bad');
      log(`读取授权失败：${error.message}`, 'error');
    }
  }

  async function verifyLicense() {
    try {
      if (!state.licenseJson || !state.currentPublicKey) {
        await loadLicense();
      }
      const cfg = getConnectionConfig();
      const expected = {
        plugin: normalizeText($('pluginName').value) || 'ikguard',
        owner: normalizeText($('licenseOwner').value),
        repo: normalizeText($('licenseRepo').value),
        device: normalizeText($('deviceId').value),
      };
      const verdict = await verifyLicenseArtifact(state.licenseJson, state.currentPublicKey, expected);
      if (!verdict.ok) {
        setBadge('verifyBadge', verdict.reason, 'bad');
        log(`验签失败：${verdict.reason}`, 'error');
        return;
      }
      $('licenseId').textContent = verdict.result.license_id || '-';
      $('licenseExp').textContent = formatDate(verdict.result.expires_at);
      $('licenseSubject').textContent = verdict.result.subject || '-';
      $('licenseFeatures').textContent = Array.isArray(verdict.result.features) ? verdict.result.features.join(', ') : '-';
      setBadge('verifyBadge', 'authorized', 'ok');
      log(`验签通过：${verdict.result.subject || verdict.result.license_id || 'license'}`);
    } catch (error) {
      setBadge('verifyBadge', '失败', 'bad');
      log(`验签异常：${error.message}`, 'error');
    }
  }

  async function dispatchWorkflow() {
    try {
      const cfg = getConnectionConfig();
      const issue = getIssueConfig();
      if (!cfg.owner || !cfg.repo) throw new Error('请先填写仓库 owner/repo');
      if (!cfg.workflow) throw new Error('请先填写 workflow 文件名');
      if (!cfg.ref) throw new Error('请先填写工作流分支');
      if (!issue.subject) throw new Error('subject 不能为空');

      const payload = {
        ref: cfg.ref,
        inputs: issue,
      };

      log(`触发 workflow：${cfg.owner}/${cfg.repo} -> ${cfg.workflow} @ ${cfg.ref}`);
      await githubRequest(
        'POST',
        `/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.repo)}/actions/workflows/${encodePath(cfg.workflow)}/dispatches`,
        cfg.token,
        payload
      );
      setBadge('stateBadge', '已触发', 'ok');
      $('lastAction').textContent = 'workflow_dispatch 已提交';
      log('workflow_dispatch 已提交，请前往 Actions 查看执行结果。');

      const runs = await githubRequest(
        'GET',
        `/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.repo)}/actions/workflows/${encodePath(cfg.workflow)}/runs?event=workflow_dispatch&branch=${encodeURIComponent(cfg.ref)}&per_page=1`,
        cfg.token
      );
      const run = runs && runs.workflow_runs && runs.workflow_runs[0];
      if (run) {
        state.lastWorkflowRunUrl = run.html_url || '';
        $('openActions').href = run.html_url || $('openActions').href;
        log(`最近一次运行：${run.status || '-'} / ${run.conclusion || '-'} / ${run.html_url || ''}`);
      }
    } catch (error) {
      setBadge('stateBadge', '失败', 'bad');
      log(`触发 workflow 失败：${error.message}`, 'error');
    }
  }

  async function loadRuns() {
    try {
      const cfg = getConnectionConfig();
      const runs = await githubRequest(
        'GET',
        `/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.repo)}/actions/workflows/${encodePath(cfg.workflow)}/runs?branch=${encodeURIComponent(cfg.ref)}&per_page=5`,
        cfg.token
      );
      const list = (runs.workflow_runs || []).map((run) => {
        const created = run.created_at ? new Date(run.created_at).toLocaleString('zh-CN', { hour12: false }) : '-';
        return `${run.status || '-'} / ${run.conclusion || '-'}\n${created}\n${run.html_url || ''}`;
      });
      $('logPanel').textContent = list.length ? list.join('\n\n') : '没有找到 workflow 运行记录。';
      $('lastAction').textContent = list.length ? '已加载 workflow 记录' : '无运行记录';
      setBadge('stateBadge', '已加载', 'ok');
    } catch (error) {
      log(`读取 workflow 失败：${error.message}`, 'error');
    }
  }

  async function copyCurrentJson() {
    try {
      if (!state.currentLicenseText) {
        await loadLicense();
      }
      await navigator.clipboard.writeText(state.currentLicenseText || '');
      log('已复制当前 license JSON。');
    } catch (error) {
      log(`复制失败：${error.message}`, 'error');
    }
  }

  function bindEvents() {
    $('saveSettings').addEventListener('click', saveSettings);
    $('loadLicense').addEventListener('click', async () => {
      saveSettings();
      await loadLicense();
    });
    $('verifyLicense').addEventListener('click', async () => {
      saveSettings();
      await verifyLicense();
    });
    $('dispatchWorkflow').addEventListener('click', async () => {
      saveSettings();
      await dispatchWorkflow();
    });
    $('loadRuns').addEventListener('click', async () => {
      saveSettings();
      await loadRuns();
    });
    $('copyLicenseJson').addEventListener('click', copyCurrentJson);
    $('githubToken').addEventListener('input', () => setToken(normalizeText($('githubToken').value)));
    $('rememberToken').addEventListener('change', () => {
      localStorage.setItem(STORAGE_KEYS.rememberToken, $('rememberToken').checked ? '1' : '0');
      setToken(normalizeText($('githubToken').value));
    });
    ['repoOwner', 'repoName', 'workflowFile'].forEach((id) => {
      $(id).addEventListener('input', () => updateHeroState(Boolean($('repoOwner').value && $('repoName').value)));
    });
  }

  function boot() {
    applySettings();
    bindEvents();
    $('dispatchLicensePath').value = $('licensePath').value;
    $('lastAction').textContent = '页面已加载';
    log('页面加载完成。GitHub Pages 管理端已就绪。');
    updateHeroState(Boolean($('repoOwner').value && $('repoName').value));
    $('openActions').href = `https://github.com/${encodeURIComponent($('repoOwner').value)}/${encodeURIComponent($('repoName').value)}/actions/workflows/${encodeURIComponent($('workflowFile').value)}`;
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
