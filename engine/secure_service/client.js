/* ROITH secure engine browser adapter. Token remains in this closure only. */
(function (global) {
  'use strict';
  let baseUrl = '';
  let bearerToken = '';

  function normalizeBase(raw) {
    const url = new URL(raw);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
      throw new Error('Remote ROITH engines must use HTTPS. HTTP is allowed only for localhost.');
    }
    url.pathname = url.pathname.replace(/\/+$/, '');
    url.search = '';
    url.hash = '';
    return url.toString().replace(/\/$/, '');
  }

  function requireConnection() {
    if (!baseUrl || !bearerToken) throw new Error('Connect to a ROITH engine first.');
  }

  async function request(path, options) {
    requireConnection();
    const response = await fetch(baseUrl + path, {
      ...options,
      headers: { ...(options && options.headers ? options.headers : {}), Authorization: 'Bearer ' + bearerToken },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error'
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || ('Engine request failed: HTTP ' + response.status));
    return body;
  }

  global.ROITHSecureEngine = Object.freeze({
    connect: async function (url, token) {
      baseUrl = normalizeBase(url);
      bearerToken = String(token || '').trim();
      if (bearerToken.length < 32) {
        baseUrl = '';
        bearerToken = '';
        throw new Error('The API token must contain at least 32 characters.');
      }
      try {
        const response = await fetch(baseUrl + '/health', { credentials: 'omit', cache: 'no-store', redirect: 'error' });
        if (!response.ok) throw new Error('Engine health check failed: HTTP ' + response.status);
        const health = await response.json();
        await request('/v2/tasks', { method: 'GET' });
        return health;
      } catch (error) {
        baseUrl = '';
        bearerToken = '';
        throw error;
      }
    },
    disconnect: function () { baseUrl = ''; bearerToken = ''; },
    tasks: function () { return request('/v2/tasks', { method: 'GET' }); },
    submit: function (task, file, rulesFile) {
      const form = new FormData();
      form.append('task', task);
      form.append('file', file, file.name || 'evidence.bin');
      if (rulesFile) form.append('rules', rulesFile, rulesFile.name || 'rules.yar');
      return request('/v2/jobs', { method: 'POST', body: form });
    },
    getJob: function (id) { return request('/v2/jobs/' + encodeURIComponent(id), { method: 'GET' }); },
    verifyAudit: function () { return request('/v2/audit/verify', { method: 'GET' }); }
  });
})(window);
