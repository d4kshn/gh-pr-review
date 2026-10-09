// secrev-github-token › Return token
const CONFIG = __CONFIG__;
const res = $input.first().json || {};
if (!res.token) throw new Error('secrev: GitHub did not return an installation token');
return [{ json: { token: res.token, expires_at: res.expires_at || null, app_slug: CONFIG.github_app_slug } }];
