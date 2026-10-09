// secrev-github-token › Build JWT claims
// GitHub App JWTs must be short-lived; iat is backdated 60 s to absorb clock drift.
const CONFIG = __CONFIG__;
const input = $input.first().json || {};
const installationId = Number(input.installation_id || CONFIG.github_installation_id);
if (!installationId) throw new Error('secrev: installation_id is required to mint a GitHub token');
const now = Math.floor(Date.now() / 1000);
const appId = String(CONFIG.github_app_id);
const request = {};
if (Array.isArray(input.repositories) && input.repositories.length) request.repositories = input.repositories.map(String);
if (input.permissions && typeof input.permissions === 'object') request.permissions = input.permissions;
return [{
  json: {
    installation_id: installationId,
    claims: { iat: now - 60, exp: now + 540, iss: /^\d+$/.test(appId) ? Number(appId) : appId },
    request,
  },
}];
