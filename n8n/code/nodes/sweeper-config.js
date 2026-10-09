// secrev-sweeper › Config
const CONFIG = __CONFIG__;
return [{
  json: {
    config: CONFIG, installation_id: Number(CONFIG.github_installation_id),
    permissions: { pull_requests: 'read', contents: 'read', actions: 'read', metadata: 'read' },
  },
}];
