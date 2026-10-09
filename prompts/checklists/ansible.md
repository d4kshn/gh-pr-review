### Ansible
- Plaintext secrets in vars, group_vars, host_vars or inventory instead of Ansible Vault; secrets passed without no_log: true.
- shell/command/raw built from variables (injection) where a module would do; curl | bash.
- validate_certs: false, host_key_checking off, StrictHostKeyChecking=no.
- File and directory modes that are world-writable; become used more broadly than needed.
- SELinux, firewall or auditing disabled; services exposed on all interfaces.
- Downloads over HTTP or without checksums; unpinned roles or collections.
- SNMP v1/v2c and default communities on monitored devices.
