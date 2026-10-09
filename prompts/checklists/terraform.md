### Terraform
- Security groups, NSGs and firewall rules: sources of 0.0.0.0/0, ::/0, "*", or broad internal ranges on management ports (22, 3389, 623, 161/162, 5432, 3306, 9200, 3000, 9090, 10050/10051).
- IAM: wildcard actions or resources, iam:PassRole, assume-role trust policies open to broad principals.
- Storage and databases: public ACLs/policies, encryption or TLS turned off, deletion protection removed, publicly_accessible.
- Secrets in .tf/.tfvars or defaults; outputs exposing secrets without sensitive = true.
- Providers with TLS verification off (vsphere allow_unverified_ssl, insecure = true).
- Module sources without a pinned ref; local-exec/remote-exec built from variables.
- Backend or state configuration changes; resources replaced or destroyed in ways that look accidental.
