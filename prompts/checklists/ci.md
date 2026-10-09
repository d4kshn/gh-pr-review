### CI/CD (GitHub Actions)
- pull_request_target or workflow_run combined with checking out or running PR code.
- ${{ github.event.* }} values (titles, bodies, branch names) interpolated into run: scripts.
- Third-party actions not pinned to a full commit SHA; permissions: write-all or broader than needed.
- Secrets echoed, written to files or passed to untrusted steps; self-hosted runners on PR events.
