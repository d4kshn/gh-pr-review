### Python
- subprocess with shell=True, os.system, eval/exec, unsafe yaml.load, pickle on untrusted data.
- requests/urllib/ssl with verification disabled; paramiko AutoAddPolicy.
- SQL built with f-strings, % or + instead of parameters.
- Secrets in code, logs or exceptions; credentials read from the wrong place.
- Path traversal when joining user-controlled paths; tempfile.mktemp.
- New or unpinned dependencies in requirements files.
