### n8n workflows
- Webhook, Chat Trigger or Form Trigger without authentication, or authentication removed; allowed origins "*".
- Literal API keys or tokens in node parameters (HTTP headers, query, body, Code nodes) instead of n8n credentials.
- SQL/database nodes building queries with {{ }} from chat or webhook input instead of query parameters.
- AI Agent tools that can write, execute code, call arbitrary URLs or query databases; prompt-injection paths from user input to those tools.
- Code nodes using child_process, $env/process.env or eval; Execute Command nodes.
- "Ignore SSL issues" on HTTP Request nodes; new external hosts receiving chat data.
- Chat memory keyed by a client-supplied sessionId; pinData with real user data committed.
