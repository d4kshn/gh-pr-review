### Chatbot frontend
- LLM or user text rendered as HTML (dangerouslySetInnerHTML, innerHTML, v-html, markdown with raw HTML) without sanitizing.
- API keys or secrets in VITE_/NEXT_PUBLIC_/REACT_APP_ variables or .env files: these ship to every browser.
- Calls straight from the browser to LLM APIs or n8n webhooks that hold credentials; n8n test webhook URLs.
- Session or user identifiers the client can choose, used to load chat history (cross-user data leaks).
- Tokens in localStorage, postMessage to "*", CORS/CSP loosened, new dependencies or install scripts.
