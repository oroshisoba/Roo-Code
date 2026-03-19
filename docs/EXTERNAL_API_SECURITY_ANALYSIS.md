# External API Security Analysis — Roo Code

**Purpose**: Document all external API access points in the Roo Code VSCode extension to assess the risk of information leakage.

**Scope**: HTTP/HTTPS requests made from the extension host process and related packages.

**Methodology**: Static analysis of all `fetch()`, `axios.*()`, and SDK client calls in `src/` and `packages/`.

---

## Risk Classification

| Level | Definition |
|-------|-----------|
| **Low** | Request sends no user data; only retrieves public information |
| **Medium** | Request sends non-sensitive metadata (machine ID, version, event names) |
| **High** | Request sends potentially sensitive content (conversation messages, file contents, auth credentials) |

---

## 1. LLM Provider API Calls

User code and conversation messages are sent to the LLM provider that the user explicitly configures. This is inherent to the function of the extension and is **not considered a risk** per the analysis requirements — with the exceptions noted below.

### 1.1 Standard Endpoints (Low Risk)

| Provider | Endpoint | Protocol | Notes |
|----------|----------|----------|-------|
| Roo Code Cloud Proxy | `https://api.roocode.com/proxy/v1` | OpenAI-compatible | Default cloud provider; proxies to upstream LLMs. Overridable via `ROO_CODE_PROVIDER_URL` env var. |
| OpenAI (native) | `https://api.openai.com/v1` | OpenAI | User-configurable base URL |
| Anthropic | `https://api.anthropic.com` | Anthropic SDK | Standard Anthropic API |
| Google Gemini | `https://generativelanguage.googleapis.com` | Gemini SDK | Standard Gemini API |
| Google Vertex AI | GCP regional endpoints | Vertex AI SDK | Standard Vertex API |
| AWS Bedrock | AWS regional endpoints | AWS SDK | Standard Bedrock API |
| DeepSeek | `https://api.deepseek.com` | OpenAI-compatible | Standard DeepSeek API |
| OpenRouter | `https://openrouter.ai/api/v1` | OpenAI-compatible | User-configurable base URL |
| Vercel AI Gateway | `https://ai-gateway.vercel.sh/v1` | OpenAI-compatible | Standard Vercel gateway |
| Mistral | `https://api.mistral.ai` | Mistral SDK | Standard Mistral API |
| X.AI (Grok) | `https://api.x.ai/v1` | OpenAI-compatible | Standard xAI API |
| SambaNova | `https://api.sambanova.ai/v1` | OpenAI-compatible | Standard SambaNova API |
| Fireworks | `https://api.fireworks.ai/inference/v1` | OpenAI-compatible | Standard Fireworks API |
| MiniMax | `https://api.minimax.io/anthropic` (international) / `https://api.minimaxi.com/anthropic` (China) | Anthropic-compatible | User-configurable base URL |
| Moonshot | `https://api.moonshot.ai/v1` | OpenAI-compatible | User-configurable base URL |
| Unbound | `https://api.getunbound.ai/v1` | OpenAI-compatible | Standard Unbound API |
| Requesty | `https://router.requesty.ai/v1` | OpenAI-compatible | User-configurable base URL |
| BaseTen | `https://inference.baseten.co/v1` | OpenAI-compatible | Standard BaseTen API |
| Z.AI (international) | `https://api.z.ai/api/coding/paas/v4` | OpenAI-compatible | GLM models |
| Z.AI (mainland) | `https://open.bigmodel.cn/api/coding/paas/v4` | OpenAI-compatible | GLM models (China endpoint) |
| LiteLLM | User-configured | OpenAI-compatible | Self-hosted proxy |
| LM Studio | `http://localhost:1234` | OpenAI-compatible | Local only |
| Ollama | `http://localhost:11434` | Ollama | Local only |

**Data sent**: System prompt, conversation history, tool definitions, model parameters. This is expected and user-controlled.

**Header note**: Requests to OpenRouter-compatible providers include `HTTP-Referer: https://github.com/RooVetGit/Roo-Cline` (source: `src/api/providers/constants.ts`). This identifies the referrer to the provider but is not sensitive.

### 1.2 Non-Standard / Unofficial Endpoints (⚠️ Risk Items)

#### 1.2.1 Qwen Code — OAuth via `chat.qwen.ai`

| Property | Value |
|----------|-------|
| **File** | `src/api/providers/qwen-code.ts` |
| **OAuth endpoint** | `https://chat.qwen.ai/api/v1/oauth2/token` |
| **API endpoint** | `https://dashscope.aliyuncs.com/compatible-mode/v1` (default) or `resource_url` from OAuth response |
| **Risk level** | **Medium** |

**Details**:
- Roo Code uses an OAuth 2.0 refresh token flow to authenticate with the Alibaba Qwen service.
- The OAuth client ID is hardcoded: `f0304373b74a44d2b584a3fb70ca9e56` (`QWEN_OAUTH_CLIENT_ID`). This is a public-client OAuth app credential; no client secret is used, so embedding it in source is standard practice for installed OAuth clients (similar to VS Code's own OAuth registrations).
- **Dynamic `resource_url` risk**: The `access_token` is obtained via OAuth, and the API endpoint `baseURL` is taken from `creds.resource_url` returned by the OAuth server (`getBaseUrl()` method). If the OAuth server is compromised or the credentials file is tampered with, the extension could send LLM requests (containing user code and conversation) to an arbitrary URL.
- Credentials are cached locally at `~/.qwen/oauth_creds.json` (default) or a user-configured path.

#### 1.2.2 OpenAI Codex — Unofficial ChatGPT Backend

| Property | Value |
|----------|-------|
| **Files** | `src/api/providers/openai-codex.ts`, `src/integrations/openai-codex/oauth.ts`, `src/integrations/openai-codex/rate-limits.ts` |
| **API endpoint** | `https://chatgpt.com/backend-api/codex/responses` |
| **Rate limit endpoint** | `https://chatgpt.com/backend-api/wham/usage` |
| **Auth endpoint** | `https://auth.openai.com/oauth/token` |
| **Risk level** | **Medium** |

**Details**:
- `https://chatgpt.com/backend-api/codex` is **not** the public OpenAI API (`api.openai.com`). It is an internal ChatGPT backend endpoint.
- This endpoint is undocumented and unsupported as a public API. It may change without notice, and it routes through ChatGPT's infrastructure.
- `https://chatgpt.com/backend-api/wham/usage` is similarly an unofficial internal rate-limit endpoint.
- Authentication uses the standard `https://auth.openai.com/oauth/token` (OAuth 2.0 PKCE), which is legitimate.
- The OAuth client ID `app_EMoamEEZ73f0CkXaXp7hrann` is hardcoded (public client, no secret — by design).
- Custom request headers sent: `originator: roo-code`, `session_id: <taskId>` (task ID, not sensitive content), `ChatGPT-Account-Id: <accountId>` (organization account ID).
- **Risk**: Using an unofficial internal API means requests are processed by ChatGPT's backend infrastructure under terms that may differ from the OpenAI API terms. Users should be aware this is not the standard `api.openai.com` endpoint.

---

## 2. Roo Code Cloud Services

These services are operated by Roo Code, Inc. and are used when the user is signed in to a Roo Code cloud account.

### 2.1 Authentication — Clerk (`clerk.roocode.com`)

| Property | Value |
|----------|-------|
| **File** | `packages/cloud/src/WebAuthService.ts` |
| **Base URL** | `https://clerk.roocode.com` (overridable via `CLERK_BASE_URL` env var) |
| **Risk level** | **High** (auth credentials) |

**Endpoints and data sent**:

| Endpoint | Method | Data Sent |
|----------|--------|-----------|
| `POST /v1/client/sign_ins` | Sign in | Authorization code (from OAuth callback) |
| `POST /v1/client/sessions/{id}/tokens` | Get session token | Session ID, `clerk-db-jwt` cookie |
| `GET /v1/me` | Get user info | Session token (Bearer) |
| `GET /v1/me/organization_memberships` | Get org membership | Session token (Bearer) |
| `POST /v1/client/sessions/{id}/remove` | Logout | Session token (Bearer) |

**Assessment**: Auth credentials are necessary for the cloud sign-in flow. All requests use HTTPS. The Clerk service is a well-known third-party authentication provider. Credential handling follows standard OAuth/JWT patterns with a 10-second timeout.

### 2.2 Cloud API — `app.roocode.com`

| Property | Value |
|----------|-------|
| **File** | `packages/cloud/src/CloudAPI.ts` |
| **Base URL** | `https://app.roocode.com` (overridable via `ROO_CODE_API_URL` env var) |
| **Risk level** | **Medium** |

**Endpoints and data sent**:

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `POST /api/extension/share` | Share task | `taskId`, `visibility` | Share task link |
| `GET /api/extension/bridge/config` | Get bridge config | Session token (Bearer) | WebSocket bridge URL and token |
| `GET /api/extension/credit-balance` | Check credits | Session token (Bearer) | Credit balance display |

**Assessment**: Task sharing sends only the task ID, not conversation content. The bridge config endpoint returns a WebSocket URL and token for real-time features. All requests use Bearer token auth with a 30-second timeout.

### 2.3 Cloud Settings — `app.roocode.com`

| Property | Value |
|----------|-------|
| **File** | `packages/cloud/src/CloudSettingsService.ts` |
| **Base URL** | `https://app.roocode.com` |
| **Risk level** | **Medium** |

**Endpoints and data sent**:

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `GET /api/extension-settings` | Fetch org/user settings | Session token (Bearer) | Organization and user settings |
| `PATCH /api/user-settings` | Update user settings | Session token, `settings` object, `version` | Save user preferences to cloud |

**Assessment**: Settings sync allows organization administrators to push configuration to users. User settings updates send configuration data (not code or conversations) to Roo Code servers.

---

## 3. Telemetry

### 3.1 PostHog — `ph.roocode.com` (anonymous usage analytics)

| Property | Value |
|----------|-------|
| **File** | `packages/telemetry/src/PostHogTelemetryClient.ts` |
| **Endpoint** | `https://ph.roocode.com` (self-hosted PostHog instance) |
| **Risk level** | **Low** |
| **Opt-out** | Settings → "Enable telemetry" toggle, or `ROO_CODE_DISABLE_TELEMETRY=1` env var |

**Data sent**: VS Code machine ID (anonymized), event names (e.g., `TASK_CREATED`, `TOOL_USED`), app version, error type and code (for exceptions).

**Explicitly NOT sent**:
- Git repository URLs, repository names, or default branch names (filtered in `isPropertyCapturable()`)
- Conversation messages or LLM completions (excluded by subscription filter)
- File contents or code

**Conditions for enablement**: PostHog telemetry is only enabled when **both** the VS Code global telemetry setting (`telemetry.telemetryLevel`) is set to `"all"` **and** the user has opted in via the Roo Code settings toggle.

### 3.2 Cloud Telemetry — `app.roocode.com` (event reporting)

| Property | Value |
|----------|-------|
| **File** | `packages/cloud/src/TelemetryClient.ts` |
| **Endpoint** | `https://app.roocode.com/api/events` |
| **Risk level** | **Medium** (High if task sync enabled) |
| **Requires** | Cloud account sign-in |

**Data sent to `/api/events`**: Usage events similar to PostHog, but `TASK_CONVERSATION_MESSAGE` events are excluded by default.

**Task sync (backfill) — `/api/events/backfill`**:

| Property | Value |
|----------|-------|
| **Risk level** | **High** |
| **Condition** | Only active when `settingsService.isTaskSyncEnabled()` returns true |

When task sync is enabled, full conversation messages (including any code or file content that was part of the conversation) are uploaded to `https://app.roocode.com/api/events/backfill`. This is an explicit opt-in feature.

---

## 4. Marketplace & Configuration

### 4.1 Marketplace — `app.roocode.com`

| Property | Value |
|----------|-------|
| **File** | `src/services/marketplace/RemoteConfigLoader.ts` |
| **Endpoints** | `GET https://app.roocode.com/api/marketplace/modes`, `GET https://app.roocode.com/api/marketplace/mcps` |
| **Risk level** | **Low** |

**Data sent**: No user data; only the request itself (fetching public marketplace listings). Uses 5-minute cache and exponential backoff (1s/2s/4s). Sends no authentication token — these are unauthenticated public endpoints.

**Assessment**: No leakage risk. These are read-only requests for publicly available configuration data.

### 4.2 MDM (Mobile Device Management) Configuration

| Property | Value |
|----------|-------|
| **File** | `src/services/mdm/MdmService.ts` |
| **Risk level** | **None** |

MDM uses **local file reads only** — it reads `~/.config/roo-code/mdm.json` (Linux/macOS) or `%APPDATA%\roo-code\mdm.json` (Windows). There are no external HTTP calls.

---

## 5. Model List Fetching

These requests are made to enumerate available models when a provider is configured. They send the user's API key for authentication but no user content.

| Provider | Endpoint | Data Sent |
|----------|----------|-----------|
| Roo Code Cloud | `https://api.roocode.com/proxy/v1/models` | Session token |
| OpenRouter | `https://openrouter.ai/api/v1/models` | API key (optional) |
| Unbound | `https://api.getunbound.ai/models` | API key |
| Requesty | `https://router.requesty.ai/v1/models` | API key (optional) |
| Vercel AI Gateway | `https://ai-gateway.vercel.sh/v1/models` | Auth token |
| LiteLLM | `<user-configured>/models` | API key |
| LM Studio | `http://localhost:1234/v1/models` | None |
| Ollama | `http://localhost:11434/api/tags` | None |
| OpenAI (custom) | `<user-configured>/models` | API key |

**Assessment**: Low risk. The user's API key is sent but this is required for authentication. No user content is sent.

---

## 6. OpenRouter OAuth Callback

| Property | Value |
|----------|-------|
| **File** | `src/core/webview/ClineProvider.ts` (line ~1725) |
| **Endpoint** | `POST https://openrouter.ai/api/v1/auth/keys` |
| **Risk level** | **Low** |

**Data sent**: The authorization code received from OpenRouter's OAuth redirect. This is the standard OAuth code exchange step to obtain an API key.

---

## 7. Code Index — Embedding Service

When the code index feature is enabled, code snippets from the workspace are sent to an embedding service.

| Property | Value |
|----------|-------|
| **Files** | `src/services/code-index/embedders/openai-compatible.ts`, `src/services/code-index/embedders/ollama.ts`, `src/services/code-index/embedders/vercel-ai-gateway.ts` |
| **Risk level** | **High** (if using external embedding endpoint) |

**Details**:
- The embedding endpoint is user-configured. It can be an OpenAI-compatible endpoint, Ollama (local), or Vercel AI Gateway.
- When a non-local endpoint is used, **batches of source code text** from the workspace are sent to the configured embedding service for vectorization.
- The request body contains: `input` (array of code text strings), `model`, `encoding_format: "base64"`.
- This is user-controlled and consistent with the stated purpose of the code-index feature.

---

## 8. MCP (Model Context Protocol) Servers

| Property | Value |
|----------|-------|
| **File** | `src/services/mcp/McpHub.ts` |
| **Risk level** | **Variable** (user-controlled) |

MCP servers are external processes or remote services configured by the user. The extension connects to user-configured MCP servers via stdio, SSE, or WebSocket. Any data shared with MCP servers is under user control. The extension does not connect to any hardcoded MCP endpoint.

For SSE-type MCP connections, a `fetch()` call is used to establish the EventSource connection, using headers from the user's MCP configuration (including any `Authorization` headers the user configures).

---

## Summary: Risk Assessment

### Items That Pose Information Leakage Risk

| # | Item | Risk Level | Condition |
|---|------|-----------|-----------|
| 1 | **Task sync / backfill** | **High** | Only when cloud task sync is explicitly enabled |
| 2 | **Code index with external embedding service** | **High** | Only when code indexing is configured with non-local endpoint |
| 3 | **Cloud authentication (Clerk)** | **High** | Only when signed in to Roo Code cloud account |
| 4 | **Qwen Code — dynamic `resource_url`** | **Medium** | Only when Qwen Code provider is configured |
| 5 | **OpenAI Codex — unofficial ChatGPT backend** | **Medium** | Only when OpenAI Codex provider is configured |
| 6 | **Cloud API (task share, bridge, settings)** | **Medium** | Only when signed in to Roo Code cloud account |
| 7 | **Cloud telemetry** | **Medium** | Only when signed in to Roo Code cloud account |
| 8 | **PostHog telemetry** | **Low** | When telemetry is enabled (anonymized, no code) |
| 9 | **Marketplace requests** | **Low** | Always (unauthenticated, no user data sent) |
| 10 | **Model list fetching** | **Low** | When provider is configured (only API key sent) |

### Key Observations

1. **LLM provider calls are inherently high-risk** by nature (user code and prompts are sent), but this is expected behavior that the user explicitly opts into by choosing a provider.

2. **Task sync is the primary non-LLM high-risk path**: When enabled, full conversation history (including all code snippets shared with the AI) is uploaded to Roo Code servers. This requires explicit opt-in.

3. **Cloud features require explicit sign-in**: Authentication/cloud settings/telemetry endpoints are only reached when the user creates and uses a Roo Code cloud account.

4. **Telemetry is anonymized**: PostHog telemetry does not include code, prompts, or repository identifiers. It can be disabled.

5. **Qwen Code `resource_url`**: The API endpoint for Qwen is taken from the OAuth server response (`resource_url`). While this is standard OAuth practice, it means the destination of LLM traffic is dynamic and could be redirected if credentials are compromised.

6. **OpenAI Codex uses unofficial APIs**: Requests go to `chatgpt.com/backend-api/codex` instead of the documented `api.openai.com`. Users should understand this routes through ChatGPT's internal infrastructure rather than the standard API.

7. **No unexpected beaconing or telemetry**: There are no hidden analytics calls, no silent data uploads, and no calls to third-party trackers beyond the disclosed PostHog instance (`ph.roocode.com`).
