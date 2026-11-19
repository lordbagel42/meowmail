# Meow Mail

Receive-only, 24-hour temporary email in Slack. Members request an address by saying `gib email` in #meow-mail and must accept the terms in Slack first. Mail threads are visible to channel members. No free-trial farming or abuse. Incoming mail is logged and audited; daily Pi + Tavily review may ban users. Automation detection is imperfect.

The owner, me@raygen.dev, operates setup, mail inspection, bans, audit history, and reviews behind backend-enforced Cloudflare Access. Secrets are supplied privately through the dashboard, encrypted in backend storage, and never returned to the browser.

## Assumptions from the explicit brief

- This is a new web frontend; Slack is the primary member experience.
- The dashboard is an operator tool, not a mailbox for composing or sending mail.
- System typography is preferred to a third-party font request; dark is the default, with a saved system/dark/light choice.
- Backend routing verifies the Access JWT and exact owner email on every admin request.

## Integration policy

Email content retention is 90 days; moderation record retention is 365 days. Slack retention is controlled by the workspace. Daily Pi reviews use `openai-codex / gpt-6.1-terra` with Tavily through the real `@earendil-works/pi-agent-core` packages. The owner's Codex subscription supplies model access and consumes subscription allowance, with no paid API fallback. OpenAI processes aggregate usage and attributed free-trial intent, not email bodies; Tavily receives observed domains. No outbound email.

The agent cannot ban from inbound sender-domain counts or search snippets alone: unsolicited mail is not proof of recipient abuse. Its autonomous ban tool requires an attributed, Slack-signed explicit free-trial address request (`gib email for a free trial on example.org`) and researched source URLs. Such requests never receive an address. Other suspicious usage is recorded as a review concern for the owner. Verified bot/app requests are banned directly, with the owner exempt; automation using ordinary human credentials is indistinguishable.

Create the Slack app without an event request URL. Install and invite it, save token/signing secret/channel with service disabled, then configure `/slack/events` and the `message.channels` bot event in Slack. Save a separate Tavily key and connect the owner's own Codex account before enabling service. Connect/Reconnect starts a fresh 10-minute legacy PKCE browser flow, showing only a validated `https://auth.openai.com/oauth/authorize` new-tab link. The owner approves in OpenAI, then pastes the full `http://localhost:1455/auth/callback` URL from the browser address bar only into the owner-protected dashboard, never this thread. The local page may fail to load; no local listener, device login, or polling is required. The callback input clears immediately upon submission and on disconnect. No callback, authorization code, or token is persisted in browser storage. State/PKCE and one-time encrypted pending state are backend enforced; tokens never return to the browser. Disconnect clears the backend grant and pauses mail. Backend first enablement queues the welcome announcement and ban-list pin; connecting alone does not activate the bot or generate an address.
