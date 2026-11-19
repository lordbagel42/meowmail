# Meow Mail interface

## Direction

A restrained functional inbox, not an email marketing product. Members use Slack; the website explains the mechanism and boundaries. The owner dashboard prioritizes setup, scanable tables, explicit actions, and honest empty/error states. Operators may use the tool in either daylight or low ambient light: default to dark as requested and offer a persisted per-browser system/dark/light choice. The implementation is code-led from the explicit UI brief, with no generated imagery.

## Surfaces

- `/`: compact introduction, an explicitly instructional `gib email` command, ordered Slack steps, then usage restrictions. No fictional conversation, operational data, or send-mail action.
- `/tos.html`: readable single column with acceptance, permitted use, visibility, logging, review limitations, and owner contact.
- `/admin`: operator layout with desktop sidebar, wrapping narrow-screen navigation, actual server statistics, inbox/mailboxes/bans/audits/reviews/settings. Native dialog for plain-text message inspection.

## Tokens and components

Typography: `Geist, "Helvetica Neue", Arial, sans-serif` system fallback; no external font requests. Monospace only for the Slack command, route snippets, and mail body. Base 14px/1.6, dashboard heading 28px, section heading 16px; utility labels have a 12px rendered minimum. Landing heading is 44–58px, with tight -0.04em tracking.

Dark: background #111315, surface #17191c, subtle #1d2023, text #eceef0, muted #a1a7af, line #303439, accent #b8dec7, accent foreground #172a20, danger #ffacb3, focus #8cbcff.

Light: background #f8f9fa, surface #ffffff, subtle #f0f2f4, text #202329, muted #59616c, line #dce0e5, accent #25654f, accent foreground #ffffff, danger #a42632, focus #4679ba.

Use 1px borders, 5–7px field/table corners, and no card shadows. Controls have 42px default height; compact secondary controls are 32–36px. Tables scroll inside their region on narrow screens instead of overflowing the page. At 700px, stack landing/settings columns, make statistics two columns, and replace sidebar with a three-column wrapping nav. At 1000px, narrow dashboard gutters and sidebar.

## Interaction and safety

Theme changes are immediate and persisted without storing secrets. The command cursor is the only authored motion, stops after three cycles, and honors reduced motion. Provide visible keyboard focus, skip navigation, proper form labels, dialog focus handling via the native dialog element, status announcements, and wrapping for hostile/long content.

All API-supplied strings are rendered through textContent. Mail is inert plain text: no remote images, HTML execution, or linkification. Password fields never receive stored credentials. Blank secrets are omitted from writes. Confirmation protects ban/unban and Slack announcement actions. Failed mutations warn that the server may have received the request, rather than silently retrying. Refresh preserves unsaved configuration fields.

Codex subscription setup replaces a model API-key field. Show Connect/Reconnect, a boolean connection badge, and confirmed Disconnect (which pauses mail). Connect starts a fresh 10-minute legacy browser callback flow. Validate the returned link's exact OpenAI HTTPS origin and `/oauth/authorize` path, and its `http://localhost:1455/auth/callback` redirect, before exposing a new-tab link with no referrer/opener. Explain that localhost may fail to load and no local listener is needed. The owner copies the full URL from that tab's address bar into a labeled private password-style input in the owner-protected dashboard, never this thread. Clear the input synchronously on submit and disconnect; send it only to same-origin `codex/complete`. No device login, polling, browser persistence of callback/code, or returned access/refresh tokens. State/PKCE and one-time encrypted pending state are backend enforced. Explain use of the owner's own subscription allowance, no paid API fallback, and the separate Tavily key. Model identity is `openai-codex / gpt-6.1-terra`. Connection is not activation.

## Verification boundary

Frontend JS syntax and Biome checks pass. Browser verification covers empty and synthetic populated inboxes, inert message dialog and Escape/focus restoration, settings, mutation errors, bans and narrow-screen navigation. Public landing and terms are inspected on the deployed domain. Runtime tests verify backend JWT identity/audience enforcement and origin restrictions; live unauthenticated admin routes redirect to Access. Live signed-in owner activation and live SMTP remain unverified until private credential setup.
