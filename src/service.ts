import { DurableObject } from "cloudflare:workers";
import PostalMime from "postal-mime";
import { decryptConfig, encryptConfig } from "./auth";
import {
	type CodexCredential,
	type CodexLogin,
	callbackCode,
	completeCodexLogin,
	piCodexCredential,
	refreshCodex,
	startCodexLogin,
} from "./codex";
import {
	automationAction,
	DAY,
	escapeSlack,
	HARDCODED_BAN,
	isRequest,
	OWNER,
	siteDomain,
	TERMS,
	TOS_VERSION,
	trialRequest,
	usableMailbox,
	verifySlack,
} from "./policy";
import { runReview } from "./review";

type Config = {
	slackToken?: string;
	slackSigningSecret?: string;
	tavilyKey?: string;
	channel?: string;
	team?: string;
	botUser?: string;
	enabled?: boolean;
};
type Mailbox = {
	address: string;
	user_id: string;
	thread_ts: string;
	expires_at: number;
	created_at: number;
	revoked: number;
	route_id: string | null;
	announced: number;
};
type SlackEvent = {
	type?: string;
	subtype?: string;
	channel?: string;
	user?: string;
	bot_id?: string;
	app_id?: string;
	text?: string;
	ts?: string;
	thread_ts?: string;
	deleted_ts?: string;
};
type Interaction = {
	type: string;
	team?: { id: string } | null;
	user: { id: string; team_id?: string };
	channel?: { id: string };
	container?: { message_ts?: string };
	message?: { ts?: string };
	actions?: { action_id: string; value: string }[];
};
type Job = {
	id: string;
	kind: string;
	payload: string;
	attempts: number;
	next_at: number;
};
const ZONE = "0318dc6255b3d612a6365e34e3dc5e3b";

export class MailService extends DurableObject<Env> {
	private codexBusy = false;
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS consents (user_id TEXT PRIMARY KEY,version TEXT NOT NULL,accepted_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS requests (thread_ts TEXT PRIMARY KEY,user_id TEXT NOT NULL,deleted INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS mailboxes (address TEXT PRIMARY KEY,user_id TEXT NOT NULL,thread_ts TEXT UNIQUE NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,route_id TEXT,announced INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS emails (id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,raw TEXT NOT NULL,domain TEXT,received_at INTEGER NOT NULL,delivery_status TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS email_recipient ON emails(recipient,received_at);
      CREATE TABLE IF NOT EXISTS bans (user_id TEXT PRIMARY KEY,reason TEXT NOT NULL,source TEXT NOT NULL,created_at INTEGER NOT NULL,hardcoded INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY,kind TEXT NOT NULL,user_id TEXT,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY,status TEXT NOT NULL,summary TEXT NOT NULL,created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS trial_intents (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,domain TEXT NOT NULL,created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_at INTEGER NOT NULL,done INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
      INSERT OR IGNORE INTO bans VALUES ('${HARDCODED_BAN}','Operator-defined permanent exclusion','operator',${Date.now()},1);
    `);
		const bootstrap = env.CODEX_BOOTSTRAP;
		if (bootstrap)
			ctx.blockConcurrencyWhile(() => this.bootstrapCodex(bootstrap));
	}

	private async bootstrapCodex(raw: string) {
		try {
			if (raw.length > 30_000) throw new Error("Invalid bootstrap");
			const { id, credential } = JSON.parse(raw);
			if (
				typeof id !== "string" ||
				!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(
					id,
				)
			)
				throw new Error("Invalid import ID");
			const key = `codex_import:${id}`;
			let outcome = this.setting(key) ?? "";
			if (!outcome) {
				if (this.setting("codex")) {
					outcome = "skipped_existing";
					this.ctx.storage.transactionSync(() => {
						this.setSetting(key, outcome);
						this.setSetting(
							"codex_import_status",
							JSON.stringify({ id, outcome }),
						);
					});
				} else {
					const grant = piCodexCredential(credential);
					const config = await this.config();
					config.enabled = false;
					const encrypted = await encryptConfig(grant, this.env.CONFIG_KEY);
					const paused = await encryptConfig(config, this.env.CONFIG_KEY);
					outcome = "imported";
					this.ctx.storage.transactionSync(() => {
						this.setSetting("codex", encrypted);
						this.setSetting("config", paused);
						this.setSetting(key, outcome);
						this.setSetting(
							"codex_import_status",
							JSON.stringify({ id, outcome }),
						);
						this.ctx.storage.sql.exec(
							"DELETE FROM settings WHERE key='codex_pending'",
						);
						this.audit(
							"codex_imported",
							OWNER,
							"Pi subscription imported; mail paused; credentials omitted",
						);
					});
				}
			}
			await this.ctx.storage.sync();
			console.info(JSON.stringify({ kind: "codex_bootstrap", id, outcome }));
		} catch {
			console.error(JSON.stringify({ kind: "codex_bootstrap_failed" }));
		}
	}

	private rows<T extends Record<string, SqlStorageValue>>(
		query: string,
		...values: SqlStorageValue[]
	): T[] {
		return this.ctx.storage.sql.exec<T>(query, ...values).toArray();
	}
	private setting(key: string): string | undefined {
		return this.rows<{ value: string }>(
			"SELECT value FROM settings WHERE key=?",
			key,
		)[0]?.value;
	}
	private setSetting(key: string, value: string) {
		this.ctx.storage.sql.exec(
			"INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
			key,
			value,
		);
	}
	private async config(): Promise<Config> {
		const value = this.setting("config");
		const deployed: Config = this.env.SLACK_DEPLOYMENT
			? JSON.parse(this.env.SLACK_DEPLOYMENT)
			: {};
		return {
			tavilyKey: this.env.MEOW_MAIL_TAVILY_API_KEY,
			...deployed,
			enabled: false,
			...(value ? await decryptConfig<Config>(value, this.env.CONFIG_KEY) : {}),
		};
	}
	private async codexAccess(): Promise<string> {
		if (this.codexBusy) throw new Error("codex_authorization_busy");
		this.codexBusy = true;
		try {
			const saved = this.setting("codex");
			if (!saved) throw new Error("codex_not_connected");
			let credential = await decryptConfig<CodexCredential>(
				saved,
				this.env.CONFIG_KEY,
			);
			if (credential.expires < Date.now() + 5 * 60_000) {
				credential = await refreshCodex(credential);
				this.setSetting(
					"codex",
					await encryptConfig(credential, this.env.CONFIG_KEY),
				);
				this.audit(
					"codex_refreshed",
					OWNER,
					"Subscription authorization refreshed; credentials omitted",
				);
			}
			return credential.access;
		} finally {
			this.codexBusy = false;
		}
	}
	private async codexAdmin(
		action: string,
		data: Record<string, unknown>,
	): Promise<Response> {
		if (!["start", "complete", "disconnect"].includes(action))
			return Response.json({ error: "Not found" }, { status: 404 });
		if (this.codexBusy)
			return Response.json(
				{
					error: "Codex authorization is busy. Check connection again shortly.",
				},
				{ status: 409 },
			);
		this.codexBusy = true;
		try {
			if (action === "disconnect") {
				this.ctx.storage.sql.exec(
					"DELETE FROM settings WHERE key IN ('codex','codex_pending')",
				);
				const config = await this.config();
				config.enabled = false;
				this.setSetting(
					"config",
					await encryptConfig(config, this.env.CONFIG_KEY),
				);
				this.audit(
					"codex_disconnected",
					OWNER,
					"Stored authorization removed and mail paused",
				);
				return Response.json({ ok: true });
			}
			if (action === "start") {
				const { pending, url } = await startCodexLogin();
				this.setSetting(
					"codex_pending",
					await encryptConfig(pending, this.env.CONFIG_KEY),
				);
				this.audit(
					"codex_login_started",
					OWNER,
					"Owner initiated legacy subscription callback sign-in",
				);
				return Response.json({
					authorization_url: url,
					expires_at: pending.expiresAt,
				});
			}
			const raw = this.setting("codex_pending");
			const pending = raw
				? await decryptConfig<CodexLogin>(raw, this.env.CONFIG_KEY)
				: undefined;
			if (!pending || pending.expiresAt <= Date.now()) {
				this.ctx.storage.sql.exec(
					"DELETE FROM settings WHERE key='codex_pending'",
				);
				return Response.json(
					{ error: "Codex sign-in expired. Start a new connection." },
					{ status: 400 },
				);
			}
			let code: string;
			try {
				code = await callbackCode(data.callback_url, pending);
			} catch {
				return Response.json(
					{
						error:
							"Invalid callback URL or state. Paste the full callback from this login, or reconnect.",
					},
					{ status: 400 },
				);
			}
			// Consume before exchanging: a lost remote response must not replay a one-use code.
			this.ctx.storage.sql.exec(
				"DELETE FROM settings WHERE key='codex_pending'",
			);
			const credential = await completeCodexLogin(code, pending);
			this.setSetting(
				"codex",
				await encryptConfig(credential, this.env.CONFIG_KEY),
			);
			this.audit(
				"codex_connected",
				OWNER,
				"Codex subscription connected; credentials omitted",
			);
			return Response.json({ status: "connected" });
		} catch {
			this.audit(
				"codex_auth_failed",
				OWNER,
				"Subscription authorization failed; provider response omitted",
			);
			return Response.json(
				{
					error:
						"Codex authorization failed. Start a new legacy callback connection. No paid API fallback was used.",
				},
				{ status: 502 },
			);
		} finally {
			this.codexBusy = false;
		}
	}
	private audit(kind: string, user: string | null, detail: string) {
		this.ctx.storage.sql.exec(
			"INSERT INTO audits VALUES (?,?,?,?,?)",
			crypto.randomUUID(),
			kind,
			user,
			detail,
			Date.now(),
		);
	}
	private banned(user: string) {
		return (
			user === HARDCODED_BAN ||
			this.rows("SELECT 1 FROM bans WHERE user_id=?", user).length > 0
		);
	}
	private async wake(delay = 100) {
		const next = Date.now() + delay;
		const current = await this.ctx.storage.getAlarm();
		if (current === null || current > next)
			await this.ctx.storage.setAlarm(next);
	}
	private async enqueue(
		kind: string,
		payload: object,
		id = crypto.randomUUID(),
	) {
		this.ctx.storage.sql.exec(
			"INSERT OR IGNORE INTO jobs (id,kind,payload,next_at,created_at) VALUES (?,?,?,?,?)",
			id,
			kind,
			JSON.stringify(payload),
			Date.now(),
			Date.now(),
		);
		await this.wake();
	}

	private async slack(
		method: string,
		payload: object,
		config: Config,
		id?: string,
	): Promise<Record<string, unknown>> {
		if (!config.slackToken) throw new Error("slack_not_configured");
		const read = method === "conversations.info" || method === "users.info";
		const url = new URL(`https://slack.com/api/${method}`);
		if (read)
			for (const [key, value] of Object.entries(payload))
				url.searchParams.set(key, String(value));
		const response = await fetch(url, {
			method: read ? "GET" : "POST",
			headers: {
				Authorization: `Bearer ${config.slackToken}`,
				...(!read ? { "Content-Type": "application/json" } : {}),
			},
			body: read
				? undefined
				: JSON.stringify({
						...payload,
						...(method === "chat.postMessage" && id
							? { client_msg_id: id }
							: {}),
					}),
			signal: AbortSignal.timeout(12000),
		});
		if (!response.ok) throw new Error(`slack_http_${response.status}`);
		const result = await response.json<Record<string, unknown>>();
		if (!result.ok)
			throw new Error(`slack_${String(result.error).replace(/[^a-z_]/g, "")}`);
		return result;
	}

	private async post(text: string, thread?: string, blocks?: object[]) {
		await this.enqueue("post", { text, thread, blocks });
	}

	async slackIngress(
		path: string,
		body: string,
		timestamp: string,
		signature: string,
	): Promise<Response> {
		const config = await this.config();
		if (!config.slackSigningSecret)
			return new Response(
				"Configure the Slack signing secret in the owner dashboard first.",
				{ status: 503 },
			);
		if (
			!(await verifySlack(
				body,
				timestamp,
				signature,
				config.slackSigningSecret,
			))
		)
			return new Response("Invalid signature", { status: 401 });
		if (path === "/slack/interactions") {
			const payload = new URLSearchParams(body).get("payload");
			if (!payload) return new Response("Invalid payload", { status: 400 });
			const interaction = JSON.parse(payload) as Interaction;
			if (interaction.channel?.id !== config.channel)
				return new Response("Wrong channel", { status: 403 });
			const digest = Array.from(
				new Uint8Array(
					await crypto.subtle.digest(
						"SHA-256",
						new TextEncoder().encode(payload),
					),
				),
				(v) => v.toString(16).padStart(2, "0"),
			).join("");
			await this.enqueue("interaction", interaction, digest);
			return new Response("");
		}
		const payload = JSON.parse(body) as {
			type: string;
			challenge?: string;
			team_id?: string;
			event_id?: string;
			event?: SlackEvent;
		};
		console.info(
			JSON.stringify({
				kind: "slack_ingress",
				challenge: payload.type === "url_verification",
				callback: payload.type === "event_callback",
				workspaceMatches: payload.team_id === config.team,
				channelMatches: payload.event?.channel === config.channel,
				mailEnabled: !!config.enabled,
			}),
		);
		if (payload.type === "url_verification")
			return Response.json({ challenge: payload.challenge });
		if (
			payload.type !== "event_callback" ||
			payload.team_id !== config.team ||
			!payload.event_id ||
			payload.event?.channel !== config.channel
		)
			return new Response("Ignored");
		const event = payload.event;
		if (
			event?.type !== "message" ||
			(event.subtype !== "message_deleted" &&
				!isRequest(event.text) &&
				!trialRequest(event.text))
		)
			return new Response("Ignored");
		if (event.subtype === "message_deleted" && event.deleted_ts) {
			this.ctx.storage.sql.exec(
				"INSERT INTO requests VALUES (?,'',1,?) ON CONFLICT(thread_ts) DO UPDATE SET deleted=1",
				event.deleted_ts,
				Date.now(),
			);
			this.ctx.storage.sql.exec(
				"UPDATE mailboxes SET revoked=1 WHERE thread_ts=?",
				event.deleted_ts,
			);
		}
		const actor = event.user ?? (event.bot_id ? `bot:${event.bot_id}` : "");
		if (
			actor &&
			actor !== config.botUser &&
			(isRequest(event.text) || trialRequest(event.text)) &&
			automationAction(
				actor,
				!!event.bot_id || !!event.app_id || event.subtype === "bot_message",
			) === "ban"
		) {
			await this.ban(actor, "Verified automated address request", "automation");
			return new Response("OK");
		}
		if (
			this.rows<{ n: number }>("SELECT count(*) n FROM jobs WHERE done=0")[0]
				.n > 500
		)
			return new Response("Queue full", { status: 503 });
		await this.enqueue("event", event, payload.event_id);
		return new Response("OK");
	}

	private async event(event: SlackEvent, config: Config) {
		if (event.subtype === "message_deleted" && event.deleted_ts) {
			this.ctx.storage.sql.exec(
				"UPDATE requests SET deleted=1 WHERE thread_ts=?",
				event.deleted_ts,
			);
			this.ctx.storage.sql.exec(
				"UPDATE mailboxes SET revoked=1 WHERE thread_ts=?",
				event.deleted_ts,
			);
			this.audit(
				"request_deleted",
				null,
				`Request ${event.deleted_ts}: delivery revoked`,
			);
			return;
		}
		const user = event.user ?? (event.bot_id ? `bot:${event.bot_id}` : "");
		if (
			!user ||
			user === config.botUser ||
			!event.ts ||
			(!isRequest(event.text) && !trialRequest(event.text)) ||
			(event.thread_ts && event.thread_ts !== event.ts)
		)
			return;
		let automated =
			!!event.bot_id || !!event.app_id || event.subtype === "bot_message";
		if (!automated && user !== OWNER) {
			const info = await this.slack("users.info", { user }, config);
			automated = !!(info.user as { is_bot?: boolean })?.is_bot;
		}
		if (automationAction(user, automated) === "ban") {
			await this.ban(user, "Verified automated address request", "automation");
			return;
		}
		if (this.banned(user)) {
			await this.post(
				"*You’re banned from Meow Mail*\nTo appeal, contact <mailto:me@raygen.dev|me@raygen.dev>.",
				event.ts,
			);
			return;
		}
		if (!config.enabled) {
			await this.post(
				"*Meow Mail is paused*\nThe operator needs to finish setup before addresses can be created.",
				event.ts,
			);
			return;
		}
		const intent = trialRequest(event.text);
		if (intent) {
			this.ctx.storage.sql.exec(
				"INSERT OR IGNORE INTO trial_intents VALUES (?,?,?,?)",
				event.ts,
				user,
				intent,
				Date.now(),
			);
			await this.post(
				"*Free-trial requests aren’t allowed*\nNo address was created. This request has been recorded for abuse review.",
				event.ts,
			);
			this.audit(
				"trial_intent",
				user,
				`Explicit free-trial request ${event.ts} for ${intent}`,
			);
			return;
		}
		const existing = this.rows<{ user_id: string; deleted: number }>(
			"SELECT user_id,deleted FROM requests WHERE thread_ts=?",
			event.ts,
		)[0];
		if (existing && (existing.deleted || existing.user_id !== user)) return;
		if (!existing) {
			if (
				this.rows<{ n: number }>(
					"SELECT count(*) n FROM requests WHERE user_id=? AND created_at>?",
					user,
					Date.now() - DAY,
				)[0].n >= 10
			) {
				await this.post(
					"*Request limit reached*\nTry again in 24 hours.",
					event.ts,
				);
				return;
			}
			this.ctx.storage.sql.exec(
				"INSERT INTO requests VALUES (?,?,0,?)",
				event.ts,
				user,
				Date.now(),
			);
		}
		const consent = this.rows<{ version: string }>(
			"SELECT version FROM consents WHERE user_id=?",
			user,
		)[0];
		if (consent?.version !== TOS_VERSION) {
			await this.post(
				`*Before you get an address*\nAccept the <${this.env.ORIGIN}/tos|Terms of Service> to continue.`,
				event.ts,
				[
					{
						type: "section",
						text: {
							type: "mrkdwn",
							text: `*Before you get an address*\n\n${escapeSlack(TERMS)}\n\n<${this.env.ORIGIN}/tos|Read the full Terms of Service>`,
						},
					},
					{
						type: "actions",
						elements: [
							{
								type: "button",
								action_id: "accept_terms",
								text: {
									type: "plain_text",
									text: "I accept the Terms of Service",
								},
								value: `${TOS_VERSION}:${event.ts}`,
								style: "primary",
							},
						],
					},
				],
			);
			return;
		}
		await this.issue(user, event.ts, config);
	}

	private async interaction(payload: Interaction, config: Config) {
		const action = payload.actions?.[0];
		if (
			payload.type !== "block_actions" ||
			action?.action_id !== "accept_terms"
		)
			return;
		const [version, ts] = action.value.split(":");
		if (version !== TOS_VERSION || !ts) return;
		if (payload.channel?.id !== config.channel) return;
		// Enterprise interactions can identify the installation workspace in team.
		// Resolve the channel workspace after acknowledging Slack, before consent.
		const info = await this.slack(
			"conversations.info",
			{ channel: config.channel },
			config,
		);
		const channel = info.channel as { context_team_id?: string };
		const workspace =
			channel.context_team_id ??
			(await this.slack("auth.test", {}, config)).team_id;
		const current = await this.config();
		if (
			current.channel !== config.channel ||
			current.team !== config.team ||
			current.slackToken !== config.slackToken ||
			current.slackSigningSecret !== config.slackSigningSecret
		)
			return;
		config = current;
		if (!config.team?.startsWith("T") || workspace !== config.team) {
			this.audit(
				"interaction_rejected",
				payload.user.id,
				"channel_workspace_mismatch",
			);
			return;
		}
		const request = this.rows<{
			user_id: string;
			deleted: number;
			created_at: number;
		}>("SELECT * FROM requests WHERE thread_ts=?", ts)[0];
		if (
			!request ||
			payload.channel?.id !== config.channel ||
			request.user_id !== payload.user.id ||
			request.deleted ||
			request.created_at < Date.now() - DAY ||
			this.banned(payload.user.id)
		)
			return;
		this.ctx.storage.sql.exec(
			"INSERT INTO consents VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,accepted_at=excluded.accepted_at",
			payload.user.id,
			TOS_VERSION,
			Date.now(),
		);
		this.audit("terms_accepted", payload.user.id, TOS_VERSION);
		const messageTs = payload.container?.message_ts ?? payload.message?.ts;
		if (messageTs)
			await this.enqueue(
				"update",
				{
					channel: config.channel,
					ts: messageTs,
					text: `*Terms accepted*\n<@${payload.user.id}>, your acceptance has been recorded.`,
					blocks: [],
				},
				`terms-accepted:${messageTs}`,
			);
		if (config.enabled) await this.issue(payload.user.id, ts, config);
	}

	private async routing<T>(
		path: string,
		method = "GET",
		body?: object,
	): Promise<T> {
		const response = await fetch(
			`https://api.cloudflare.com/client/v4/zones/${ZONE}/email/routing/rules${path}`,
			{
				method,
				headers: {
					Authorization: `Bearer ${this.env.CF_ROUTING_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: body ? JSON.stringify(body) : undefined,
				signal: AbortSignal.timeout(12000),
			},
		);
		const result = await response.json<{ success: boolean; result: T }>();
		if (!response.ok || !result.success)
			throw new Error("email_routing_failed");
		return result.result;
	}

	private async routingRules() {
		const all: { id: string; name: string }[] = [];
		for (let page = 1; page <= 20; page++) {
			const rules = await this.routing<{ id: string; name: string }[]>(
				`?per_page=50&page=${page}`,
			);
			all.push(...rules);
			if (rules.length < 50) return all;
		}
		throw new Error("routing_pagination_limit");
	}

	private async issue(user: string, ts: string, config: Config) {
		if (this.banned(user) || !config.enabled) return;
		const request = this.rows<{ deleted: number }>(
			"SELECT deleted FROM requests WHERE thread_ts=?",
			ts,
		)[0];
		if (!request || request.deleted) return;
		let box = this.rows<Mailbox>(
			"SELECT * FROM mailboxes WHERE thread_ts=?",
			ts,
		)[0];
		if (box?.announced || box?.revoked || (box && box.expires_at <= Date.now()))
			return;
		if (!box) {
			const active = this.rows<Mailbox>(
				"SELECT * FROM mailboxes WHERE user_id=? AND revoked=0 AND expires_at>?",
				user,
				Date.now(),
			)[0];
			if (active) {
				await this.post(
					`*You already have an active address*\n\`${active.address}\`\n\nUse its original thread, or delete that request to stop delivery.`,
					ts,
				);
				return;
			}
			if (
				this.rows<{ n: number }>(
					"SELECT count(*) n FROM mailboxes WHERE user_id=? AND created_at>?",
					user,
					Date.now() - DAY,
				)[0].n >= 3
			) {
				await this.post(
					"*Address limit reached*\nYou can create up to *3 addresses per 24 hours*.",
					ts,
				);
				return;
			}
			if (
				this.rows<{ n: number }>(
					"SELECT count(*) n FROM mailboxes WHERE route_id IS NOT NULL OR (revoked=0 AND expires_at>?)",
					Date.now(),
				)[0].n >= 50
			) {
				await this.post(
					"*Meow Mail is full*\nTry again after existing addresses expire.",
					ts,
				);
				return;
			}
			const address = `${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}@${this.env.MAIL_DOMAIN}`;
			this.ctx.storage.sql.exec(
				"INSERT INTO mailboxes (address,user_id,thread_ts,expires_at,created_at) VALUES (?,?,?,?,?)",
				address,
				user,
				ts,
				Date.now() + DAY,
				Date.now(),
			);
			box = this.rows<Mailbox>(
				"SELECT * FROM mailboxes WHERE address=?",
				address,
			)[0];
		}
		if (!box.route_id) {
			const rules = await this.routingRules();
			let rule = rules.find((r) => r.name === `meow-mail:${box.address}`);
			if (!rule)
				rule = await this.routing<{ id: string; name: string }>("", "POST", {
					name: `meow-mail:${box.address}`,
					enabled: true,
					matchers: [{ type: "literal", field: "to", value: box.address }],
					actions: [{ type: "worker", value: ["meow-mail"] }],
				});
			this.ctx.storage.sql.exec(
				"UPDATE mailboxes SET route_id=? WHERE address=?",
				rule.id,
				box.address,
			);
		}
		// Consent, deletion and bans may have changed while routing was being provisioned.
		if (
			this.banned(user) ||
			!(await this.config()).enabled ||
			this.rows<{ deleted: number }>(
				"SELECT deleted FROM requests WHERE thread_ts=?",
				ts,
			)[0]?.deleted
		) {
			this.ctx.storage.sql.exec(
				"UPDATE mailboxes SET revoked=1 WHERE address=?",
				box.address,
			);
			return;
		}
		await this.post(
			`*Your temporary address*\n\`${box.address}\`\n\n• *Expires:* <!date^${Math.floor(box.expires_at / 1000)}^{date_short_pretty} at {time}|${new Date(box.expires_at).toISOString()}>\n• *Inbox:* incoming email appears in this thread.\n• *Stop delivery:* delete your original \`gib email\` message.\n\n_All mail is logged and audited. No free trials._`,
			ts,
		);
		this.ctx.storage.sql.exec(
			"UPDATE mailboxes SET announced=1 WHERE address=?",
			box.address,
		);
		this.audit("address_created", user, box.address);
	}

	async receive(
		sender: string,
		recipient: string,
		raw: string,
	): Promise<string | null> {
		const box = this.rows<Mailbox>(
			"SELECT * FROM mailboxes WHERE address=?",
			recipient.toLowerCase(),
		)[0];
		if (
			!usableMailbox(box, box ? this.banned(box.user_id) : false) ||
			!box.route_id
		)
			return "This address is unavailable or expired.";
		const config = await this.config();
		if (!config.enabled) return "Meow Mail is paused.";
		if (
			this.rows<{ n: number }>(
				"SELECT count(*) n FROM emails WHERE recipient=? AND received_at>?",
				recipient,
				Date.now() - DAY,
			)[0].n >= 50
		) {
			this.audit("mail_rate_limited", box.user_id, recipient);
			return "Mailbox daily message limit reached.";
		}
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(`${recipient}\n${raw}`),
		);
		const id = Array.from(new Uint8Array(digest), (v) =>
			v.toString(16).padStart(2, "0"),
		).join("");
		if (this.rows("SELECT 1 FROM emails WHERE id=?", id).length) return null;
		const parsed = await PostalMime.parse(raw, {
			attachmentEncoding: "base64",
		});
		const subject = (parsed.subject ?? "(no subject)").slice(0, 1000);
		const body = (
			parsed.text ??
			parsed.html?.replace(/<[^>]*>/g, " ") ??
			"(no text body)"
		).slice(0, 64000);
		this.ctx.storage.sql.exec(
			"INSERT OR IGNORE INTO emails VALUES (?,?,?,?,?,?,?,?,?)",
			id,
			sender,
			recipient,
			subject,
			body,
			raw,
			siteDomain(sender),
			Date.now(),
			"queued",
		);
		this.audit(
			"email_received",
			box.user_id,
			`Email ${id} stored for ${recipient}`,
		);
		await this.enqueue("deliver", { id }, id);
		return null;
	}

	async ban(user: string, reason: string, source: string) {
		if (this.banned(user)) return;
		this.ctx.storage.sql.exec(
			"INSERT INTO bans VALUES (?,?,?,?,0)",
			user,
			reason.slice(0, 4000),
			source,
			Date.now(),
		);
		this.ctx.storage.sql.exec(
			"UPDATE mailboxes SET revoked=1 WHERE user_id=?",
			user,
		);
		this.audit("user_banned", user, `${source}: ${reason}`);
		const mention = /^U[A-Z0-9]+$/.test(user)
			? `<@${user}>`
			: escapeSlack(user);
		await this.post(
			`*Meow Mail ban*\n${mention} · ${source === "pi" ? "Automated abuse review" : source === "automation" ? "Verified automated request" : "Operator decision"}\n\nActive addresses have been revoked. Evidence is kept in the owner audit log.\n*Appeals:* <mailto:me@raygen.dev|me@raygen.dev>`,
		);
		await this.enqueue("pin", {});
	}

	async admin(path: string, method: string, body: string): Promise<Response> {
		if (method === "GET" && path === "state") {
			const config = await this.config();
			return Response.json({
				config: {
					slack: !!config.slackToken,
					tavily: !!config.tavilyKey,
					codex: !!this.setting("codex"),
					codexImport: JSON.parse(
						this.setting("codex_import_status") ?? "null",
					),
					channel: config.channel ?? null,
					enabled: !!config.enabled,
				},
				mailboxes: this.rows(
					"SELECT * FROM mailboxes ORDER BY created_at DESC LIMIT 100",
				),
				emails: this.rows(
					"SELECT id,sender,recipient,subject,received_at,delivery_status FROM emails ORDER BY received_at DESC LIMIT 100",
				),
				bans: this.rows("SELECT * FROM bans ORDER BY created_at DESC"),
				audits: this.rows(
					"SELECT * FROM audits ORDER BY created_at DESC LIMIT 100",
				),
				reviews: this.rows(
					"SELECT * FROM reviews ORDER BY created_at DESC LIMIT 30",
				),
				stats: {
					active: this.rows<{ n: number }>(
						"SELECT count(*) n FROM mailboxes WHERE revoked=0 AND expires_at>?",
						Date.now(),
					)[0].n,
					emails: this.rows<{ n: number }>("SELECT count(*) n FROM emails")[0]
						.n,
					bans: this.rows<{ n: number }>("SELECT count(*) n FROM bans")[0].n,
				},
			});
		}
		if (method === "GET" && path === "email")
			return Response.json(
				this.rows(
					"SELECT sender,recipient,subject,body,received_at FROM emails WHERE id=?",
					body,
				)[0] ?? { error: "Email not found" },
			);
		if (method !== "POST" || body.length > 16000)
			return Response.json({ error: "Not found" }, { status: 404 });
		const data = JSON.parse(body) as Record<string, unknown>;
		if (path.startsWith("codex/")) return this.codexAdmin(path.slice(6), data);
		if (path === "config") {
			if (this.codexBusy)
				return Response.json(
					{ error: "Settings or Codex authorization is busy. Retry shortly." },
					{ status: 409 },
				);
			this.codexBusy = true;
			let stage = "load";
			let saved = false;
			try {
				const config = await this.config();
				const wasEnabled = !!config.enabled;
				for (const key of [
					"slackToken",
					"slackSigningSecret",
					"tavilyKey",
					"channel",
				] as const)
					if (typeof data[key] === "string" && data[key])
						config[key] = data[key].trim();
				if (typeof data.enabled === "boolean") config.enabled = data.enabled;
				if (config.channel && !/^C[A-Z0-9]+$/.test(config.channel))
					return Response.json(
						{ error: "Enter the channel ID for #meow-mail (starts with C)." },
						{ status: 400 },
					);
				if (config.slackToken) {
					stage = "slack_auth";
					const auth = await this.slack("auth.test", {}, config);
					config.team = String(auth.team_id);
					config.botUser = String(auth.user_id);
					if (config.channel) {
						stage = "slack_channel";
						const info = await this.slack(
							"conversations.info",
							{ channel: config.channel },
							config,
						);
						const channel = info.channel as {
							name: string;
							context_team_id?: string;
							is_archived: boolean;
							is_member: boolean;
						};
						if (
							channel.name !== "meow-mail" ||
							channel.is_archived ||
							!channel.is_member
						)
							return Response.json(
								{
									error:
										"Invite this bot to an active #meow-mail channel first.",
								},
								{ status: 400 },
							);
						config.team = channel.context_team_id ?? config.team;
						if (!config.team?.startsWith("T"))
							return Response.json(
								{ error: "Slack did not identify the channel workspace." },
								{ status: 400 },
							);
					}
				}
				if (
					config.enabled &&
					(!config.slackToken ||
						!config.slackSigningSecret ||
						!config.channel ||
						!config.tavilyKey ||
						!this.setting("codex") ||
						!this.env.CF_ROUTING_TOKEN)
				)
					return Response.json(
						{
							error:
								"Configure Slack, channel, Tavily and your Codex subscription before enabling mail.",
						},
						{ status: 400 },
					);
				stage = "persist";
				this.setSetting(
					"config",
					await encryptConfig(config, this.env.CONFIG_KEY),
				);
				saved = true;
				this.audit(
					"config_updated",
					OWNER,
					"Settings changed; secret values omitted",
				);
				stage = "schedule";
				if (config.enabled && !wasEnabled) {
					await this.post(
						`*Meow Mail is enabled*\nPost \`gib email\` for a *24-hour, receive-only address*, then accept the <${this.env.ORIGIN}/tos|Terms of Service>.\n\n• No free trials or abuse.\n• All mail is logged and audited.\n• Pi + Tavily reviews run every 24 hours and may ban users independently.\n• Verified automated requests cause an immediate ban, except for the operator.\n\nBan records are pinned. *Appeals:* <mailto:me@raygen.dev|me@raygen.dev>`,
					);
					await this.enqueue("pin", {});
				}
				await this.wake();
			} catch (error) {
				const code =
					error instanceof Error &&
					/^slack_[a-z_0-9]{1,64}$/.test(error.message)
						? error.message
						: error instanceof Error && error.name === "TimeoutError"
							? "timeout"
							: "request_failed";
				console.error(
					JSON.stringify({ kind: "config_failed", stage, code, saved }),
				);
				return Response.json(
					{
						error: saved
							? `Settings were saved, but follow-up work failed at ${stage} (${code}). Check current state before retrying.`
							: `Settings could not be saved at ${stage} (${code}). No credentials were logged.`,
						saved,
					},
					{ status: 502 },
				);
			} finally {
				this.codexBusy = false;
			}
		} else if (path === "ban") {
			if (
				typeof data.user_id !== "string" ||
				!/^U[A-Z0-9]{8,}$/.test(data.user_id) ||
				typeof data.reason !== "string" ||
				!data.reason.trim()
			)
				return Response.json(
					{ error: "A Slack user ID and reason are required." },
					{ status: 400 },
				);
			await this.ban(data.user_id, data.reason, "operator");
		} else if (path === "unban") {
			if (typeof data.user_id !== "string" || data.user_id === HARDCODED_BAN)
				return Response.json(
					{ error: "The hardcoded exclusion cannot be removed." },
					{ status: 400 },
				);
			this.ctx.storage.sql.exec(
				"DELETE FROM bans WHERE user_id=?",
				data.user_id,
			);
			this.audit(
				"user_unbanned",
				data.user_id,
				"Operator appeal decision; old addresses remain revoked",
			);
			await this.enqueue("pin", {});
		} else if (path === "review") {
			await this.scheduleReview();
		} else if (path === "announce") {
			await this.post(
				`*Meow Mail*\nPost \`gib email\` to request a *24-hour, receive-only address*. Accept the <${this.env.ORIGIN}/tos|Terms of Service> before using it.\n\n• *No free trials or abuse.*\n• Incoming mail is posted in its request thread, logged, and audited.\n• Pi researches usage with Tavily every 24 hours and can ban users independently.\n• Bans revoke all active addresses; service bans are pinned.\n• Verified automated requests cause an immediate ban, except for the operator. Tools using human credentials aren’t reliably detectable.\n\n*Appeals:* <mailto:me@raygen.dev|me@raygen.dev>`,
			);
			await this.enqueue("pin", {});
		} else return Response.json({ error: "Not found" }, { status: 404 });
		return Response.json({ ok: true });
	}

	async scheduleReview() {
		const day = new Date().toISOString().slice(0, 10);
		await this.enqueue("review", {}, `review:${day}`);
	}

	private async pin(config: Config) {
		const bans = this.rows<{ user_id: string }>(
			"SELECT user_id FROM bans ORDER BY created_at",
		);
		const names = bans.map((b) =>
			/^U[A-Z0-9]+$/.test(b.user_id)
				? `<@${b.user_id}>`
				: escapeSlack(b.user_id),
		);
		const text = `*Banned from Meow Mail*\n${names.join(", ") || "No bans."}\n\n<mailto:me@raygen.dev|Appeals> · <${this.env.ORIGIN}/tos|Terms>`;
		const ts = this.setting("pin_ts");
		if (ts)
			await this.slack(
				"chat.update",
				{ channel: config.channel, ts, text },
				config,
			);
		else {
			const result = await this.slack(
				"chat.postMessage",
				{
					channel: config.channel,
					text,
					unfurl_links: false,
					unfurl_media: false,
				},
				config,
			);
			this.setSetting("pin_ts", String(result.ts));
		}
		try {
			await this.slack(
				"pins.add",
				{ channel: config.channel, timestamp: this.setting("pin_ts") },
				config,
			);
		} catch (error) {
			if (!(error instanceof Error && error.message === "slack_already_pinned"))
				throw error;
		}
	}

	async alarm(): Promise<void> {
		await this.ctx.storage.setAlarm(Date.now() + 60_000);
		const config = await this.config();
		for (const job of this.rows<Job>(
			"SELECT * FROM jobs WHERE done=0 AND next_at<=? ORDER BY created_at LIMIT 10",
			Date.now(),
		)) {
			try {
				const payload = JSON.parse(job.payload);
				if (job.kind === "event") await this.event(payload, config);
				else if (job.kind === "interaction")
					await this.interaction(payload, config);
				else if (job.kind === "update") {
					if (payload.channel === config.channel)
						await this.slack("chat.update", payload, config);
				} else if (job.kind === "post")
					await this.slack(
						"chat.postMessage",
						{
							channel: config.channel,
							text: payload.text,
							thread_ts: payload.thread,
							blocks: payload.blocks,
							unfurl_links: false,
							unfurl_media: false,
						},
						config,
						job.id,
					);
				else if (job.kind === "pin") await this.pin(config);
				else if (job.kind === "deliver") {
					const email = this.rows<{
						id: string;
						recipient: string;
						sender: string;
						subject: string;
						body: string;
					}>("SELECT * FROM emails WHERE id=?", payload.id)[0];
					const box = email
						? this.rows<Mailbox>(
								"SELECT * FROM mailboxes WHERE address=?",
								email.recipient,
							)[0]
						: undefined;
					if (
						email &&
						box &&
						config.enabled &&
						usableMailbox(box, this.banned(box.user_id))
					) {
						await this.slack(
							"chat.postMessage",
							{
								channel: config.channel,
								thread_ts: box.thread_ts,
								text: "Incoming email · Logged and audited",
								blocks: [
									{
										type: "section",
										text: { type: "mrkdwn", text: "*Incoming email*" },
									},
									{
										type: "section",
										text: {
											type: "plain_text",
											text: `From: ${email.sender}\nTo: ${email.recipient}\nSubject: ${email.subject}`.slice(
												0,
												2900,
											),
											emoji: false,
										},
									},
									{ type: "divider" },
									{
										type: "section",
										text: {
											type: "plain_text",
											text: email.body.slice(0, 2800) || "(empty message)",
											emoji: false,
										},
									},
									{
										type: "context",
										elements: [
											{
												type: "mrkdwn",
												text: "*Logged and audited* · Attachments omitted · Long messages truncated\nNo free trials.",
											},
										],
									},
								],
								unfurl_links: false,
								unfurl_media: false,
							},
							config,
							job.id,
						);
						this.ctx.storage.sql.exec(
							"UPDATE emails SET delivery_status='delivered' WHERE id=?",
							email.id,
						);
					} else
						this.ctx.storage.sql.exec(
							"UPDATE emails SET delivery_status='withheld' WHERE id=?",
							payload.id,
						);
				} else if (job.kind === "review") {
					await this.review(config, job.id);
				}
				this.ctx.storage.sql.exec(
					"UPDATE jobs SET done=1,payload='{}' WHERE id=?",
					job.id,
				);
			} catch {
				const failed = job.attempts >= 4;
				this.ctx.storage.sql.exec(
					"UPDATE jobs SET attempts=attempts+1,next_at=?,done=? WHERE id=?",
					Date.now() + Math.min(3600000, 60000 * 2 ** job.attempts),
					failed ? 2 : 0,
					job.id,
				);
				this.audit(
					failed ? "job_failed" : "job_retry",
					null,
					`${job.kind} ${job.id}; no secret or email content in error logs`,
				);
			}
		}
		// Reconcile by stable identity even when POST/DELETE succeeded but its response was lost.
		// This is independent of finite event retries and whether issuance is still allowed.
		if (this.env.CF_ROUTING_TOKEN)
			try {
				const rules = await this.routingRules();
				const ids = new Set(rules.map((rule) => rule.id));
				for (const box of this.rows<Mailbox>(
					"SELECT * FROM mailboxes WHERE route_id IS NOT NULL",
				)) {
					if (box.route_id && !ids.has(box.route_id))
						this.ctx.storage.sql.exec(
							"UPDATE mailboxes SET route_id=NULL,revoked=1 WHERE address=?",
							box.address,
						);
				}
				let deleted = 0;
				for (const rule of rules) {
					if (!rule.name.startsWith("meow-mail:")) continue;
					const address = rule.name.slice(10);
					if (
						!/^[a-f0-9]{16}$/.test(address.split("@")[0]) ||
						!address.endsWith(`@${this.env.MAIL_DOMAIN}`)
					)
						continue;
					const box = this.rows<Mailbox>(
						"SELECT * FROM mailboxes WHERE address=?",
						address,
					)[0];
					if (box && usableMailbox(box, this.banned(box.user_id))) {
						this.ctx.storage.sql.exec(
							"UPDATE mailboxes SET route_id=? WHERE address=?",
							rule.id,
							address,
						);
					} else if (deleted++ < 5) {
						await this.routing(`/${rule.id}`, "DELETE");
						this.ctx.storage.sql.exec(
							"UPDATE mailboxes SET route_id=NULL,revoked=1 WHERE address=?",
							address,
						);
						if (box?.announced)
							await this.post(
								"*Delivery stopped*\nThis address has expired or been revoked and no longer receives mail.",
								box.thread_ts,
							);
					}
				}
			} catch {
				this.audit(
					"routing_cleanup_retry",
					null,
					"Will reconcile service-owned routes again on the next alarm",
				);
			}
		this.ctx.storage.sql.exec(
			"DELETE FROM emails WHERE received_at<?",
			Date.now() - 90 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM jobs WHERE (done=1 AND created_at<?) OR (done=2 AND created_at<?)",
			Date.now() - 2 * DAY,
			Date.now() - 365 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM requests WHERE created_at<?",
			Date.now() - 90 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM mailboxes WHERE route_id IS NULL AND created_at<?",
			Date.now() - 90 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM audits WHERE created_at<?",
			Date.now() - 365 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM reviews WHERE created_at<?",
			Date.now() - 365 * DAY,
		);
		this.ctx.storage.sql.exec(
			"DELETE FROM trial_intents WHERE created_at<?",
			Date.now() - 365 * DAY,
		);
		const pending = this.rows<{ n: number }>(
			"SELECT count(*) n FROM jobs WHERE done=0",
		)[0].n;
		const active = this.rows<{ n: number }>(
			"SELECT count(*) n FROM mailboxes WHERE route_id IS NOT NULL",
		)[0].n;
		await this.ctx.storage.setAlarm(
			Date.now() + (pending ? 10_000 : active ? 60_000 : DAY),
		);
	}

	private async review(config: Config, id: string) {
		if (!config.tavilyKey || !this.setting("codex")) {
			this.ctx.storage.sql.exec(
				"INSERT OR REPLACE INTO reviews VALUES (?,?,?,?)",
				id,
				"blocked",
				"Configure Tavily and connect your Codex subscription in the owner dashboard.",
				Date.now(),
			);
			return;
		}
		this.ctx.storage.sql.exec(
			"INSERT OR REPLACE INTO reviews VALUES (?,?,?,?)",
			id,
			"running",
			"Daily Pi review started",
			Date.now(),
		);
		const usage = this.rows<{
			user_id: string;
			domain: string;
			mailboxes: number;
			messages: number;
		}>(
			"SELECT m.user_id,e.domain,count(DISTINCT m.address) mailboxes,count(*) messages FROM emails e JOIN mailboxes m ON m.address=e.recipient LEFT JOIN bans b ON b.user_id=m.user_id WHERE e.received_at>? AND e.domain IS NOT NULL AND b.user_id IS NULL GROUP BY m.user_id,e.domain ORDER BY mailboxes DESC,messages DESC LIMIT 20",
			Date.now() - DAY,
		);
		const intents = this.rows<{ id: string; user_id: string; domain: string }>(
			"SELECT i.* FROM trial_intents i LEFT JOIN bans b ON b.user_id=i.user_id WHERE i.created_at>? AND b.user_id IS NULL ORDER BY i.created_at DESC LIMIT 20",
			Date.now() - DAY,
		);
		const observed = [
			...intents.map((i) => ({
				user_id: i.user_id,
				domain: i.domain,
				mailboxes: 0,
				messages: 0,
				intent_id: i.id,
			})),
			...usage,
		];
		try {
			const summary = await runReview(
				config.tavilyKey,
				observed.length ? await this.codexAccess() : "",
				observed,
				async (user, reason) => this.ban(user, reason, "pi"),
			);
			this.ctx.storage.sql.exec(
				"UPDATE reviews SET status='complete',summary=? WHERE id=?",
				summary,
				id,
			);
			this.audit("review_complete", null, id);
		} catch {
			this.ctx.storage.sql.exec(
				"UPDATE reviews SET status='failed',summary='Pi review failed. Check credentials; no decision was inferred from the failure.' WHERE id=?",
				id,
			);
			throw new Error("review_failed");
		}
	}
}
