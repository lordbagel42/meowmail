import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import { zstdDecompressSync } from "node:zlib";
import { build } from "esbuild";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

type State = {
	mailboxes: {
		address: string;
		user_id: string;
		thread_ts: string;
		expires_at: number;
		revoked: number;
		route_id: string | null;
	}[];
	emails: { delivery_status: string }[];
	bans: { user_id: string; source: string }[];
	audits: { kind: string; user_id: string | null }[];
	reviews: { status: string; summary: string }[];
};

test("mail service enforces consent, signed actors, revocation, and owner-only access", async () => {
	const sent: Record<string, unknown>[] = [];
	const routes: { id: string; name: string }[] = [];
	let modelTurns = 0;
	let loseCreateResponse = false;
	let loseDeleteResponse = false;
	let loginChallenge = "";
	let exchanges = 0;
	let refreshes = 0;
	let slackAuthTeam = "EORG";
	let slackAuthError = "";
	let channelTeam: string | undefined = "TTEST";
	let heldConfig: { reached: () => void; wait: Promise<void> } | undefined;
	let heldChannel: { reached: () => void; wait: Promise<void> } | undefined;
	const accessToken = `e30.${Buffer.from(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "synthetic-account" } })).toString("base64url")}.signature`;
	const researchQueries: string[] = [];
	const { publicKey, privateKey } = await generateKeyPair("RS256");
	const jwk = {
		...(await exportJWK(publicKey)),
		kid: "test-key",
		alg: "RS256",
		use: "sig",
	};
	const origin = "https://temp.mrrpmraow.com";
	const bundle = await build({
		stdin: {
			contents: `import worker, { MailService } from './dist/index.js'; export class TestMailService extends MailService { async drain() { await super.alarm(); } } export default worker;`,
			resolveDir: process.cwd(),
		},
		bundle: true,
		format: "esm",
		platform: "neutral",
		external: ["cloudflare:*", "node:*"],
		write: false,
	});
	const mf = new Miniflare(
		convertV4MiniflareOptions({
			modules: true,
			script: bundle.outputFiles[0].text,
			compatibilityDate: "2026-11-19",
			compatibilityFlags: ["nodejs_compat"],
			assets: {
				directory: "public",
				binding: "ASSETS",
				run_worker_first: true,
				routerConfig: { has_user_worker: true },
			},
			durableObjects: {
				MAIL: { className: "TestMailService", useSQLite: true },
			},
			bindings: {
				CONFIG_KEY: "synthetic-encryption-key",
				CF_ROUTING_TOKEN: "synthetic-routing-token",
				SLACK_DEPLOYMENT: JSON.stringify({
					slackToken: "xoxb-deployed-synthetic",
					slackSigningSecret: "deploy-signing",
					channel: "CTEST",
					team: "TTEST",
					botUser: "UOURBOT",
					enabled: true,
				}),
				ORIGIN: origin,
				MAIL_DOMAIN: "temp.mrrpmraow.com",
				ACCESS_ISSUER: "https://bagel.cloudflareaccess.com",
				ACCESS_AUD: "test-audience",
			},
			outboundService: async (request) => {
				const url = new URL(request.url);
				if (url.pathname === "/cdn-cgi/access/certs")
					return Response.json({ keys: [jwk] });
				if (url.hostname === "auth.openai.com") {
					assert.equal(
						url.pathname,
						"/oauth/token",
						"Only legacy token exchange/refresh; no device endpoints",
					);
					const params = new URLSearchParams(await request.text());
					assert.equal(params.get("client_id"), "app_EMoamEEZ73f0CkXaXp7hrann");
					if (params.get("grant_type") === "authorization_code") {
						exchanges++;
						assert.equal(
							params.get("redirect_uri"),
							"http://localhost:1455/auth/callback",
						);
						assert.equal(params.get("code"), "synthetic-code");
						assert.equal(
							createHash("sha256")
								.update(params.get("code_verifier") ?? "")
								.digest("base64url"),
							loginChallenge,
						);
					} else {
						assert.equal(params.get("grant_type"), "refresh_token");
						assert.equal(
							params.get("refresh_token"),
							refreshes === 0 ? "synthetic-refresh" : "rotated-refresh",
						);
						refreshes++;
					}
					return Response.json({
						access_token: accessToken,
						refresh_token: refreshes ? "rotated-refresh" : "synthetic-refresh",
						expires_in: refreshes > 1 ? 3600 : 60,
					});
				}
				const data =
					request.method === "POST"
						? ((request.headers.get("content-encoding") === "zstd"
								? JSON.parse(
										zstdDecompressSync(
											Buffer.from(await request.arrayBuffer()),
										).toString("utf8"),
									)
								: await request.json()) as Record<string, unknown>)
						: {};
				if (url.hostname === "slack.com") {
					if (url.pathname.endsWith("auth.test")) {
						if (slackAuthError)
							return Response.json({ ok: false, error: slackAuthError });
						if (heldConfig) {
							heldConfig.reached();
							await heldConfig.wait;
						}
						return Response.json({
							ok: true,
							team_id: slackAuthTeam,
							user_id: "UOURBOT",
						});
					}
					if (url.pathname.endsWith("conversations.info")) {
						if (url.searchParams.get("channel") !== "CTEST")
							return Response.json({ ok: false, error: "missing_argument" });
						const contextTeam = channelTeam;
						const hold = heldChannel;
						heldChannel = undefined;
						if (hold) {
							hold.reached();
							await hold.wait;
						}
						return Response.json({
							ok: true,
							channel: {
								name: "meow-mail",
								context_team_id: contextTeam,
								is_member: true,
								is_archived: false,
							},
						});
					}
					if (url.pathname.endsWith("users.info")) {
						if (!url.searchParams.get("user"))
							return Response.json({ ok: false, error: "missing_argument" });
						return Response.json({ ok: true, user: { is_bot: false } });
					}
					sent.push(data);
					return Response.json({ ok: true, ts: `${Date.now() / 1000}` });
				}
				if (url.hostname === "api.cloudflare.com") {
					if (request.method === "GET")
						return Response.json({ success: true, result: routes });
					if (request.method === "DELETE") {
						const index = routes.findIndex((r) =>
							url.pathname.endsWith(`/${r.id}`),
						);
						if (index < 0)
							return Response.json({ success: false }, { status: 404 });
						routes.splice(index, 1);
						if (loseDeleteResponse) {
							loseDeleteResponse = false;
							throw new Error("Synthetic response lost after remote deletion");
						}
						return Response.json({ success: true, result: {} });
					}
					const rule = { id: crypto.randomUUID(), name: String(data.name) };
					routes.push(rule);
					if (loseCreateResponse) {
						loseCreateResponse = false;
						throw new Error("Synthetic response lost after remote creation");
					}
					return Response.json({ success: true, result: rule });
				}
				if (url.hostname === "api.tavily.com") {
					researchQueries.push(String(data.query));
					return Response.json({
						results: [
							{
								url: "https://example.org/terms",
								title: "Synthetic service terms",
								content:
									"Multiple accounts to evade trial limits are prohibited.",
							},
						],
					});
				}
				if (url.hostname === "chatgpt.com") {
					assert.equal(url.pathname, "/backend-api/codex/responses");
					assert.equal(
						request.headers.get("authorization"),
						`Bearer ${accessToken}`,
					);
					assert.equal(
						request.headers.get("chatgpt-account-id"),
						"synthetic-account",
					);
					assert.equal(data.model, "gpt-6.1-terra");
					const turn = modelTurns++;
					const call =
						turn === 0
							? { name: "research_site", input: { domain: "example.org" } }
							: turn === 1 || turn === 2
								? {
										name: "ban_user",
										input: {
											user_id: turn === 1 ? "UOTHERUSER" : "UADMITTED",
											domain: "example.org",
											reason:
												"Synthetic reviewer attempts a ban; code must independently require an attributable signed free-trial request.",
											source_urls: ["https://example.org/terms"],
										},
									}
								: null;
					const item = call
						? {
								type: "function_call",
								id: `fc_${turn}`,
								call_id: `call_${turn}`,
								name: call.name,
								arguments: JSON.stringify(call.input),
								status: "completed",
							}
						: {
								type: "message",
								id: `msg_${turn}`,
								role: "assistant",
								status: "completed",
								content: [
									{
										type: "output_text",
										text: "Synthetic review complete; forged inbound evidence refused and signed intent handled.",
										annotations: [],
									},
								],
							};
					const events = [
						{
							type: "response.created",
							response: { id: `resp_${turn}`, status: "in_progress" },
						},
						{
							type: "response.output_item.added",
							output_index: 0,
							item: call
								? { ...item, arguments: "" }
								: { ...item, content: [] },
						},
						{ type: "response.output_item.done", output_index: 0, item },
						{
							type: "response.completed",
							response: {
								id: `resp_${turn}`,
								status: "completed",
								output: [item],
								usage: {
									input_tokens: 40,
									output_tokens: 40,
									total_tokens: 80,
								},
							},
						},
					];
					return new Response(
						events
							.map(
								(value) =>
									`event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`,
							)
							.join(""),
						{ headers: { "content-type": "text/event-stream" } },
					);
				}
				throw new Error(`Unexpected network request: ${url.hostname}`);
			},
		}),
	);
	try {
		const ns = await mf.getDurableObjectNamespace("MAIL");
		const stub = ns.get(ns.idFromName("meow-mail"));
		const admin = async (path: string, data?: object) => {
			const response = await stub.admin(
				path,
				data ? "POST" : "GET",
				data ? JSON.stringify(data) : "",
			);
			return {
				status: response.status,
				...((await response.json()) as Record<string, unknown>),
			};
		};
		const state = async (): Promise<State> => {
			const response = await stub.admin("state", "GET", "");
			return response.json() as Promise<State>;
		};
		const tick = async () => {
			await stub.drain();
			await stub.drain();
		};
		const event = async (user: string, ts: string, extra: object = {}) => {
			const body = JSON.stringify({
				type: "event_callback",
				team_id: "TTEST",
				event_id: `event-${ts}`,
				event: {
					type: "message",
					channel: "CTEST",
					user,
					ts,
					text: "gib email",
					...extra,
				},
			});
			const timestamp = String(Math.floor(Date.now() / 1000));
			const signature = `v0=${createHmac("sha256", "test-signing").update(`v0:${timestamp}:${body}`).digest("hex")}`;
			return mf.dispatchFetch(`${origin}/slack/events`, {
				method: "POST",
				headers: {
					"x-slack-request-timestamp": timestamp,
					"x-slack-signature": signature,
				},
				body,
			});
		};
		const anonymous = await mf.dispatchFetch(`${origin}/admin/api/state`);
		assert.equal(anonymous.status, 403, await anonymous.text());
		assert.equal((await mf.dispatchFetch(`${origin}/admin.html`)).status, 403);
		const oversized = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("é".repeat(33_000)));
				controller.close();
			},
		});
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/slack/events`, {
					method: "POST",
					body: oversized,
					duplex: "half",
				})
			).status,
			413,
			"Streamed size is bounded in bytes without Content-Length",
		);
		const jwt = async (email: string, aud = "test-audience") =>
			new SignJWT({ email })
				.setProtectedHeader({ alg: "RS256", kid: "test-key" })
				.setIssuer("https://bagel.cloudflareaccess.com")
				.setAudience(aud)
				.setSubject("test-owner")
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);
		const ownerJWT = await jwt("me@raygen.dev");
		const deployed = await admin("state");
		assert.equal(
			(deployed.config as { slack: boolean }).slack,
			true,
			"CLI deployment credentials are available without dashboard entry",
		);
		assert.equal(
			(deployed.config as { enabled: boolean }).enabled,
			false,
			"Deployment credentials cannot enable mail or bypass review setup",
		);
		assert.ok(
			!JSON.stringify(deployed).includes("xoxb-deployed-synthetic"),
			"Deployment secrets are not returned",
		);
		assert.equal(
			(await mf.dispatchFetch(`${origin}/tos`, { redirect: "manual" })).status,
			200,
			"Clean terms URL must not redirect to itself",
		);
		const dashboard = await mf.dispatchFetch(`${origin}/admin`, {
			headers: { "cf-access-jwt-assertion": ownerJWT },
			redirect: "manual",
		});
		assert.equal(
			dashboard.status,
			200,
			"Authenticated clean dashboard URL must render, not redirect to itself",
		);
		assert.ok((await dashboard.text()).includes('id="config-form"'));
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/admin/api/state`, {
					headers: { "cf-access-jwt-assertion": ownerJWT },
				})
			).status,
			200,
		);
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/admin/api/state`, {
					headers: {
						"cf-access-jwt-assertion": await jwt("other@example.com"),
					},
				})
			).status,
			403,
		);
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/admin/api/state`, {
					headers: {
						"cf-access-jwt-assertion": await jwt(
							"me@raygen.dev",
							"wrong-audience",
						),
					},
				})
			).status,
			403,
		);
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/admin/api/ban`, {
					method: "POST",
					headers: {
						"cf-access-jwt-assertion": ownerJWT,
						Origin: "https://evil.example",
					},
					body: "{}",
				})
			).status,
			403,
		);
		for (const path of ["start", "complete", "disconnect"]) {
			assert.equal(
				(
					await mf.dispatchFetch(`${origin}/admin/api/codex/${path}`, {
						method: "POST",
						body: "{}",
					})
				).status,
				403,
			);
			assert.equal(
				(
					await mf.dispatchFetch(`${origin}/admin/api/codex/${path}`, {
						method: "POST",
						headers: {
							"cf-access-jwt-assertion": ownerJWT,
							Origin: "https://evil.example",
						},
						body: "{}",
					})
				).status,
				403,
			);
		}
		const start = await admin("codex/start", {});
		const authorization = new URL(String(start.authorization_url));
		assert.equal(authorization.origin, "https://auth.openai.com");
		assert.equal(authorization.pathname, "/oauth/authorize");
		assert.equal(
			authorization.searchParams.get("redirect_uri"),
			"http://localhost:1455/auth/callback",
		);
		assert.equal(
			authorization.searchParams.get("code_challenge_method"),
			"S256",
		);
		assert.equal(
			authorization.searchParams.get("scope"),
			"openid profile email offline_access",
		);
		loginChallenge = authorization.searchParams.get("code_challenge") ?? "";
		const callback = `http://localhost:1455/auth/callback?code=synthetic-code&state=${authorization.searchParams.get("state")}`;
		for (const callback_url of [
			callback.replace("localhost:1455", "evil.example"),
			callback.replace("&state=", "&state=wrong"),
			"synthetic-code",
			`${callback}&code=duplicate`,
		]) {
			assert.equal(
				(await admin("codex/complete", { callback_url })).status,
				400,
			);
		}
		assert.equal(exchanges, 0, "Invalid callbacks never reach token exchange");
		assert.equal(
			(await admin("codex/complete", { callback_url: callback })).status,
			"connected",
		);
		assert.equal(
			(await admin("codex/complete", { callback_url: callback })).status,
			400,
			"Callback is one use",
		);
		assert.equal(exchanges, 1);
		const connectionState = JSON.stringify(await state());
		for (const secret of [
			accessToken,
			"synthetic-refresh",
			loginChallenge,
			authorization.searchParams.get("state") ?? "missing",
		])
			assert.ok(
				!connectionState.includes(secret),
				"State omits OAuth secrets and pending material",
			);
		slackAuthError = "invalid_auth";
		const failedSave = await admin("config", { enabled: true });
		assert.equal(failedSave.status, 502);
		assert.match(String(failedSave.error), /slack_auth \(slack_invalid_auth\)/);
		assert.equal(
			((await admin("state")).config as { enabled: boolean }).enabled,
			false,
			"Failed Slack validation cannot enable mail",
		);
		slackAuthError = "";
		assert.equal(
			(
				await admin("config", {
					slackToken: "xoxb-synthetic",
					slackSigningSecret: "test-signing",
					channel: "CTEST",
					tavilyKey: "synthetic",
					enabled: true,
				})
			).status,
			200,
		);
		channelTeam = undefined;
		assert.equal(
			(await admin("config", {})).status,
			400,
			"An organization ID cannot stand in for the channel workspace",
		);
		slackAuthTeam = "TTEST";
		assert.equal((await admin("config", {})).status, 200);
		slackAuthTeam = "EORG";
		channelTeam = "TTEST";
		assert.equal((await admin("config", {})).status, 200);
		assert.equal(
			((await admin("state")).config as { enabled: boolean }).enabled,
			true,
			"Revalidation preserves enablement",
		);
		assert.equal(
			(await admin("unban", { user_id: "U085KKYFA6Q" })).status,
			400,
		);
		assert.equal(
			(
				await mf.dispatchFetch(`${origin}/slack/events`, {
					method: "POST",
					body: '{"event":{"text":"gib email"}}',
				})
			).status,
			401,
		);
		assert.equal((await event("U085KKYFA6Q", "100.001")).status, 200);
		await tick();
		assert.equal((await state()).mailboxes.length, 0);
		await event("UOTHERUSER", "100.002");
		await tick();
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"No address before terms acceptance",
		);
		assert.ok(sent.some((m) => JSON.stringify(m).includes("accept_terms")));
		assert.ok(
			sent.some((m) => JSON.stringify(m).includes("not Devansh Awatramani")),
		);
		const consent = async (
			user: string,
			ts = "100.002",
			version = "2026-11-19.2",
			team: string | null = "TINSTALL",
			channel = "CTEST",
		) => {
			const body = new URLSearchParams({
				payload: JSON.stringify({
					type: "block_actions",
					team: team === null ? null : { id: team },
					user: { id: user, team_id: "TTEST" },
					channel: { id: channel },
					container: { message_ts: `terms-${ts}` },
					message: { ts: `fallback-${ts}` },
					actions: [{ action_id: "accept_terms", value: `${version}:${ts}` }],
				}),
			}).toString();
			const timestamp = String(Math.floor(Date.now() / 1000));
			const signature = `v0=${createHmac("sha256", "test-signing").update(`v0:${timestamp}:${body}`).digest("hex")}`;
			await mf.dispatchFetch(`${origin}/slack/interactions`, {
				method: "POST",
				headers: {
					"x-slack-request-timestamp": timestamp,
					"x-slack-signature": signature,
				},
				body,
			});
			await tick();
		};
		await consent("UOTHERUSER", "100.002", "2026-11-19");
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"Old terms cannot authorize an address",
		);
		await consent("UIMPOSTOR");
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"Someone else's acceptance cannot issue an address",
		);
		await consent("UOTHERUSER", "100.002", "2026-11-19.2", "TTEST", "COTHER");
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"The actor's workspace cannot authorize a different channel",
		);
		channelTeam = "TOTHER";
		await consent("UOTHERUSER", "100.002", "2026-11-19.2", "TTEST");
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"The actor's workspace cannot override the authenticated channel workspace",
		);
		channelTeam = undefined;
		await consent("UOTHERUSER", "100.002", "2026-11-19.2", "TABSENT");
		assert.equal(
			(await state()).mailboxes.length,
			0,
			"An authenticated organization ID is not a channel workspace",
		);
		channelTeam = "TTEST";
		for (const change of ["delete", "ban", "credentials"] as const) {
			const user = `URACETEST${change.toUpperCase()}`;
			const ts = `race-${change}`;
			await event(user, ts);
			await tick();
			let release!: () => void;
			const reached = new Promise<void>((resolve) => {
				heldChannel = {
					reached: resolve,
					wait: new Promise<void>((r) => {
						release = r;
					}),
				};
			});
			const accepting = consent(user, ts);
			await reached;
			try {
				if (change === "delete")
					await event(user, `${ts}-deleted`, {
						subtype: "message_deleted",
						deleted_ts: ts,
						text: undefined,
					});
				else if (change === "ban")
					assert.equal(
						(await admin("ban", { user_id: user, reason: "Fixture" })).status,
						200,
					);
				else
					assert.equal(
						(await admin("config", { slackToken: "xoxb-rotated" })).status,
						200,
					);
			} finally {
				release();
			}
			await accepting;
			const snapshot = await state();
			assert.ok(!snapshot.mailboxes.some((box) => box.user_id === user));
			assert.ok(
				!snapshot.audits.some(
					(audit) => audit.kind === "terms_accepted" && audit.user_id === user,
				),
				`${change} during lookup must prevent consent`,
			);
		}
		assert.equal(
			(await admin("config", { slackToken: "xoxb-synthetic" })).status,
			200,
		);
		assert.ok(
			!sent.some((message) => message.ts === "terms-100.002"),
			"Rejected acceptance must not mark the Terms prompt accepted",
		);
		await consent("UOTHERUSER");
		const boxes = (await state()).mailboxes;
		assert.equal(boxes.length, 1);
		const accepted = sent.find((message) => message.ts === "terms-100.002");
		assert.equal(accepted?.channel, "CTEST");
		assert.equal(
			accepted?.text,
			"*Terms accepted*\n<@UOTHERUSER>, your acceptance has been recorded.",
		);
		assert.deepEqual(
			accepted?.blocks,
			[],
			"Acceptance removes the Terms button",
		);
		channelTeam = undefined;
		slackAuthTeam = "TTEST";
		await consent("UOTHERUSER", "100.002", "2026-11-19.2", null);
		assert.equal(
			(await state()).audits.filter(
				(audit) =>
					audit.kind === "terms_accepted" && audit.user_id === "UOTHERUSER",
			).length,
			2,
			"Ordinary workspace auth can resolve a missing channel context without trusting the payload team",
		);
		channelTeam = "TTEST";
		slackAuthTeam = "EORG";
		assert.ok(boxes[0].expires_at > Date.now() + 86_000_000);
		const raw = `From: sender@example.org\r\nTo: ${boxes[0].address}\r\nSubject: Synthetic delivery check\r\n\r\nHello, <@U085KKYFA6Q> & <script>not executable</script>`;
		assert.equal(
			await stub.receive("sender@example.org", boxes[0].address, raw),
			null,
		);
		await tick();
		assert.equal((await state()).emails[0].delivery_status, "delivered");
		const delivered = sent.find(
			(m) => m.text === "Incoming email · Logged and audited",
		);
		assert.ok(delivered);
		const mailBlocks = delivered.blocks as {
			text?: { type: string; text: string };
		}[];
		assert.equal(mailBlocks[1].text?.type, "plain_text");
		assert.equal(mailBlocks[3].text?.type, "plain_text");
		assert.equal(
			mailBlocks[3].text?.text,
			"Hello, <@U085KKYFA6Q> & <script>not executable</script>\n",
			"Formatting must not interpret or rewrite email content",
		);
		await stub.receive("sender@example.org", boxes[0].address, raw);
		assert.equal(
			(await state()).emails.length,
			1,
			"SMTP retry is deduplicated",
		);
		await event("UOTHERUSER", "100.003", {
			subtype: "message_deleted",
			deleted_ts: "100.002",
			text: undefined,
		});
		assert.ok(
			await stub.receive(
				"sender@example.org",
				boxes[0].address,
				`${raw} again`,
			),
			"Deletion immediately revokes delivery",
		);
		await event("UAUTOBOT", "100.004", {
			bot_id: "BAUTOMATION",
			subtype: "bot_message",
		});
		assert.ok(
			(await state()).bans.some((b) => b.user_id === "UAUTOBOT"),
			"Verified automated actor is immediately banned",
		);
		assert.ok(
			!(await state()).bans.some((b) => b.user_id === "UOTHERUSER"),
			"Do not blame unrelated humans for bot messages",
		);
		await event("U08R4KDL6UF", "100.005", {
			bot_id: "BOWNERTOOL",
			subtype: "bot_message",
		});
		await tick();
		assert.ok(
			!(await state()).bans.some((b) => b.user_id === "U08R4KDL6UF"),
			"Owner automation exception",
		);
		for (const ts of ["100.006", "100.007"]) {
			await event("UOTHERUSER", ts);
			await tick();
			const box = (await state()).mailboxes.find((b) => b.thread_ts === ts);
			assert.ok(box);
			await stub.receive("sender@example.org", box.address, `${raw}\n${ts}`);
			await tick();
			if (ts === "100.006") {
				await event("UOTHERUSER", `${ts}9`, {
					subtype: "message_deleted",
					deleted_ts: ts,
					text: undefined,
				});
				await tick();
			}
		}
		await event("ULOSTPOST", "100.008");
		await tick();
		loseCreateResponse = true;
		await consent("ULOSTPOST", "100.008");
		const lost = (await state()).mailboxes.find(
			(b) => b.thread_ts === "100.008",
		);
		assert.ok(lost);
		loseDeleteResponse = true;
		await event("ULOSTPOST", "100.009", {
			subtype: "message_deleted",
			deleted_ts: "100.008",
			text: undefined,
		});
		await tick();
		assert.ok(
			!routes.some((r) => r.name === `meow-mail:${lost.address}`),
			"Ambiguous creation reconciles even after request deletion",
		);
		assert.equal(
			(await state()).mailboxes.find((b) => b.thread_ts === "100.008")
				?.route_id,
			null,
			"Ambiguous deletion releases local routing capacity",
		);
		await event("UADMITTED", "100.010", {
			text: "gib email for a free trial on example.org",
		});
		await tick();
		assert.ok(
			!(await state()).mailboxes.some((b) => b.user_id === "UADMITTED"),
			"Free-trial intent never issues an address",
		);
		await admin("review", {});
		await tick();
		const reviewed = await state();
		assert.equal(
			reviewed.reviews[0].status,
			"complete",
			JSON.stringify({ modelTurns, refreshes, exchanges }),
		);
		assert.equal(
			modelTurns,
			4,
			"Real Pi loop completed research, rejected forged evidence, accepted signed intent, and summarized",
		);
		assert.ok(
			!reviewed.bans.some((b) => b.user_id === "UOTHERUSER"),
			"Even a model ban call cannot turn unauthenticated inbound mail into a ban",
		);
		assert.ok(
			reviewed.bans.some((b) => b.user_id === "UADMITTED" && b.source === "pi"),
			"Pi independently bans on attributable intent plus researched evidence",
		);
		assert.equal(researchQueries.length, 1);
		assert.ok(
			!researchQueries[0].includes("sender@"),
			"Tavily receives only site domains, not email addresses/content",
		);
		assert.ok(
			!JSON.stringify(await state()).includes("xoxb-synthetic"),
			"Secrets are not returned",
		);
		assert.equal(
			refreshes,
			1,
			"Near-expiry subscription authorization refreshed before Pi review",
		);
		await admin("review", {});
		await tick();
		assert.equal(
			refreshes,
			1,
			"Repeated requests do not rerun the daily review or consume more subscription allowance",
		);
		let release!: () => void;
		const reached = new Promise<void>((resolve) => {
			heldConfig = {
				reached: resolve,
				wait: new Promise<void>((r) => {
					release = r;
				}),
			};
		});
		const saving = admin("config", { enabled: true });
		await reached;
		try {
			assert.equal(
				(await admin("codex/disconnect", {})).status,
				409,
				"Concurrent disconnect fails explicitly rather than racing a settings write",
			);
		} finally {
			release();
		}
		assert.equal((await saving).status, 200);
		heldConfig = undefined;
		assert.equal((await admin("codex/disconnect", {})).status, 200);
		const disconnected = await admin("state");
		assert.equal((disconnected.config as { codex: boolean }).codex, false);
		assert.equal((disconnected.config as { enabled: boolean }).enabled, false);
		assert.equal(
			(await admin("config", { enabled: true })).status,
			400,
			"Cannot enable without subscription; no API fallback",
		);
	} finally {
		await mf.dispose();
	}
});

test("operator Pi import is one-shot, preserves existing grants, and never enables mail", async () => {
	const id = "11111111-1111-4111-8111-111111111111";
	const skippedId = "22222222-2222-4222-8222-222222222222";
	const access = `e30.${Buffer.from(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "import-account" } })).toString("base64url")}.signature`;
	const credential = {
		type: "oauth",
		access,
		refresh: "synthetic-import-refresh",
		expires: Date.now() + 3_600_000,
		accountId: "import-account",
		unrelated: "must-not-be-persisted",
	};
	const options = {
		modules: true,
		scriptPath: "dist/index.js",
		compatibilityDate: "2026-11-19",
		compatibilityFlags: ["nodejs_compat"],
		durableObjects: { MAIL: { className: "MailService", useSQLite: true } },
		bindings: {
			CONFIG_KEY: "synthetic-bootstrap-encryption-key",
			MEOW_MAIL_TAVILY_API_KEY: "synthetic-import-tavily",
			SLACK_DEPLOYMENT: JSON.stringify({
				channel: "CIMPORT",
				slackToken: "synthetic-import-slack",
			}),
			CODEX_BOOTSTRAP: "invalid JSON",
		},
		outboundService: async () => {
			throw new Error("Bootstrap must not call a provider");
		},
	};
	const mf = new Miniflare(convertV4MiniflareOptions(options));
	const state = async () => {
		const ns = await mf.getDurableObjectNamespace("MAIL");
		const response = await ns
			.get(ns.idFromName("meow-mail"))
			.admin("state", "GET", "");
		return response.json() as Promise<{
			config: {
				codex: boolean;
				enabled: boolean;
				slack: boolean;
				tavily: boolean;
				channel: string;
				codexImport: { id: string; outcome: string } | null;
			};
		}>;
	};
	const reload = async (bootstrap: unknown) => {
		options.bindings.CODEX_BOOTSTRAP =
			typeof bootstrap === "string" ? bootstrap : JSON.stringify(bootstrap);
		await mf.setOptions(convertV4MiniflareOptions(options));
		return state();
	};
	const disconnect = async () => {
		const ns = await mf.getDurableObjectNamespace("MAIL");
		const response = await ns
			.get(ns.idFromName("meow-mail"))
			.admin("codex/disconnect", "POST", "{}");
		assert.equal(response.status, 200);
	};
	try {
		assert.equal(
			(await state()).config.codex,
			false,
			"Malformed input does not stop normal requests",
		);
		await reload({ id, credential });
		const results = await Promise.all([state(), state(), state()]);
		for (const result of results) {
			assert.equal(result.config.codex, true);
			assert.equal(result.config.enabled, false);
			assert.equal(result.config.slack, true);
			assert.equal(result.config.tavily, true);
			assert.equal(result.config.channel, "CIMPORT");
			assert.deepEqual(result.config.codexImport, { id, outcome: "imported" });
			const serialized = JSON.stringify(result);
			for (const secret of [
				access,
				credential.refresh,
				credential.unrelated,
				"synthetic-import-tavily",
			])
				assert.equal(serialized.includes(secret), false);
		}
		assert.equal(
			(await reload({ id: skippedId, credential })).config.codexImport?.outcome,
			"skipped_existing",
		);
		await disconnect();
		assert.equal(
			(await reload({ id: skippedId, credential })).config.codex,
			false,
			"Skipped import cannot take over after disconnect",
		);
		assert.equal(
			(await reload({ id, credential })).config.codex,
			false,
			"Consumed import cannot resurrect a disconnected grant",
		);
		for (const invalid of [
			{ ...credential, type: "api_key" },
			{ ...credential, accountId: "wrong-account" },
			{ ...credential, refresh: "" },
			{ ...credential, expires: "tomorrow" },
		]) {
			const result = await reload({
				id: "33333333-3333-4333-8333-333333333333",
				credential: invalid,
			});
			assert.equal(result.config.codex, false);
			assert.equal(result.config.slack, true);
		}
		const imported = await reload({
			id: "33333333-3333-4333-8333-333333333333",
			credential: { ...credential, expires: 1 },
		});
		assert.equal(
			imported.config.codex,
			true,
			"Expired access token may still have a usable refresh grant",
		);
		assert.equal(
			(await reload("")).config.codex,
			true,
			"Removing bootstrap secret preserves encrypted grant",
		);
	} finally {
		await mf.dispose();
	}
});
