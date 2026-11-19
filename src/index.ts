import { isOwner } from "./auth";
import { MailService } from "./service";

export { MailService };

function service(env: Env) {
	return env.MAIL.getByName("meow-mail");
}

async function boundedBody(
	request: Request,
	limit: number,
): Promise<string | null> {
	if (Number(request.headers.get("content-length") ?? "0") > limit) return null;
	const reader = request.body?.getReader();
	if (!reader) return "";
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > limit) {
			await reader.cancel();
			return null;
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(bytes);
}

function secure(response: Response): Response {
	const headers = new Headers(response.headers);
	headers.set("Cache-Control", "no-store");
	headers.set("X-Content-Type-Options", "nosniff");
	headers.set("Referrer-Policy", "no-referrer");
	headers.set("X-Frame-Options", "DENY");
	headers.set(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	);
	return new Response(response.body, { status: response.status, headers });
}

export default {
	async fetch(request, env): Promise<Response> {
		try {
			const url = new URL(request.url);
			const admin =
				url.pathname === "/admin" ||
				url.pathname.startsWith("/admin/") ||
				url.pathname === "/admin.html" ||
				url.pathname === "/admin.js";
			if (admin && !(await isOwner(request, env)))
				return secure(
					new Response(
						"Owner sign-in required. Open https://temp.mrrpmraow.com/admin",
						{ status: 403 },
					),
				);
			if (url.pathname.startsWith("/admin/api/")) {
				if (
					request.method !== "GET" &&
					request.headers.get("Origin") !== env.ORIGIN
				)
					return secure(new Response("Invalid origin", { status: 403 }));
				const body =
					request.method === "POST"
						? await boundedBody(request, 16_000)
						: (url.searchParams.get("id") ?? "");
				if (body === null)
					return secure(new Response("Too large", { status: 413 }));
				return secure(
					await service(env).admin(
						url.pathname.slice(11),
						request.method,
						body,
					),
				);
			}
			if (
				url.pathname === "/slack/events" ||
				url.pathname === "/slack/interactions"
			) {
				if (request.method !== "POST")
					return new Response("Method not allowed", { status: 405 });
				const body = await boundedBody(request, 64_000);
				if (body === null) return new Response("Too large", { status: 413 });
				return await service(env).slackIngress(
					url.pathname,
					body,
					request.headers.get("x-slack-request-timestamp") ?? "",
					request.headers.get("x-slack-signature") ?? "",
				);
			}
			if (url.pathname === "/health")
				return secure(Response.json({ ok: true, service: "meow-mail" }));
			if (request.method !== "GET" && request.method !== "HEAD")
				return secure(new Response("Method not allowed", { status: 405 }));
			return secure(await env.ASSETS.fetch(request));
		} catch {
			console.error(JSON.stringify({ kind: "request_failed" }));
			return secure(
				Response.json(
					{ error: "Request failed. Retry or check the owner audit log." },
					{ status: 500 },
				),
			);
		}
	},
	async email(message, env): Promise<void> {
		if (message.rawSize > 262_144) {
			message.setReject(
				"Meow Mail accepts messages up to 256 KiB, without attachment delivery.",
			);
			return;
		}
		const raw = await new Response(message.raw).text();
		if (new TextEncoder().encode(raw).length > 262_144) {
			message.setReject("Message too large");
			return;
		}
		const result = await service(env).receive(message.from, message.to, raw);
		if (result) message.setReject(result);
	},
	async scheduled(_event, env, ctx) {
		ctx.waitUntil(service(env).scheduleReview());
	},
} satisfies ExportedHandler<Env>;
