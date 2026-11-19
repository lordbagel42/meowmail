import { decodeJwt } from "jose";

// Legacy browser callback protocol used by Pi 1.5.2's openai-codex provider.
// No Platform API key or paid API fallback is accepted.
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTH = "https://auth.openai.com";
const REDIRECT = "http://localhost:1455/auth/callback";

export type CodexCredential = {
	access: string;
	refresh: string;
	expires: number;
	accountId: string;
};

export type CodexLogin = {
	verifier: string;
	state: string;
	expiresAt: number;
};

// Deployment input is trusted operator data, not proof of provider acceptance.
export function piCodexCredential(input: unknown): CodexCredential {
	if (!input || typeof input !== "object")
		throw new Error("Invalid Pi Codex credential");
	const value = input as Record<string, unknown>;
	for (const key of ["access", "refresh", "accountId"])
		if (
			typeof value[key] !== "string" ||
			!value[key] ||
			value[key].length > 12_000
		)
			throw new Error("Invalid Pi Codex credential");
	if (
		value.type !== "oauth" ||
		typeof value.expires !== "number" ||
		!Number.isFinite(value.expires) ||
		value.expires <= 0
	)
		throw new Error("Invalid Pi Codex credential");
	const access = value.access as string;
	const auth = decodeJwt(access)["https://api.openai.com/auth"] as
		| { chatgpt_account_id?: unknown }
		| undefined;
	if (auth?.chatgpt_account_id !== value.accountId)
		throw new Error("Invalid Pi Codex account");
	return {
		access,
		refresh: value.refresh as string,
		expires: value.expires,
		accountId: value.accountId as string,
	};
}

function base64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export async function startCodexLogin(): Promise<{
	pending: CodexLogin;
	url: string;
}> {
	const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
	const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
	const challenge = base64url(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
		),
	);
	const url = new URL(`${AUTH}/oauth/authorize`);
	url.search = new URLSearchParams({
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT,
		scope: "openid profile email offline_access",
		code_challenge: challenge,
		code_challenge_method: "S256",
		state,
		id_token_add_organizations: "true",
		codex_cli_simplified_flow: "true",
		originator: "pi",
	}).toString();
	return {
		pending: { verifier, state, expiresAt: Date.now() + 10 * 60_000 },
		url: url.toString(),
	};
}

export async function callbackCode(
	input: unknown,
	pending: CodexLogin,
): Promise<string> {
	if (
		typeof input !== "string" ||
		input.length > 8000 ||
		pending.expiresAt <= Date.now()
	)
		throw new Error("Invalid or expired callback");
	const url = new URL(input.trim());
	if (
		url.origin !== new URL(REDIRECT).origin ||
		url.pathname !== "/auth/callback" ||
		url.username ||
		url.password ||
		url.hash ||
		url.searchParams.has("error") ||
		url.searchParams.getAll("code").length !== 1 ||
		url.searchParams.getAll("state").length !== 1
	)
		throw new Error("Invalid callback");
	const hash = async (value: string) =>
		crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	const [actual, expected] = await Promise.all([
		hash(url.searchParams.get("state") ?? ""),
		hash(pending.state),
	]);
	if (!crypto.subtle.timingSafeEqual(actual, expected))
		throw new Error("Callback state mismatch");
	const code = url.searchParams.get("code");
	if (!code) throw new Error("Missing callback code");
	return code;
}

async function token(body: Record<string, string>): Promise<CodexCredential> {
	const response = await fetch(`${AUTH}/oauth/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...body, client_id: CLIENT_ID }),
		signal: AbortSignal.timeout(12_000),
	});
	if (!response.ok)
		throw new Error(
			"Codex authorization failed. Reconnect your subscription; no API fallback was used.",
		);
	const data = await response.json<{
		access_token?: string;
		refresh_token?: string;
		expires_in?: number;
	}>();
	if (
		!data.access_token ||
		!data.refresh_token ||
		typeof data.expires_in !== "number" ||
		!Number.isFinite(data.expires_in) ||
		data.expires_in <= 0
	)
		throw new Error("Invalid Codex token response");
	const auth = decodeJwt(data.access_token)["https://api.openai.com/auth"] as
		| { chatgpt_account_id?: unknown }
		| undefined;
	if (typeof auth?.chatgpt_account_id !== "string" || !auth.chatgpt_account_id)
		throw new Error("Codex account missing from authorization");
	return {
		access: data.access_token,
		refresh: data.refresh_token,
		expires: Date.now() + data.expires_in * 1000,
		accountId: auth.chatgpt_account_id,
	};
}

export function completeCodexLogin(
	code: string,
	pending: CodexLogin,
): Promise<CodexCredential> {
	return token({
		grant_type: "authorization_code",
		code,
		code_verifier: pending.verifier,
		redirect_uri: REDIRECT,
	});
}

export function refreshCodex(
	credential: CodexCredential,
): Promise<CodexCredential> {
	return token({
		grant_type: "refresh_token",
		refresh_token: credential.refresh,
	});
}
