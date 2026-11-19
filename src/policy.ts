export const OWNER = "U08R4KDL6UF";
export const OWNER_EMAIL = "me@raygen.dev";
export const HARDCODED_BAN = "U085KKYFA6Q";
export const TOS_VERSION = "2026-11-19.2";
export const DAY = 86_400_000;
export const TERMS =
	"By accepting, you confirm that you are not Devansh Awatramani, are not using Meow Mail on behalf of Devansh Awatramani, and, to the best of your knowledge, information and belief, no address or email obtained through this service will be made available to Devansh Awatramani.\n\n" +
	"No free trials, trial cycling, limit evasion, spam, fraud, or other abuse.\n\n" +
	"All email received through Meow Mail is logged and audited by its operator and an automated Pi reviewer, which may ban you without advance approval. Mail is posted in this channel and is not private. Email content is retained for 90 days; moderation records for one year.\n\n" +
	"Research sends site domains, not email bodies, to Tavily; the AI reviewer processes limited usage evidence. Automated address requests are prohibited except for the operator. Proven, attributable automated requests cause an immediate service ban.\n\n" +
	"You are responsible for using only accounts and services you are authorized to access. Contact me@raygen.dev to appeal.\n\n" +
	"This service receives email only, offers no availability guarantee, and addresses expire after 24 hours. Deleting your request stops delivery, but does not erase audit records.";

export function isRequest(text: unknown): boolean {
	return typeof text === "string" && /^gib\s+email[.!]?$/i.test(text.trim());
}

// Narrow, explicit first-person intent, not a model's interpretation of inbound mail.
export function trialRequest(text: unknown): string | null {
	if (typeof text !== "string") return null;
	const match = /^gib email for (?:a )?free trial on ([a-z0-9.-]+)$/i.exec(
		text.trim(),
	);
	return match ? siteDomain(`intent@${match[1]}`) : null;
}

export function escapeSlack(text: string): string {
	return text
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;");
}

export function usableMailbox(
	mailbox: { expires_at: number; revoked: number } | undefined,
	banned: boolean,
	now = Date.now(),
): boolean {
	return !!mailbox && !banned && !mailbox.revoked && mailbox.expires_at > now;
}

export function automationAction(user: string, bot: boolean): "allow" | "ban" {
	return bot && user !== OWNER ? "ban" : "allow";
}

export async function verifySlack(
	body: string,
	timestamp: string,
	signature: string,
	secret: string,
	now = Date.now(),
): Promise<boolean> {
	if (
		!/^\d+$/.test(timestamp) ||
		Math.abs(now / 1000 - Number(timestamp)) > 300 ||
		!/^v0=[a-f0-9]{64}$/.test(signature)
	)
		return false;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["verify"],
	);
	const bytes = Uint8Array.from(signature.slice(3).match(/../g) ?? [], (b) =>
		Number.parseInt(b, 16),
	);
	return crypto.subtle.verify(
		"HMAC",
		key,
		bytes,
		encoder.encode(`v0:${timestamp}:${body}`),
	);
}

export function siteDomain(sender: string): string | null {
	const domain = sender.toLowerCase().split("@").at(-1) ?? "";
	return /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$/.test(
		domain,
	)
		? domain
		: null;
}

export function safeEvidenceURL(value: string): string | null {
	try {
		const url = new URL(value);
		if (url.protocol !== "https:" || url.username || url.password) return null;
		return url.href;
	} catch {
		return null;
	}
}
