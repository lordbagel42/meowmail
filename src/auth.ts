import { createRemoteJWKSet, jwtVerify } from "jose";
import { OWNER_EMAIL } from "./policy";

export async function isOwner(request: Request, env: Env): Promise<boolean> {
	const assertion = request.headers.get("cf-access-jwt-assertion");
	if (!assertion || !env.ACCESS_AUD) return false;
	try {
		const { payload } = await jwtVerify(
			assertion,
			createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`)),
			{
				issuer: env.ACCESS_ISSUER,
				audience: env.ACCESS_AUD,
				algorithms: ["RS256"],
			},
		);
		return payload.email === OWNER_EMAIL && typeof payload.sub === "string";
	} catch {
		return false;
	}
}

export async function encryptConfig(
	value: object,
	secret: string,
): Promise<string> {
	const key = await configKey(secret);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encrypted = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv },
			key,
			new TextEncoder().encode(JSON.stringify(value)),
		),
	);
	return JSON.stringify({ iv: Array.from(iv), data: Array.from(encrypted) });
}

export async function decryptConfig<T>(
	value: string,
	secret: string,
): Promise<T> {
	const { iv, data } = JSON.parse(value) as { iv: number[]; data: number[] };
	const plain = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: new Uint8Array(iv) },
		await configKey(secret),
		new Uint8Array(data),
	);
	return JSON.parse(new TextDecoder().decode(plain)) as T;
}

async function configKey(secret: string) {
	return crypto.subtle.importKey(
		"raw",
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret)),
		"AES-GCM",
		false,
		["encrypt", "decrypt"],
	);
}
