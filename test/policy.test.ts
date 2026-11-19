import assert from "node:assert/strict";
import { createHmac, webcrypto } from "node:crypto";
import { test } from "node:test";
import {
	automationAction,
	HARDCODED_BAN,
	isRequest,
	OWNER,
	usableMailbox,
	verifySlack,
} from "../src/policy";

if (!globalThis.crypto)
	Object.defineProperty(globalThis, "crypto", { value: webcrypto });

test("only the mailbox command is accepted; quotes and instructions do not trigger creation", () => {
	assert.equal(isRequest(" GiB email! "), true);
	for (const input of [
		"please gib email",
		"gib email for a free trial",
		"don't gib email",
		"gib email\n@someone",
		undefined,
	])
		assert.equal(isRequest(input), false);
});

test("expired, revoked or banned mailboxes cannot receive mail", () => {
	assert.equal(
		usableMailbox({ expires_at: 101, revoked: 0 }, false, 100),
		true,
	);
	assert.equal(
		usableMailbox({ expires_at: 100, revoked: 0 }, false, 100),
		false,
	);
	assert.equal(
		usableMailbox({ expires_at: 101, revoked: 1 }, false, 100),
		false,
	);
	assert.equal(
		usableMailbox({ expires_at: 101, revoked: 0 }, true, 100),
		false,
	);
	assert.equal(usableMailbox(undefined, false, 100), false);
});

test("verified automation bans its actor, with only the configured owner exempt", () => {
	assert.equal(automationAction(OWNER, true), "allow");
	assert.equal(automationAction("UOTHERUSER", true), "ban");
	assert.equal(automationAction("UOTHERUSER", false), "allow");
	assert.equal(HARDCODED_BAN, "U085KKYFA6Q");
});

test("Slack signatures bind the complete body and reject old or malformed requests", async () => {
	const now = 1795040000000;
	const ts = String(now / 1000);
	const body = '{"text":"gib email"}';
	const secret = "synthetic-test-secret";
	const sig = `v0=${createHmac("sha256", secret).update(`v0:${ts}:${body}`).digest("hex")}`;
	assert.equal(await verifySlack(body, ts, sig, secret, now), true);
	assert.equal(await verifySlack(`${body} `, ts, sig, secret, now), false);
	assert.equal(await verifySlack(body, ts, sig, secret, now + 301000), false);
	assert.equal(await verifySlack(body, ts, "v0=invalid", secret, now), false);
});
