const $ = (id) => document.getElementById(id);
let state = null;
let settingsDirty = false;
let messageRequest = 0;
let codexExpiresAt = null;
let codexBusy = false;
const views = {
	inbox: ["Inbox", "Incoming mail across temporary addresses."],
	mailboxes: ["Mailboxes", "24-hour addresses and their current status."],
	bans: ["Bans", "Manage access and inspect enforcement decisions."],
	audits: ["Audit log", "A record of what happened and who was involved."],
	reviews: ["Reviews", "Automated abuse detection, with an audit trail."],
	settings: [
		"Setup & settings",
		"Private credentials and workspace configuration.",
	],
};
function node(tag, text, className) {
	const result = document.createElement(tag);
	if (text !== undefined) result.textContent = String(text ?? "—");
	if (className) result.className = className;
	return result;
}
function date(value) {
	const parsed = new Date(value);
	return value != null && Number.isFinite(parsed.getTime())
		? parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })
		: "—";
}
function detail(value) {
	return typeof value === "object" && value !== null
		? JSON.stringify(value)
		: value;
}
function badge(text) {
	return node("span", text, "badge");
}
function table(target, headers, rows, empty) {
	const host = $(target);
	host.replaceChildren();
	if (!rows.length) {
		host.append(node("p", empty, "empty"));
		return;
	}
	const element = node("table");
	element.setAttribute("aria-label", headers.join(", "));
	const head = node("thead");
	const heading = node("tr");
	for (const title of headers) {
		const cell = node("th", title);
		cell.scope = "col";
		heading.append(cell);
	}
	head.append(heading);
	const body = node("tbody");
	for (const row of rows) {
		const tr = node("tr");
		for (const value of row) {
			const cell = node("td");
			cell.append(value instanceof Node ? value : node("span", value));
			tr.append(cell);
		}
		body.append(tr);
	}
	element.append(head, body);
	host.append(element);
}
async function api(path, body) {
	const response = await fetch(`/admin/api/${path}`, {
		credentials: "same-origin",
		cache: "no-store",
		...(body === undefined
			? {}
			: {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(body),
				}),
	});
	let result;
	try {
		result = await response.json();
	} catch {
		throw new Error(
			"The server did not return JSON. Your Access session may have expired; reload to sign in again.",
		);
	}
	if (!response.ok || result.error)
		throw new Error(
			result.error || `Request failed (${response.status}). Try again.`,
		);
	return result;
}
function notice(message, error = false) {
	$("notice").hidden = false;
	$("notice").className = error ? "notice error" : "notice";
	$("notice").textContent = message;
	$("notice").scrollIntoView({ block: "nearest" });
}
function navigate() {
	const key = Object.hasOwn(views, location.hash.slice(1))
		? location.hash.slice(1)
		: "inbox";
	for (const section of document.querySelectorAll(".view"))
		section.hidden = section.id !== key;
	for (const link of document.querySelectorAll("[data-view]")) {
		if (link.dataset.view === key) link.setAttribute("aria-current", "page");
		else link.removeAttribute("aria-current");
	}
	$("view-title").textContent = views[key][0];
	$("view-description").textContent = views[key][1];
	document.title = `${views[key][0]} — Meow Mail`;
}
function renderMail() {
	if (!state) return;
	const query = $("mail-search").value.trim().toLowerCase();
	const emails = state.emails.filter((email) =>
		[email.sender, email.recipient, email.subject].some((value) =>
			String(value ?? "")
				.toLowerCase()
				.includes(query),
		),
	);
	table(
		"email-list",
		["Subject / sender", "To", "Received", "Delivery"],
		emails.map((email) => {
			const group = node("div", undefined, "mail-subject");
			const button = node(
				"button",
				email.subject || "(No subject)",
				"text-button",
			);
			button.addEventListener("click", () => openMessage(email.id));
			group.append(button, node("span", email.sender, "muted"));
			return [
				group,
				email.recipient,
				date(email.received_at),
				badge(email.delivery_status),
			];
		}),
		query
			? "No messages match your search. Try another sender, recipient, or subject."
			: "No incoming mail yet. Messages will appear here after a Slack member creates an address and receives email.",
	);
}
function render() {
	for (const key of ["active", "emails", "bans"])
		$(`stat-${key}`).textContent = Number.isFinite(state.stats[key])
			? state.stats[key].toLocaleString()
			: "—";
	$("nav-count").textContent = state.emails.length.toLocaleString();
	$("service-status").textContent = state.config.enabled ? "Enabled" : "Paused";
	$("setup-banner").hidden = Boolean(
		state.config.slack &&
			state.config.channel &&
			state.config.tavily &&
			state.config.codex,
	);
	for (const key of ["slack", "tavily"])
		$(`credential-${key}`).textContent = state.config[key]
			? "Saved"
			: "Not configured";
	renderCodex();
	if (!settingsDirty) {
		$("channel").value = state.config.channel || "";
		$("enabled").checked = state.config.enabled;
	}
	renderMail();
	table(
		"mailbox-list",
		["Address", "Slack user", "Expires", "Status"],
		state.mailboxes.map((box) => [
			box.address,
			box.user_id,
			date(box.expires_at),
			badge(
				box.revoked
					? "Revoked"
					: box.expires_at <= Date.now()
						? "Expired"
						: "Active",
			),
		]),
		"No addresses yet. Members can request one in Slack once setup is complete and they accept the terms.",
	);
	table(
		"ban-list",
		["Slack user", "Reason", "Source", "Created", "Action"],
		state.bans.map((ban) => {
			const action = ban.hardcoded
				? badge("Protected")
				: node("button", "Unban", "small-button");
			if (!ban.hardcoded)
				action.addEventListener("click", () => {
					if (confirm(`Restore Meow Mail access for ${ban.user_id}?`))
						perform(
							action,
							"unban",
							{ user_id: ban.user_id },
							"User unbanned.",
						);
				});
			return [
				ban.user_id,
				ban.reason,
				ban.source,
				date(ban.created_at),
				action,
			];
		}),
		"No banned users.",
	);
	table(
		"audit-list",
		["Event", "Slack user", "Detail", "Time"],
		state.audits.map((audit) => [
			badge(audit.kind),
			audit.user_id,
			detail(audit.detail),
			date(audit.created_at),
		]),
		"No audit events yet. Activity will be recorded here.",
	);
	table(
		"review-list",
		["Status", "Summary", "Time"],
		state.reviews.map((review) => [
			badge(review.status),
			review.summary || "No summary yet.",
			date(review.created_at),
		]),
		"No reviews yet. Save a Tavily key and connect Codex, then run a review or wait for the daily schedule.",
	);
}
async function refresh() {
	const button = $("refresh");
	button.disabled = true;
	button.textContent = "Refreshing…";
	try {
		const result = await api("state");
		if (
			!result.config ||
			!result.stats ||
			!["emails", "mailboxes", "bans", "audits", "reviews"].every((key) =>
				Array.isArray(result[key]),
			)
		)
			throw new Error(
				"The server returned an unexpected state. Reload or contact the operator.",
			);
		state = result;
		render();
		$("load-error").hidden = true;
		$("last-updated").textContent =
			`Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
	} catch (error) {
		$("load-error").hidden = false;
		$("load-error").textContent =
			`${error.message} ${state ? "Showing previously loaded data." : "Use Refresh to retry."}`;
		if (!state) {
			$("service-status").textContent = "Unavailable";
			for (const id of [
				"email-list",
				"mailbox-list",
				"ban-list",
				"audit-list",
				"review-list",
			])
				$(id).replaceChildren(node("p", "Data could not be loaded.", "empty"));
		}
	} finally {
		button.disabled = false;
		button.textContent = "Refresh";
	}
}
async function perform(button, path, body, success, onSuccess) {
	const original = button.textContent;
	button.disabled = true;
	button.textContent = "Working…";
	try {
		await api(path, body);
		onSuccess?.();
		notice(success);
		await refresh();
	} catch (error) {
		notice(
			`${error.message} The request may have reached the server. Refresh and verify before retrying.`,
			true,
		);
	} finally {
		button.disabled = false;
		button.textContent = original;
	}
}
async function openMessage(id) {
	const request = ++messageRequest;
	$("message-content").replaceChildren(node("p", "Loading message…", "muted"));
	if (!$("message-dialog").open) $("message-dialog").showModal();
	try {
		const mail = await api(`email?id=${encodeURIComponent(id)}`);
		if (request !== messageRequest) return;
		const info = node("dl", undefined, "message-meta");
		for (const [label, value] of [
			["From", mail.sender],
			["To", mail.recipient],
			["Subject", mail.subject || "(No subject)"],
			["Received", date(mail.received_at)],
		])
			info.append(node("dt", label), node("dd", value));
		$("message-content").replaceChildren(
			info,
			node("pre", mail.body || "(Empty message)", "message-body"),
		);
	} catch (error) {
		if (request === messageRequest)
			$("message-content").replaceChildren(
				node("p", error.message, "notice error"),
			);
	}
}
$("close-message").addEventListener("click", () => $("message-dialog").close());
$("message-dialog").addEventListener("close", () => {
	messageRequest++;
	$("message-content").replaceChildren();
});
$("refresh").addEventListener("click", refresh);
$("mail-search").addEventListener("input", renderMail);
$("config-form").addEventListener("input", () => {
	settingsDirty = true;
});
$("config-form").addEventListener("submit", (event) => {
	event.preventDefault();
	const body = {
		channel: $("channel").value.trim(),
		enabled: $("enabled").checked,
	};
	for (const name of ["slackToken", "slackSigningSecret", "tavilyKey"]) {
		const value = event.currentTarget.elements.namedItem(name).value.trim();
		if (value) body[name] = value;
	}
	const firstEnable = body.enabled && state && !state.config.enabled;
	perform(
		event.currentTarget.querySelector('[type="submit"]'),
		"config",
		body,
		firstEnable
			? "Settings saved. Welcome announcement and ban-list pin queued. Secret fields have been cleared."
			: "Settings saved. Secret fields have been cleared.",
		() => {
			for (const input of $("config-form").querySelectorAll(
				'[type="password"]',
			))
				input.value = "";
			settingsDirty = false;
		},
	);
});
$("ban-form").addEventListener("submit", (event) => {
	event.preventDefault();
	const user_id = $("ban-user").value.trim();
	const reason = $("ban-reason").value.trim();
	if (!user_id || !reason) {
		notice("Enter a Slack user ID and a reason.", true);
		return;
	}
	if (confirm(`Ban ${user_id} from Meow Mail?`))
		perform(
			event.currentTarget.querySelector("button"),
			"ban",
			{ user_id, reason },
			"User banned.",
			() => $("ban-form").reset(),
		);
});
$("run-review").addEventListener("click", (event) =>
	perform(
		event.currentTarget,
		"review",
		{},
		"Review requested. It runs asynchronously; refresh shortly to see progress.",
	),
);
$("announce").addEventListener("click", (event) => {
	if (settingsDirty) {
		notice("Save your settings before posting the welcome.", true);
		return;
	}
	if (
		confirm(
			"Post or update the pinned welcome in the configured Slack channel?",
		)
	)
		perform(
			event.currentTarget,
			"announce",
			{},
			"Welcome announcement updated in Slack.",
		);
});
function renderCodex() {
	const connected = Boolean(state?.config.codex);
	$("credential-codex").textContent = state
		? connected
			? "Connected"
			: "Not connected"
		: "Checking…";
	$("codex-connect").textContent = connected
		? "Reconnect Codex"
		: "Connect Codex";
	$("codex-connect").disabled = codexBusy;
	$("codex-disconnect").disabled = codexBusy || (!connected && !codexExpiresAt);
	$("codex-complete").disabled = codexBusy || !codexExpiresAt;
}
function clearCodexFlow() {
	codexExpiresAt = null;
	$("codex-flow").hidden = true;
	$("codex-authorize").removeAttribute("href");
	$("codex-callback").value = "";
	$("codex-expiry").textContent = "";
}
async function codexAction(action) {
	if (codexBusy) return;
	codexBusy = true;
	renderCodex();
	try {
		await action();
	} catch {
		$("codex-status").textContent =
			"Connection request failed. Refresh to verify connection status, then start a fresh flow if needed.";
		notice(
			"Codex connection request failed or expired. The request may have reached the server. Refresh and verify before starting again. Never share the private callback URL in this thread.",
			true,
		);
	} finally {
		codexBusy = false;
		renderCodex();
	}
}
$("codex-connect").addEventListener("click", () =>
	codexAction(async () => {
		clearCodexFlow();
		$("codex-status").textContent = "Starting a private browser connection…";
		const result = await api("codex/start", {});
		const authorization = new URL(result.authorization_url);
		if (
			authorization.origin !== "https://auth.openai.com" ||
			authorization.pathname !== "/oauth/authorize" ||
			authorization.username ||
			authorization.password ||
			authorization.hash ||
			authorization.searchParams.get("redirect_uri") !==
				"http://localhost:1455/auth/callback" ||
			!Number.isFinite(result.expires_at) ||
			result.expires_at <= Date.now()
		)
			throw new Error(
				"The server returned an invalid Codex authorization response.",
			);
		codexExpiresAt = result.expires_at;
		$("codex-authorize").href = authorization.href;
		$("codex-expiry").textContent =
			`Complete this fresh 10-minute flow by ${date(result.expires_at)}.`;
		$("codex-flow").hidden = false;
		$("codex-status").textContent =
			"Open OpenAI sign-in, then paste the full localhost callback URL here. No address or bot activation has been performed.";
	}),
);
$("codex-complete-form").addEventListener("submit", (event) => {
	event.preventDefault();
	const callback_url = $("codex-callback").value.trim();
	$("codex-callback").value = "";
	if (codexBusy) return;
	codexAction(async () => {
		if (!codexExpiresAt || Date.now() >= codexExpiresAt) {
			clearCodexFlow();
			$("codex-status").textContent =
				"Browser flow expired. Connect again to start a fresh 10-minute flow.";
			return;
		}
		const callback = new URL(callback_url);
		if (
			callback.origin !== "http://localhost:1455" ||
			callback.pathname !== "/auth/callback" ||
			callback.username ||
			callback.password ||
			callback.hash
		)
			throw new Error(
				"Paste the full localhost callback URL from the OpenAI sign-in tab.",
			);
		clearCodexFlow();
		await api("codex/complete", { callback_url });
		if (state) state.config.codex = true;
		$("codex-status").textContent =
			"Codex connected. Save your Tavily key and other settings before enabling service.";
		await refresh();
	});
});
$("codex-disconnect").addEventListener("click", () => {
	if (!confirm("Disconnect Codex and pause new mail addresses?")) return;
	codexAction(async () => {
		clearCodexFlow();
		await api("codex/disconnect", {});
		if (state) {
			state.config.codex = false;
			state.config.enabled = false;
		}
		$("enabled").checked = false;
		$("codex-status").textContent =
			"Codex disconnected and mail service paused. Reconnect before enabling service again.";
		await refresh();
	});
});
window.addEventListener("hashchange", navigate);
navigate();
refresh();
