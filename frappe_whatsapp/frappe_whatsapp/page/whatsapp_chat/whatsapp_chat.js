// WhatsApp Chat — minimal two-pane conversation window over WhatsApp Message.
// Interleaves inbound, API-sent, and phone-sent (coexistence echo) messages.
// Kept deliberately small and DOM-simple so per-business variants can extend it.

frappe.pages["whatsapp-chat"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("WhatsApp Chat"),
		single_column: true,
	});
	const state = { current: null, conversations: [] };

	const $root = $(`
		<div class="wa-chat" style="display:flex;height:calc(100vh - 140px);border:1px solid var(--border-color);border-radius:8px;overflow:hidden">
			<div class="wa-list" style="width:280px;min-width:220px;border-right:1px solid var(--border-color);overflow-y:auto;background:var(--bg-color)"></div>
			<div class="wa-thread-wrap" style="flex:1;display:flex;flex-direction:column">
				<div class="wa-thread-header" style="padding:10px 14px;border-bottom:1px solid var(--border-color);font-weight:600"></div>
				<div class="wa-thread" style="flex:1;overflow-y:auto;padding:14px;background:var(--subtle-bg)"></div>
				<div class="wa-compose" style="display:flex;gap:8px;padding:10px;border-top:1px solid var(--border-color)">
					<input class="form-control wa-input" type="text" placeholder="${__("Type a message")}" style="flex:1">
					<button class="btn btn-primary wa-send">${__("Send")}</button>
				</div>
			</div>
		</div>`).appendTo(page.body);

	const esc = frappe.utils.escape_html;

	function fmt_time(ts) {
		return frappe.datetime.prettyDate ? frappe.datetime.prettyDate(ts) : ts;
	}

	function render_list() {
		const $list = $root.find(".wa-list").empty();
		state.conversations.forEach((c) => {
			const active = c.counterparty === state.current ? "background:var(--fg-hover-color);" : "";
			$(`
				<div class="wa-conv" data-number="${esc(c.counterparty)}" style="padding:10px 12px;cursor:pointer;border-bottom:1px solid var(--border-color);${active}">
					<div style="font-weight:600">${esc(c.profile_name || c.counterparty)}</div>
					<div class="text-muted" style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
						${c.type === "Incoming" ? "" : "→ "}${esc((c.message || "").replace(/<[^>]*>/g, "").slice(0, 48))}
					</div>
					<div class="text-muted" style="font-size:11px">${fmt_time(c.last_time)}</div>
				</div>`)
				.on("click", () => open_thread(c.counterparty))
				.appendTo($list);
		});
	}

	function bubble(m) {
		const mine = m.type === "Outgoing";
		const via = m.via_phone ? ` · ${__("from phone")}` : "";
		const status = mine && m.status ? ` · ${esc(m.status)}` : "";
		const body = m.content_type === "text" || !m.attach
			? esc((m.message || "").replace(/<[^>]*>/g, ""))
			: `<a href="${esc(m.attach)}" target="_blank">[${esc(m.content_type)}]</a> ${esc(m.message || "")}`;
		return `
			<div style="display:flex;justify-content:${mine ? "flex-end" : "flex-start"};margin-bottom:6px">
				<div style="max-width:70%;padding:8px 12px;border-radius:10px;
					background:${mine ? "var(--blue-100, #d1e7ff)" : "var(--bg-color, #fff)"};
					border:1px solid var(--border-color)">
					<div style="white-space:pre-wrap;word-break:break-word">${body}</div>
					<div class="text-muted" style="font-size:10px;margin-top:2px">${fmt_time(m.creation)}${via}${status}</div>
				</div>
			</div>`;
	}

	function open_thread(number) {
		state.current = number;
		render_list();
		const conv = state.conversations.find((c) => c.counterparty === number);
		$root.find(".wa-thread-header").text((conv && conv.profile_name) ? `${conv.profile_name} (${number})` : number);
		frappe.call("frappe_whatsapp.utils.chat.get_thread", { number }).then((r) => {
			const $t = $root.find(".wa-thread").empty();
			(r.message || []).forEach((m) => $t.append(bubble(m)));
			$t.scrollTop($t[0].scrollHeight);
		});
	}

	function refresh_conversations(then) {
		frappe.call("frappe_whatsapp.utils.chat.get_conversations").then((r) => {
			state.conversations = r.message || [];
			render_list();
			if (then) then();
		});
	}

	function send() {
		const $input = $root.find(".wa-input");
		const text = $input.val().trim();
		if (!text || !state.current) return;
		$input.val("").prop("disabled", true);
		frappe
			.call("frappe_whatsapp.utils.chat.send_text", { to: state.current, message: text })
			.then(() => open_thread(state.current))
			.catch((e) => frappe.msgprint({ title: __("Send failed"), message: e.message || String(e), indicator: "red" }))
			.always(() => $input.prop("disabled", false).focus());
	}

	$root.find(".wa-send").on("click", send);
	$root.find(".wa-input").on("keydown", (e) => {
		if (e.key === "Enter" && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	});

	frappe.realtime.on("whatsapp_message_new", (m) => {
		const other = m.type === "Incoming" ? m.from : m.to;
		refresh_conversations(() => {
			if (state.current && other === state.current) open_thread(state.current);
		});
	});

	refresh_conversations(() => {
		if (state.conversations.length) open_thread(state.conversations[0].counterparty);
	});
};
