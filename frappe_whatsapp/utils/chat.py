"""Chat window API: conversations, threads, and sending.

Deliberately small and generic — per-business customization happens on top
(custom fields, doctype links, or downstream forks), not inside these queries.
"""
import frappe
from frappe import _


@frappe.whitelist()
def get_conversations(limit: int = 100):
	"""Distinct counterparties with their latest message, newest first."""
	frappe.has_permission("WhatsApp Message", "read", throw=True)
	rows = frappe.db.sql(
		"""
		SELECT counterparty, MAX(creation) AS last_time
		FROM (
			SELECT CASE WHEN type = 'Incoming' THEN `from` ELSE `to` END AS counterparty,
			       creation
			FROM `tabWhatsApp Message`
			WHERE COALESCE(CASE WHEN type = 'Incoming' THEN `from` ELSE `to` END, '') != ''
		) t
		GROUP BY counterparty
		ORDER BY last_time DESC
		LIMIT %(limit)s
		""",
		{"limit": int(limit)},
		as_dict=True,
	)
	for row in rows:
		last = frappe.db.get_value(
			"WhatsApp Message",
			{
				"creation": row.last_time,
			},
			["message", "type", "content_type", "via_phone", "profile_name"],
			as_dict=True,
		)
		row.update(last or {})
		row.profile_name = row.get("profile_name") or frappe.db.get_value(
			"WhatsApp Profiles", {"number": row.counterparty}, "profile_name"
		)
	return rows


@frappe.whitelist()
def get_thread(number: str, limit: int = 200):
	"""Full thread with one counterparty, oldest first (inbound + API-sent + phone echoes)."""
	frappe.has_permission("WhatsApp Message", "read", throw=True)
	return list(
		reversed(
			frappe.get_all(
				"WhatsApp Message",
				filters=[["WhatsApp Message", "content_type", "!=", ""]],
				or_filters=[["from", "=", number], ["to", "=", number]],
				fields=[
					"name", "type", "`from`", "`to`", "message", "content_type",
					"status", "via_phone", "attach", "creation", "profile_name",
				],
				order_by="creation desc",
				limit_page_length=int(limit),
			)
		)
	)


@frappe.whitelist()
def send_text(to: str, message: str):
	"""Send a free-form text (24h-window rules apply; errors surface verbatim)."""
	frappe.has_permission("WhatsApp Message", "create", throw=True)
	if not (to or "").strip() or not (message or "").strip():
		frappe.throw(_("Recipient and message are required"))
	doc = frappe.get_doc(
		{
			"doctype": "WhatsApp Message",
			"type": "Outgoing",
			"to": to.strip(),
			"message": message,
			"content_type": "text",
		}
	).insert(ignore_permissions=True)
	return {"name": doc.name, "status": doc.status}
