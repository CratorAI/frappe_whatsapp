"""Webhook."""
import frappe
import json
import requests
import time
from frappe import _
from werkzeug.wrappers import Response
import frappe.utils

from frappe_whatsapp.utils import get_whatsapp_account


@frappe.whitelist(allow_guest=True)
def webhook():
	"""Meta webhook."""
	require_inbound_secret()
	if frappe.request.method == "GET":
		return get()
	return post()


def require_inbound_secret():
	"""Site-level inbound auth for the guest webhook.

	When the site cannot validate Meta's X-Hub-Signature-256 (e.g. the WABA lives
	under a relay provider's Meta app, so we never hold the app secret), the only
	caller authentication available is a secret embedded in the registered callback
	URL: .../webhook?secret=<value>. Meta and Graph-compatible relays call the
	registered URL verbatim (query string preserved, on the verification GET too).

	Enforcement: if ANY WhatsApp Account defines an Inbound Webhook Secret, every
	request must present a secret matching one of them. Sites with no secrets
	configured behave exactly as upstream (no check).
	"""
	import hmac

	accounts = frappe.get_all("WhatsApp Account", pluck="name")
	secrets = []
	for name in accounts:
		try:
			value = frappe.utils.password.get_decrypted_password(
				"WhatsApp Account", name, "inbound_secret", raise_exception=False
			)
		except Exception:
			value = None
		if value:
			secrets.append(value)
	if not secrets:
		return
	presented = frappe.form_dict.get("secret") or frappe.request.args.get("secret") or ""
	if not any(hmac.compare_digest(presented, s) for s in secrets):
		frappe.throw("Invalid webhook secret", frappe.PermissionError)


def get():
	"""Get."""
	hub_challenge = frappe.form_dict.get("hub.challenge")
	verify_token = frappe.form_dict.get("hub.verify_token")
	webhook_verify_token = frappe.db.get_value(
		'WhatsApp Account',
		{"webhook_verify_token": verify_token},
		'webhook_verify_token'
	)
	if not webhook_verify_token:
		frappe.throw("No matching WhatsApp account")

	if frappe.form_dict.get("hub.verify_token") != webhook_verify_token:
		frappe.throw("Verify token does not match")

	return Response(hub_challenge, status=200)

def post():
	"""Post."""
	data = frappe.local.form_dict
	frappe.get_doc({
		"doctype": "WhatsApp Notification Log",
		"template": "Webhook",
		"meta_data": json.dumps(data)
	}).insert(ignore_permissions=True)

	messages = []
	message_echoes = []
	phone_id = None
	try:
		value = data["entry"][0]["changes"][0]["value"]
		messages = value.get("messages", [])
		# Coexistence: messages the owner sends from the WhatsApp Business app on
		# the phone arrive as echoes. Observed wire key is `message_echoes`
		# (Meta's docs call the subscription field `smb_message_echoes`).
		message_echoes = value.get("message_echoes", [])
		phone_id = value.get("metadata", {}).get("phone_number_id")
	except KeyError:
		value = data["entry"]["changes"][0]["value"]
		messages = value.get("messages", [])
		message_echoes = value.get("message_echoes", [])
	sender_profile_name = next(
		(
			contact.get("profile", {}).get("name")
			for entry in data.get("entry", [])
			for change in entry.get("changes", [])
			for contact in change.get("value", {}).get("contacts", [])
		),
		None,
	)

	whatsapp_account = get_whatsapp_account(phone_id) if phone_id else None

	# Only `messages` events carry `metadata.phone_number_id`. Status-change
	# events (`message_template_status_update`, message status callbacks) have
	# no metadata, so `phone_id` is None and `whatsapp_account` is also None
	# for them by design. Gating the entire handler on `whatsapp_account`
	# silently drops every template-status update; gate only the message-
	# ingestion branch instead.
	if (messages or message_echoes) and not whatsapp_account:
		return

	for echo in message_echoes:
		create_echo_message(echo, whatsapp_account)

	# Coexistence chat-history sync: delivered once around QR onboarding as `history`
	# chunks. Parsed defensively — the raw payload is already in WhatsApp Notification
	# Log (inserted above), so anything this parser skips remains recoverable.
	history_chunks = value.get("history") if isinstance(value, dict) else None
	if history_chunks:
		account = whatsapp_account or get_whatsapp_account(account_type="incoming")
		business_number = (value.get("metadata") or {}).get("display_phone_number", "")
		if account:
			import_history_chunks(history_chunks, account, business_number)

	if messages:
		for message in messages:
			message_type = message['type']
			is_reply = True if message.get('context') and 'forwarded' not in message.get('context') else False
			reply_to_message_id = message['context']['id'] if is_reply else None
			if message_type == 'text':
				frappe.get_doc({
					"doctype": "WhatsApp Message",
					"type": "Incoming",
					"from": message['from'],
					"message": message['text']['body'],
					"message_id": message['id'],
					"reply_to_message_id": reply_to_message_id,
					"is_reply": is_reply,
					"content_type":message_type,
					"profile_name":sender_profile_name,
					"whatsapp_account":whatsapp_account.name
				}).insert(ignore_permissions=True)
			elif message_type == 'reaction':
				frappe.get_doc({
					"doctype": "WhatsApp Message",
					"type": "Incoming",
					"from": message['from'],
					"message": message['reaction']['emoji'],
					"reply_to_message_id": message['reaction']['message_id'],
					"message_id": message['id'],
					"content_type": "reaction",
					"profile_name":sender_profile_name,
					"whatsapp_account":whatsapp_account.name
				}).insert(ignore_permissions=True)
			elif message_type == 'interactive':
				interactive_data = message['interactive']
				interactive_type = interactive_data.get('type')

				# Handle button reply
				if interactive_type == 'button_reply':
					frappe.get_doc({
						"doctype": "WhatsApp Message",
						"type": "Incoming",
						"from": message['from'],
						"message": interactive_data['button_reply']['id'],
						"message_id": message['id'],
						"reply_to_message_id": reply_to_message_id,
						"is_reply": is_reply,
						"content_type": "button",
						"profile_name": sender_profile_name,
						"whatsapp_account": whatsapp_account.name
					}).insert(ignore_permissions=True)
				# Handle list reply
				elif interactive_type == 'list_reply':
					frappe.get_doc({
						"doctype": "WhatsApp Message",
						"type": "Incoming",
						"from": message['from'],
						"message": interactive_data['list_reply']['id'],
						"message_id": message['id'],
						"reply_to_message_id": reply_to_message_id,
						"is_reply": is_reply,
						"content_type": "button",
						"profile_name": sender_profile_name,
						"whatsapp_account": whatsapp_account.name
					}).insert(ignore_permissions=True)
				# Handle WhatsApp Flows (nfm_reply)
				elif interactive_type == 'nfm_reply':
					nfm_reply = interactive_data['nfm_reply']
					response_json_str = nfm_reply.get('response_json', '{}')

					# Parse the response JSON
					try:
						flow_response = json.loads(response_json_str)
					except json.JSONDecodeError:
						flow_response = {}

					# Create a summary message from the flow response
					summary_parts = []
					for key, value in flow_response.items():
						if value:
							summary_parts.append(f"{key}: {value}")
					summary_message = ", ".join(summary_parts) if summary_parts else "Flow completed"

					msg_doc = frappe.get_doc({
						"doctype": "WhatsApp Message",
						"type": "Incoming",
						"from": message['from'],
						"message": summary_message,
						"message_id": message['id'],
						"reply_to_message_id": reply_to_message_id,
						"is_reply": is_reply,
						"content_type": "flow",
						"flow_response": json.dumps(flow_response),
						"profile_name": sender_profile_name,
						"whatsapp_account": whatsapp_account.name
					}).insert(ignore_permissions=True)

					# Publish realtime event for flow response
					frappe.publish_realtime(  # nosemgrep: frappe-realtime-pick-room -- intentional site-wide fan-out for chat UIs (whatsapp_chat companion app) listening for inbound flow responses
						"whatsapp_flow_response",
						{
							"phone": message['from'],
							"message_id": message['id'],
							"flow_response": flow_response,
							"whatsapp_account": whatsapp_account.name
						}
					)
			# NEW: Handle Shopping Cart / Orders from MPM
			elif message_type == 'order':
				order_data = message['order']

				# Inject the raw data into product_catalog_json
				frappe.get_doc({
					"doctype": "WhatsApp Message",
					"type": "Incoming",
					"from": message['from'],
					"message": _("New Order Received via WhatsApp"),
					"message_id": message['id'],
					"content_type": "order",
					"profile_name": sender_profile_name,
					"whatsapp_account": whatsapp_account.name,
					"product_catalog_json": json.dumps(order_data)
				}).insert(ignore_permissions=True)
			elif message_type in ["image", "audio", "video", "document"]:
				token = whatsapp_account.get_password("token")
				url = f"{whatsapp_account.url}/{whatsapp_account.version}/"

				media_id = message[message_type]["id"]
				headers = {
					'Authorization': 'Bearer ' + token

				}
				response = requests.get(f'{url}{media_id}/', headers=headers)

				if response.status_code == 200:
					media_data = response.json()
					media_url = media_data.get("url")
					mime_type = media_data.get("mime_type")
					file_extension = mime_type.split('/')[1]

					media_response = requests.get(media_url, headers=headers)
					if media_response.status_code == 200:

						file_data = media_response.content
						file_name = f"{frappe.generate_hash(length=10)}.{file_extension}"

						message_doc = frappe.get_doc({
							"doctype": "WhatsApp Message",
							"type": "Incoming",
							"from": message['from'],
							"message_id": message['id'],
							"reply_to_message_id": reply_to_message_id,
							"is_reply": is_reply,
							"message": message[message_type].get("caption", ""),
							"content_type" : message_type,
							"profile_name":sender_profile_name,
							"whatsapp_account":whatsapp_account.name
						}).insert(ignore_permissions=True)

						file = frappe.get_doc(
							{
								"doctype": "File",
								"file_name": file_name,
								"attached_to_doctype": "WhatsApp Message",
								"attached_to_name": message_doc.name,
								"content": file_data,
								"attached_to_field": "attach"
							}
						).save(ignore_permissions=True)


						message_doc.attach = file.file_url
						message_doc.save()
			elif message_type == "button":
				frappe.get_doc({
					"doctype": "WhatsApp Message",
					"type": "Incoming",
					"from": message['from'],
					"message": message['button']['text'],
					"message_id": message['id'],
					"reply_to_message_id": reply_to_message_id,
					"is_reply": is_reply,
					"content_type": message_type,
					"profile_name":sender_profile_name,
					"whatsapp_account":whatsapp_account.name
				}).insert(ignore_permissions=True)
			else:
				frappe.get_doc({
					"doctype": "WhatsApp Message",
					"type": "Incoming",
					"from": message['from'],
					"message_id": message['id'],
					"message": message[message_type].get(message_type),
					"content_type" : message_type,
					"profile_name":sender_profile_name,
					"whatsapp_account":whatsapp_account.name
				}).insert(ignore_permissions=True)

	else:
		changes = None
		try:
			changes = data["entry"][0]["changes"][0]
		except KeyError:
			changes = data["entry"]["changes"][0]
		update_status(changes)
	return

def import_history_chunks(chunks, whatsapp_account, business_number):
	"""Import coexistence history-sync chunks into WhatsApp Message rows.

	Per-message isolation: one malformed entry must not 500 the whole chunk (Meta
	redelivers the entire webhook on non-200, which would loop the batch forever).
	Original send time is preserved onto `creation` so threads keep true chronology.
	Direction: `from` == the business number → Outgoing via_phone; else Incoming.
	"""
	import datetime

	if not isinstance(chunks, list):
		chunks = [chunks]
	imported = skipped = failed = 0
	for chunk in chunks:
		threads = (chunk or {}).get("threads") or []
		for thread in threads:
			counterparty = str(thread.get("id") or "")
			for msg in thread.get("messages") or []:
				try:
					msg_id = msg.get("id")
					if not msg_id or frappe.db.exists("WhatsApp Message", {"message_id": msg_id}):
						skipped += 1
						continue
					sender = str(msg.get("from") or "")
					outgoing = business_number and sender.endswith(business_number[-8:])
					msg_type = msg.get("type", "text")
					if msg_type == "text":
						body = (msg.get("text") or {}).get("body", "")
					elif msg_type in ("image", "audio", "video", "document", "sticker"):
						body = (msg.get(msg_type) or {}).get("caption", "") or f"[{msg_type}]"
					else:
						payload = msg.get(msg_type)
						body = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload or f"[{msg_type}]")
					doc = frappe.get_doc({
						"doctype": "WhatsApp Message",
						"type": "Outgoing" if outgoing else "Incoming",
						"via_phone": 1 if outgoing else 0,
						"to": (counterparty or msg.get("to")) if outgoing else None,
						"from": None if outgoing else (sender or counterparty),
						"message": body,
						"message_id": msg_id,
						"content_type": msg_type if msg_type in ("text", "image", "audio", "video", "document", "flow") else "text",
						"status": "delivered" if outgoing else None,
						"whatsapp_account": whatsapp_account.name,
					})
					doc.insert(ignore_permissions=True)
					ts = msg.get("timestamp")
					if ts:
						original = datetime.datetime.utcfromtimestamp(int(ts))
						frappe.db.set_value(
							"WhatsApp Message", doc.name, "creation", original,
							update_modified=False,
						)
					imported += 1
				except Exception:
					failed += 1
					frappe.log_error(title="WhatsApp history import: message skipped")
	frappe.logger("frappe_whatsapp").info(
		f"history import: {imported} imported, {skipped} skipped (dupes), {failed} failed"
	)


def create_echo_message(echo, whatsapp_account):
	"""Record a coexistence echo: a message the owner sent from the WhatsApp
	Business app on the phone. type=Outgoing + via_phone=1 (which suppresses the
	controller's send path — the message already went out through the phone).

	Meta redelivers webhooks on retry, so dedupe on message_id.
	Media echoes are recorded with caption + content_type only (no media download
	in v1 — echoes carry a media id whose download semantics differ per provider).
	"""
	echo_type = echo.get("type", "text")
	if frappe.db.exists("WhatsApp Message", {"message_id": echo.get("id")}):
		return
	if echo_type == "text":
		body = echo.get("text", {}).get("body", "")
	elif echo_type in ("image", "audio", "video", "document", "sticker"):
		body = echo.get(echo_type, {}).get("caption", "") or f"[{echo_type} sent from phone]"
	else:
		payload = echo.get(echo_type)
		body = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload or f"[{echo_type}]")
	frappe.get_doc({
		"doctype": "WhatsApp Message",
		"type": "Outgoing",
		"via_phone": 1,
		"to": echo.get("to"),
		"message": body,
		"message_id": echo.get("id"),
		"content_type": echo_type if echo_type in ("text", "image", "audio", "video", "document", "flow") else "text",
		"status": "sent",
		"whatsapp_account": whatsapp_account.name,
	}).insert(ignore_permissions=True)


def update_status(data):
	"""Update status hook."""
	if data.get("field") == "message_template_status_update":
		update_template_status(data['value'])

	elif data.get("field") == "messages":
		update_message_status(data['value'])

def update_template_status(data):
	"""Update template status."""
	frappe.db.sql(
		"""UPDATE `tabWhatsApp Templates`
		SET status = %(event)s
		WHERE id = %(message_template_id)s""",
		data
	)

def update_message_status(data):
	"""Update message status."""
	id = data['statuses'][0]['id']
	status = data['statuses'][0]['status']
	conversation = data['statuses'][0].get('conversation', {}).get('id')
	name = frappe.db.get_value("WhatsApp Message", filters={"message_id": id})

	# Status callbacks can reference messages we hold no row for (sent before this
	# app was installed, echo-status races, other integrations on the same number).
	# Crashing here 500s the webhook and puts Meta into a retry storm — skip instead.
	if not name:
		return

	doc = frappe.get_doc("WhatsApp Message", name)
	doc.status = status
	if conversation:
		doc.conversation_id = conversation
	doc.save(ignore_permissions=True)
