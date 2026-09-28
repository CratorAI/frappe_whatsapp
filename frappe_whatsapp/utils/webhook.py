"""Webhook."""
import frappe
import json
import requests
import time
import traceback
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
	# Read the secret from the URL QUERY STRING ONLY. frappe.form_dict merges POST body
	# fields, so a caller whose body happens to contain a "secret" key (relay-provider
	# verification probes do) would SHADOW the URL secret and fail the comparison.
	presented = ""
	if getattr(frappe.request, "args", None) is not None:
		presented = frappe.request.args.get("secret") or ""
	if not presented:
		presented = frappe.form_dict.get("secret") or ""
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
	value = {}
	try:
		value = data["entry"][0]["changes"][0]["value"]
		messages = value.get("messages", [])
		# Coexistence: messages the owner sends from the WhatsApp Business app on
		# the phone arrive as echoes. Observed wire key is `message_echoes`
		# (Meta's docs call the subscription field `smb_message_echoes`).
		message_echoes = value.get("message_echoes", [])
		phone_id = value.get("metadata", {}).get("phone_number_id")
	except KeyError:
		try:
			value = data["entry"]["changes"][0]["value"]
			messages = value.get("messages", [])
			message_echoes = value.get("message_echoes", [])
		except (KeyError, TypeError, IndexError):
			# Not a Meta event envelope at all — relay-provider verification probes and
			# health checks POST arbitrary bodies. The raw payload is already in
			# WhatsApp Notification Log (above); acknowledge instead of 500ing, so
			# provider preflights pass and Meta never enters a redelivery loop.
			return
	except (TypeError, IndexError):
		return
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
			# Per-message isolation. One unhandled payload used to raise out of the
			# webhook, which (a) 500'd the whole batch so Meta redelivered it forever,
			# (b) dropped every other message in the same delivery, and (c) rolled back
			# the WhatsApp Notification Log row written above — destroying the only
			# copy of the raw payload. Now a bad message is logged and skipped alone.
			frappe.db.savepoint("wa_inbound_message")
			try:
				ingest_incoming_message(message, whatsapp_account, sender_profile_name)
			except Exception:
				frappe.db.rollback(save_point="wa_inbound_message")
				log_webhook_failure("WhatsApp inbound message failed", message)

	else:
		changes = None
		try:
			changes = data["entry"][0]["changes"][0]
		except KeyError:
			changes = data["entry"]["changes"][0]
		update_status(changes)
	return

# Options of WhatsApp Message.content_type. Anything else must be mapped onto one of
# these before insert, or the Select validation throws and the message is lost.
CONTENT_TYPES = (
	"text", "document", "image", "video", "audio", "flow", "reaction",
	"location", "contact", "button", "interactive", "order",
)
MEDIA_TYPES = ("image", "audio", "video", "document", "sticker")


def sender_of(message):
	"""The customer's identity. Username-only WhatsApp users (no phone number on the
	account) arrive with `from_user_id` and NO `from` key — indexing `message['from']`
	raised KeyError and silently lost their messages."""
	return message.get("from") or message.get("from_user_id")


def log_webhook_failure(title, payload, detail=None):
	"""Log without Frappe's traceback-with-variables. That dump captures the request
	object, whose URL carries the ?secret= used to authenticate this guest endpoint —
	so every crash was writing the live webhook secret into Error Log."""
	body = detail or traceback.format_exc()
	try:
		summary = json.dumps(payload, default=str)[:3000]
	except Exception:
		summary = str(payload)[:3000]
	frappe.log_error(title=title, message=f"{body}\n\npayload:\n{summary}")


def ingest_incoming_message(message, whatsapp_account, sender_profile_name):
	"""Record one inbound message. Raises on genuinely malformed payloads; the caller
	isolates each message in its own savepoint."""
	message_type = message.get("type")
	message_id = message.get("id")

	# Meta redelivers a webhook until it gets a 200, so a delivery that previously
	# failed can arrive again. The echo path already dedupes; inbound now does too.
	if message_id and frappe.db.exists("WhatsApp Message", {"message_id": message_id}):
		return

	sender = sender_of(message)
	context = message.get("context") or {}
	is_reply = True if context and "forwarded" not in context else False
	reply_to_message_id = context.get("id") if is_reply else None

	def insert(**fields):
		doc = {
			"doctype": "WhatsApp Message",
			"type": "Incoming",
			"from": sender,
			"message_id": message_id,
			"profile_name": sender_profile_name,
			"whatsapp_account": whatsapp_account.name,
		}
		doc.update(fields)
		return frappe.get_doc(doc).insert(ignore_permissions=True)

	if message_type == "text":
		insert(
			message=message["text"]["body"],
			reply_to_message_id=reply_to_message_id,
			is_reply=is_reply,
			content_type="text",
		)

	elif message_type == "reaction":
		reaction = message.get("reaction") or {}
		# A reaction with no emoji is the customer REMOVING their reaction. Nothing to
		# record — and indexing ['emoji'] used to raise.
		if not reaction.get("emoji"):
			return
		insert(
			message=reaction["emoji"],
			reply_to_message_id=reaction.get("message_id"),
			content_type="reaction",
		)

	elif message_type == "interactive":
		interactive_data = message["interactive"]
		interactive_type = interactive_data.get("type")
		if interactive_type == "button_reply":
			insert(
				message=interactive_data["button_reply"]["id"],
				reply_to_message_id=reply_to_message_id,
				is_reply=is_reply,
				content_type="button",
			)
		elif interactive_type == "list_reply":
			insert(
				message=interactive_data["list_reply"]["id"],
				reply_to_message_id=reply_to_message_id,
				is_reply=is_reply,
				content_type="button",
			)
		elif interactive_type == "nfm_reply":
			nfm_reply = interactive_data["nfm_reply"]
			try:
				flow_response = json.loads(nfm_reply.get("response_json", "{}"))
			except json.JSONDecodeError:
				flow_response = {}
			summary_parts = [f"{key}: {value}" for key, value in flow_response.items() if value]
			insert(
				message=", ".join(summary_parts) if summary_parts else "Flow completed",
				reply_to_message_id=reply_to_message_id,
				is_reply=is_reply,
				content_type="flow",
				flow_response=json.dumps(flow_response),
			)
			frappe.publish_realtime(  # nosemgrep: frappe-realtime-pick-room -- intentional site-wide fan-out for chat UIs (whatsapp_chat companion app) listening for inbound flow responses
				"whatsapp_flow_response",
				{
					"phone": sender,
					"message_id": message_id,
					"flow_response": flow_response,
					"whatsapp_account": whatsapp_account.name,
				},
			)

	elif message_type == "order":
		insert(
			message=_("New Order Received via WhatsApp"),
			content_type="order",
			product_catalog_json=json.dumps(message["order"]),
		)

	elif message_type in MEDIA_TYPES:
		ingest_incoming_media(message, message_type, insert, reply_to_message_id, is_reply, whatsapp_account)

	elif message_type == "button":
		insert(
			message=message["button"]["text"],
			reply_to_message_id=reply_to_message_id,
			is_reply=is_reply,
			content_type="button",
		)

	elif message_type == "edit":
		# The customer edited a message they already sent. Update that message in
		# place rather than recording the edit as a separate new message.
		edit = message.get("edit") or {}
		new_message = edit.get("message") or {}
		new_text = (new_message.get("text") or {}).get("body")
		if new_text is None:
			new_text = f"[edited {new_message.get('type') or 'message'}]"
		original = frappe.db.get_value(
			"WhatsApp Message", {"message_id": edit.get("original_message_id")}, "name"
		)
		if original:
			frappe.db.set_value("WhatsApp Message", original, "message", f"{new_text} (edited)")
		else:
			insert(message=f"{new_text} (edited)", content_type="text")

	elif message_type == "revoke":
		# The customer deleted a message on WhatsApp. The copy already recorded here is
		# kept as-is (it is the business's record of what was received); nothing new
		# to insert.
		return

	elif message_type == "unsupported":
		insert(
			message="[Unsupported message type — open it on the phone]",
			content_type="text",
		)

	else:
		payload = message.get(message_type)
		body = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload or f"[{message_type}]")
		insert(
			message=body,
			content_type=message_type if message_type in CONTENT_TYPES else "text",
		)


def ingest_incoming_media(message, message_type, insert, reply_to_message_id, is_reply, whatsapp_account):
	"""Record an inbound image/audio/video/document/sticker.

	The message is saved FIRST, then the file is fetched. Previously both media-API
	calls had to return 200 before anything was written, with no else branch — so any
	download failure discarded the message, its caption and every trace of it. Not a
	single inbound media message had ever reached this site.
	"""
	media = message.get(message_type) or {}
	caption = media.get("caption", "")
	if not caption and message_type == "sticker":
		caption = "[sticker]"
	doc = insert(
		message=caption,
		reply_to_message_id=reply_to_message_id,
		is_reply=is_reply,
		# Stickers are webp images; content_type has no sticker option.
		content_type="image" if message_type == "sticker" else message_type,
	)

	file_data, file_extension, failure = download_inbound_media(media, whatsapp_account)
	if failure:
		if not caption:
			doc.db_set("message", f"[{message_type} received — could not be downloaded]")
		log_webhook_failure(
			"WhatsApp inbound media download failed",
			{
				"message_id": message.get("id"),
				"type": message_type,
				"media_id": media.get("id"),
				"mime_type": media.get("mime_type"),
				# Whether the payload itself carried a direct download link — the
				# deciding fact for how downloads should be fetched.
				"payload_has_url": bool(media.get("url")),
			},
			detail=failure,
		)
		return

	file = frappe.get_doc({
		"doctype": "File",
		"file_name": f"{frappe.generate_hash(length=10)}.{file_extension}",
		"attached_to_doctype": "WhatsApp Message",
		"attached_to_name": doc.name,
		"content": file_data,
		"attached_to_field": "attach",
	}).save(ignore_permissions=True)
	doc.db_set("attach", file.file_url)


def download_inbound_media(media, whatsapp_account):
	"""Fetch an inbound media file. Returns (bytes, extension, None) on success or
	(None, None, reason) on failure — never raises, and the reason records the exact
	HTTP status and response so a failure can be diagnosed from Error Log."""
	media_id = media.get("id")
	if not media_id:
		return None, None, "payload carried no media id"
	token = whatsapp_account.get_password("token")
	headers = {"Authorization": "Bearer " + token}
	lookup_url = f"{whatsapp_account.url}/{whatsapp_account.version}/{media_id}/"

	try:
		response = requests.get(lookup_url, headers=headers, timeout=30)
	except requests.RequestException as e:
		return None, None, f"media lookup request failed: {lookup_url}: {e!r}"
	if response.status_code != 200:
		return None, None, (
			f"media lookup returned HTTP {response.status_code} from {lookup_url}\n"
			f"body: {response.text[:1500]}"
		)

	try:
		media_data = response.json()
	except ValueError:
		return None, None, f"media lookup returned non-JSON from {lookup_url}: {response.text[:1500]}"
	media_url = media_data.get("url")
	mime_type = media_data.get("mime_type") or media.get("mime_type") or ""
	file_extension = (mime_type.split("/")[1].split(";")[0] if "/" in mime_type else "bin") or "bin"
	if not media_url:
		return None, None, f"media lookup response had no url: {json.dumps(media_data)[:1500]}"

	try:
		media_response = requests.get(media_url, headers=headers, timeout=60)
	except requests.RequestException as e:
		return None, None, f"media download request failed: {media_url[:200]}: {e!r}"
	if media_response.status_code != 200:
		return None, None, (
			f"media download returned HTTP {media_response.status_code} from {media_url[:200]}\n"
			f"body: {media_response.text[:1500]}"
		)
	return media_response.content, file_extension, None


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
		# Username-only recipients have no phone number: Meta sends `to_user_id`
		# instead of `to`. A missing `to` crashed the profile lookup (None.startswith).
		"to": echo.get("to") or echo.get("to_user_id"),
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
