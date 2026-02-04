
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import re
import os
import logging
import requests
from functools import wraps

# ================= CONFIG =================

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_KEY = os.environ.get("API_KEY", "demo123")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

memory = {}

# ================= AUTH =================

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        key = request.headers.get("x-api-key")

        if not key or key != API_KEY:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        return f(*args, **kwargs)

    return wrapper


# ================= DETECTION =================

KEYWORDS = [
    "urgent", "otp", "bank", "upi", "account",
    "verify", "blocked", "payment", "click", "link"
]


def detect(text):

    score = 0

    for k in KEYWORDS:
        if k in text.lower():
            score += 1

    if score >= 3:
        return "Fraud", 95

    if score == 0:
        return "Safe", 80

    return "Unknown", 60


# ================= INTEL =================

def extract(text):

    intel = {
        "bankAccounts": re.findall(r"\b\d{9,18}\b", text),
        "upiIds": re.findall(r"\b[\w\.-]+@[\w\.-]+\b", text),
        "phishingLinks": re.findall(r"https?://\S+", text),
        "phoneNumbers": re.findall(r"(?:\+91)?[6-9]\d{9}", text),
        "suspiciousKeywords": []
    }

    for k in KEYWORDS:
        if k in text.lower():
            intel["suspiciousKeywords"].append(k)

    return intel


# ================= AI =================

def reply(text, history):

    text = text.lower()

    if "otp" in text:
        return "I just got an OTP. Is it safe to share?"

    if "bank" in text:
        return "Which bank is this?"

    if "click" in text:
        return "What happens if I click?"

    replies = [
        "Please explain again.",
        "I am confused.",
        "What should I do now?",
        "Can you help me?"
    ]

    return replies[len(history) % len(replies)]


# ================= HEALTH =================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy",
        "service": "Honeypot API",
        "time": datetime.utcnow().isoformat() + "Z"
    }), 200


# ================= MAIN API =================

@app.route("/api/analyze", methods=["POST"])
@require_api_key
def analyze():

    try:

        # Safe JSON read
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "message": "Invalid JSON body"
            }), 400

        logger.info(f"Incoming: {data}")

        # ---------------- Read message ----------------

        message = data.get("message", {})

        if not isinstance(message, dict):
            return jsonify({
                "status": "error",
                "message": "Invalid message format"
            }), 400

        text = message.get("text", "")
        sender = message.get("sender", "scammer")
        timestamp = message.get("timestamp")

        if not timestamp:
            timestamp = datetime.utcnow().isoformat() + "Z"

        if not text:
            return jsonify({
                "status": "error",
                "message": "Missing message.text"
            }), 400

        # ---------------- Session ----------------

        session_id = data.get("sessionId", "default")

        history = data.get("conversationHistory", [])

        if session_id not in memory:
            memory[session_id] = []

        # Save user msg
        user_msg = {
            "sender": sender,
            "text": text,
            "timestamp": timestamp
        }

        memory[session_id].append(user_msg)

        # ---------------- Process ----------------

        fraud, conf = detect(text)

        intel = extract(text)

        ai_reply = reply(text, history)

        # Save AI msg
        memory[session_id].append({
            "sender": "ai",
            "text": ai_reply,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        # ---------------- Callback ----------------

        if fraud == "Fraud" and (
            intel["upiIds"] or
            intel["bankAccounts"] or
            intel["phishingLinks"] or
            intel["phoneNumbers"]
        ):

            payload = {
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": len(memory[session_id]),
                "extractedIntelligence": intel,
                "agentNotes": "Scam detected via keyword + behavior"
            }

            try:
                requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
                logger.info("GUVI callback sent")

            except Exception as e:
                logger.error(f"Callback failed: {e}")

        # ---------------- Response ----------------

        return jsonify({
            "status": "success",
            "reply": ai_reply,
            "fraud_status": fraud,
            "confidence": conf,
            "extractedIntelligence": intel
        }), 200


    except Exception as e:

        logger.exception("Analyze error")

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ================= RUN =================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
