
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import re
import logging
import requests
from functools import wraps

# ==================== APP SETUP ====================

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== CONFIG ====================

VALID_API_KEY = os.environ.get("API_KEY", "demo123")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

conversation_memory = {}

# ==================== AUTH ====================


def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        key = request.headers.get("x-api-key")

        if not key or key != VALID_API_KEY:
            return jsonify({
                "status": "error",
                "message": "Invalid API Key"
            }), 401

        return f(*args, **kwargs)

    return wrapper


# ==================== KEYWORDS ====================

SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp", "cvv",
    "bank", "upi", "transfer", "payment", "refund", "click",
    "link", "account", "expire", "immediately"
]


# ==================== SCAM DETECTOR ====================


def detect_scam(text):

    text = text.lower()

    score = 0

    for k in SCAM_KEYWORDS:
        if k in text:
            score += 1

    if score >= 3:
        return "Fraud", min(90 + score, 99)

    if score == 0:
        return "Safe", 80

    return "Unknown", 50


# ==================== INTEL EXTRACTION ====================


def extract_intelligence(text):

    intel = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }

    # UPI
    intel["upiIds"] = re.findall(r"\b[\w\.-]+@[\w\.-]+\b", text)

    # Phone
    intel["phoneNumbers"] = re.findall(r"(?:\+91)?[6-9]\d{9}", text)

    # URLs
    intel["phishingLinks"] = re.findall(r"https?://[^\s]+", text)

    # Bank numbers
    intel["bankAccounts"] = re.findall(r"\b\d{9,18}\b", text)

    # Keywords
    for k in SCAM_KEYWORDS:
        if k in text.lower():
            intel["suspiciousKeywords"].append(k)

    return intel


# ==================== AI REPLY ====================


def generate_ai_reply(text, history):

    text = text.lower()

    if "otp" in text:
        return "I just got an OTP. Is it safe to share?"

    if "bank" in text:
        return "Which bank are you calling from?"

    if "click" in text:
        return "What will happen if I click that?"

    if "payment" in text:
        return "How much money do I need to send?"

    replies = [
        "Can you explain again?",
        "I am confused. Please guide me.",
        "What should I do next?",
        "I don't understand this fully.",
        "Please help me."
    ]

    return replies[len(history) % len(replies)]


# ==================== GUVI CALLBACK ====================


def send_final_result(session_id, intel, total):

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total,
        "extractedIntelligence": intel,
        "agentNotes": "Used urgency and payment manipulation"
    }

    try:
        r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)

        logger.info(f"GUVI Callback: {r.status_code}")

    except Exception as e:

        logger.error(f"Callback Failed: {e}")


# ==================== HEALTH ====================


@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy",
        "service": "Scam Honeypot",
        "time": datetime.utcnow().isoformat() + "Z"
    }), 200


# ==================== MAIN API ====================


@app.route("/api/analyze", methods=["POST"])
@require_api_key
def analyze():

    try:

        # Get JSON safely
        data = request.get_json(silent=True)

        if data is None:
            data = {}

        logger.info(f"Incoming data: {data}")

        message_text = ""

        # Handle all formats
        if isinstance(data, dict):

            # { message: { text: "hi" } }
            if "message" in data and isinstance(data["message"], dict):
                message_text = data["message"].get("text", "")

            # { message: "hi" }
            elif "message" in data and isinstance(data["message"], str):
                message_text = data["message"]

            # { text: "hi" }
            elif "text" in data:
                message_text = data.get("text", "")

        # Fallback
        if not message_text:
            message_text = "Hello"

        session_id = data.get("sessionId", "default")

        history = data.get("conversationHistory", [])

        # Save user message
        user_msg = {
            "sender": "user",
            "text": message_text,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        if session_id not in conversation_memory:
            conversation_memory[session_id] = []

        conversation_memory[session_id].append(user_msg)

        # Detect scam
        fraud, confidence = detect_scam(message_text)

        # Extract intel
        intel = extract_intelligence(message_text)

        # AI reply
        reply = generate_ai_reply(message_text, history)

        # Save AI msg
        conversation_memory[session_id].append({
            "sender": "ai",
            "text": reply,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        # Callback if fraud
        if fraud == "Fraud" and (
            intel["upiIds"] or
            intel["bankAccounts"] or
            intel["phishingLinks"] or
            intel["phoneNumbers"]
        ):

            total = len(conversation_memory[session_id])

            send_final_result(session_id, intel, total)

        # FINAL RESPONSE
        return jsonify({
            "status": "success",
            "reply": reply,
            "fraud_status": fraud,
            "confidence": confidence,
            "extractedIntelligence": intel
        }), 200


    except Exception as e:

        logger.exception("Analyze error")

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ==================== RUN ====================


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
