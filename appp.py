
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import re
import os
import logging
import requests
from functools import wraps

# ==================== CONFIG ====================

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VALID_API_KEY = os.environ.get("API_KEY", "demo123")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

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
    upi = re.findall(r"\b[\w\.-]+@[\w\.-]+\b", text)
    intel["upiIds"] = upi

    # Phone
    phone = re.findall(r"(?:\+91)?[6-9]\d{9}", text)
    intel["phoneNumbers"] = phone

    # Links
    urls = re.findall(r"https?://[^\s]+", text)
    intel["phishingLinks"] = urls

    # Bank numbers
    acc = re.findall(r"\b\d{9,18}\b", text)
    intel["bankAccounts"] = acc

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


# ==================== TEST ENDPOINT (GUVI) ====================

@app.route("/api/test", methods=["GET"])
@require_api_key
def api_test():

    return jsonify({
        "status": "success",
        "message": "Honeypot API working",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


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

        data = request.get_json()

        if not data or "message" not in data:
            return jsonify({
                "status": "error",
                "message": "Invalid input"
            }), 400

        session_id = data.get("sessionId", "default")
        msg = data["message"]
        history = data.get("conversationHistory", [])

        text = msg["text"]

        if session_id not in conversation_memory:
            conversation_memory[session_id] = []

        conversation_memory[session_id].append(msg)

        # Detect
        fraud, confidence = detect_scam(text)

        # Extract
        intel = extract_intelligence(text)

        # AI Reply
        reply = generate_ai_reply(text, history)

        # Store AI msg
        conversation_memory[session_id].append({
            "sender": "ai",
            "text": reply,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        # Completion
        if fraud == "Fraud" and (
            intel["upiIds"] or
            intel["bankAccounts"] or
            intel["phishingLinks"] or
            intel["phoneNumbers"]
        ):

            total = len(conversation_memory[session_id])

            send_final_result(session_id, intel, total)

        # Response
        response = {
            "status": "success",
            "reply": reply,
            "fraud_status": fraud,
            "confidence": confidence,
            "extractedIntelligence": intel
        }

        return jsonify(response), 200


    except Exception as e:

        logger.error(e)

        return jsonify({
            "status": "error",
            "message": "Server Error"
        }), 500


# ==================== SESSION ====================

@app.route("/api/sessions/<sid>", methods=["GET"])
@require_api_key
def get_session(sid):

    if sid not in conversation_memory:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "sessionId": sid,
        "messages": conversation_memory[sid]
    })


@app.route("/api/sessions/<sid>", methods=["DELETE"])
@require_api_key
def delete_session(sid):

    if sid in conversation_memory:
        del conversation_memory[sid]

    return jsonify({"status": "deleted"})


# ==================== RUN ====================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
