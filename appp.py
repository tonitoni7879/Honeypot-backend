
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

        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

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

    if "otp" in text:
        return "I got an OTP. Is it safe to share?"

    if "bank" in text:
        return "Which bank is this?"

    if "click" in text:
        return "What happens if I click?"

    return "Please explain again."


# ================= HEALTH =================

@app.route("/health")
def health():

    return jsonify({
        "status": "healthy"
    })


# ================= MAIN API =================

@app.route("/api/analyze", methods=["POST"])
@require_api_key
def analyze():

    try:

        # Never crash on bad JSON
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            data = {}

        logger.info(f"DATA: {data}")

        text = ""

        # All formats
        if "message" in data:

            if isinstance(data["message"], dict):
                text = data["message"].get("text", "")

            elif isinstance(data["message"], str):
                text = data["message"]

        elif "text" in data:
            text = data["text"]

        # Fallback (GUVI case)
        if not text:
            text = "Hello"

        session = data.get("sessionId", "default")

        history = data.get("conversationHistory", [])

        # Save user msg
        user_msg = {
            "sender": "user",
            "text": text,
            "time": datetime.utcnow().isoformat()
        }

        if session not in memory:
            memory[session] = []

        memory[session].append(user_msg)

        # Detect
        fraud, conf = detect(text)

        intel = extract(text)

        ai = reply(text, history)

        memory[session].append({
            "sender": "ai",
            "text": ai
        })

        # Callback
        if fraud == "Fraud" and (
            intel["upiIds"] or
            intel["bankAccounts"] or
            intel["phishingLinks"] or
            intel["phoneNumbers"]
        ):

            payload = {
                "sessionId": session,
                "scamDetected": True,
                "totalMessagesExchanged": len(memory[session]),
                "extractedIntelligence": intel,
                "agentNotes": "Scam detected"
            }

            try:
                requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            except:
                pass


        # GUVI NEEDS THIS FORMAT
        return jsonify({
            "status": "success",
            "reply": ai,
            "fraud_status": fraud,
            "confidence": conf,
            "extractedIntelligence": intel
        })


    except Exception as e:

        logger.exception("ERROR")

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ================= RUN =================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port
    )
