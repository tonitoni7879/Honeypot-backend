from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import re
import os
from functools import wraps
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Configuration
VALID_API_KEY = os.environ.get('API_KEY', 'demo123')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')  # Optional: Set for real AI responses
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# In-memory session storage (use Redis in production)
conversation_memory = {}

# ==================== AUTHENTICATION ====================

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key or api_key != VALID_API_KEY:
            return jsonify({
                'error': 'Invalid or missing API key',
                'status': 'unauthorized'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

# ==================== SCAM DETECTION LOGIC ====================

SCAM_KEYWORDS = [
    'urgent', 'verify', 'suspended', 'account blocked', 'click here',
    'confirm your', 'won', 'lottery', 'prize', 'claim', 'refund',
    'bank account', 'card details', 'cvv', 'otp', 'one time password',
    'expire', 'immediately', 'act now', 'limited time', 'congratulations',
    'tax refund', 'government', 'irs', 'revenue', 'penalty',
    'arrest warrant', 'legal action', 'court', 'police', 'officer',
    'paytm', 'phonepe', 'gpay', 'upi', 'transfer money',
    'update kyc', 'kyc pending', 'link aadhar', 'pan card',
    'covid relief', 'stimulus', 'beneficiary', 'inheritance',
    'nigerian prince', 'bitcoin', 'investment opportunity',
    'double your money', 'guaranteed returns', 'risk free'
]

SAFE_INDICATORS = [
    'hello', 'how are you', 'good morning', 'good evening',
    'thank you', 'thanks', 'okay', 'yes', 'no', 'bye'
]

def detect_scam(text, conversation_history):
    """
    Rule-based scam detection with confidence scoring
    """
    text_lower = text.lower()
    
    # Count scam keyword matches
    scam_matches = sum(1 for keyword in SCAM_KEYWORDS if keyword in text_lower)
    safe_matches = sum(1 for keyword in SAFE_INDICATORS if keyword in text_lower)
    
    # Check for urgency patterns
    urgency_patterns = ['urgent', 'immediate', 'now', 'quickly', 'asap', 'expire']
    urgency_score = sum(1 for pattern in urgency_patterns if pattern in text_lower)
    
    # Check for financial requests
    financial_patterns = ['send money', 'transfer', 'pay', 'payment', 'deposit', 'account number']
    financial_score = sum(1 for pattern in financial_patterns if pattern in text_lower)
    
    # Check for personal info requests
    info_patterns = ['password', 'pin', 'otp', 'cvv', 'card number', 'social security', 'aadhar']
    info_score = sum(1 for pattern in info_patterns if pattern in text_lower)
    
    # Calculate confidence
    total_scam_indicators = scam_matches + urgency_score + financial_score * 2 + info_score * 3
    
    # Determine fraud status
    if total_scam_indicators >= 5:
        fraud_status = "Fraud"
        confidence = min(85 + total_scam_indicators * 2, 99)
    elif total_scam_indicators >= 2:
        fraud_status = "Fraud"
        confidence = 60 + total_scam_indicators * 5
    elif safe_matches > scam_matches and total_scam_indicators == 0:
        fraud_status = "Safe"
        confidence = 80
    else:
        fraud_status = "Unknown"
        confidence = 40 + scam_matches * 10
    
    return fraud_status, confidence

# ==================== INTELLIGENCE EXTRACTION ====================

def extract_intelligence(text):
    """
    Extract scam-related intelligence using regex
    """
    intelligence = {
        'bankAccounts': [],
        'upiIds': [],
        'phishingLinks': [],
        'phoneNumbers': [],
        'suspiciousKeywords': []
    }
    
    # Extract UPI IDs (format: username@bank)
    upi_pattern = r'\b[\w\.-]+@[\w\.-]+\b'
    upi_matches = re.findall(upi_pattern, text)
    intelligence['upiIds'] = [upi for upi in upi_matches if any(bank in upi.lower() for bank in ['paytm', 'ybl', 'okaxis', 'oksbi', 'axl', 'airtel', 'fbl', 'ibl', 'upi'])]
    
    # Extract phone numbers (Indian format: 10 digits, optional +91)
    phone_pattern = r'(?:\+91[-\s]?)?[6-9]\d{9}'
    intelligence['phoneNumbers'] = list(set(re.findall(phone_pattern, text)))
    
    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    intelligence['phishingLinks'] = list(set(re.findall(url_pattern, text)))
    
    # Extract bank account numbers (9-18 digits)
    bank_pattern = r'\b\d{9,18}\b'
    potential_accounts = re.findall(bank_pattern, text)
    # Filter out phone numbers from bank accounts
    intelligence['bankAccounts'] = [acc for acc in potential_accounts if len(acc) >= 9 and acc not in ''.join(intelligence['phoneNumbers'])]
    
    # Extract suspicious keywords found
    text_lower = text.lower()
    intelligence['suspiciousKeywords'] = [keyword for keyword in SCAM_KEYWORDS if keyword in text_lower]
    
    return intelligence

# ==================== FINAL RESULT CALLBACK (GUVI) ====================

def send_final_result(session_id, intelligence, total_messages):
    """
    Send final extracted intelligence to GUVI evaluation endpoint
    """

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": intelligence.get("bankAccounts", []),
            "upiIds": intelligence.get("upiIds", []),
            "phishingLinks": intelligence.get("phishingLinks", []),
            "phoneNumbers": intelligence.get("phoneNumbers", []),
            "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
        },
        "agentNotes": "Scammer used urgency and financial manipulation tactics"
    }

    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )

        logger.info(f"GUVI Callback Sent: {response.status_code}")

    except Exception as e:
        logger.error(f"GUVI Callback Failed: {str(e)}")


# ==================== AI REPLY GENERATION ====================
# (YOUR EXISTING AI REPLY CODE STARTS BELOW THIS LINE)

def generate_ai_reply(message_text, conversation_history, fraud_status):
    """
    Generate human-like AI reply to engage scammer
    Strategy: Keep them talking, extract more info, waste their time
    """
    
    text_lower = message_text.lower()
    
    # If using OpenAI API (optional)
    if OPENAI_API_KEY:
        try:
            import openai
            openai.api_key = OPENAI_API_KEY
            
            system_prompt = """You are an AI honeypot designed to engage with potential scammers.
Your goal is to:
1. Sound like a naive, slightly confused victim
2. Ask clarifying questions to extract more information
3. Never give real personal information
4. Keep the scammer engaged
5. Be believable and human-like
6. Show interest but hesitation
Keep responses under 100 words."""

            messages = [{"role": "system", "content": system_prompt}]
            for msg in conversation_history[-5:]:  # Last 5 messages for context
                role = "assistant" if msg['sender'] == 'ai' else "user"
                messages.append({"role": role, "content": msg['text']})
            messages.append({"role": "user", "content": message_text})
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=100,
                temperature=0.8
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            # Fall through to rule-based responses
    
    # Rule-based responses (fallback or primary)
    
    # Initial greeting responses
    if len(conversation_history) == 0:
        return "Hello? Who is this?"
    
    # Account/verification scams
    if any(word in text_lower for word in ['account', 'verify', 'suspended', 'blocked']):
        return "Oh no, really? My account is blocked? What do I need to do? I'm not very good with these things..."
    
    # OTP/Password requests
    if any(word in text_lower for word in ['otp', 'password', 'pin', 'cvv']):
        return "You need my OTP? Is that safe? I just got a message... should I share it with you? I'm a bit confused."
    
    # Money transfer requests
    if any(word in text_lower for word in ['send money', 'transfer', 'payment', 'deposit']):
        return "Send money? How much? Where do I send it? Can you explain the process? I've never done this before."
    
    # Prize/lottery scams
    if any(word in text_lower for word in ['won', 'prize', 'lottery', 'congratulations']):
        return "Really? I won something? That's amazing! What did I win? What do I need to do to claim it?"
    
    # Link clicking
    if 'http' in text_lower or 'click' in text_lower:
        return "You want me to click a link? I'm on my phone right now. Can you send it again? What will happen when I click it?"
    
    # KYC/Document requests
    if any(word in text_lower for word in ['kyc', 'aadhar', 'pan', 'document']):
        return "Update my KYC? Is this mandatory? What documents do you need? Can I do this later?"
    
    # Urgency tactics
    if any(word in text_lower for word in ['urgent', 'immediately', 'expire', 'limited time']):
        return "Oh, it's urgent? I'm a bit busy right now. How much time do I have? What happens if I don't do it immediately?"
    
    # Generic continuation
    continuation_responses = [
        "I see... can you tell me more about this?",
        "Okay, I'm listening. What should I do next?",
        "I'm not sure I understand. Can you explain again?",
        "Hmm, this sounds important. Give me a moment to process this.",
        "Wait, let me get my reading glasses. Can you repeat that?",
        "I want to help, but I need to understand better. What exactly do you need from me?"
    ]
    
    # Rotate through responses based on conversation length
    return continuation_responses[len(conversation_history) % len(continuation_responses)]
@app.route('/health', methods=['GET'])
def health():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'service': 'Scam Honeypot API',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
# ==================== MAIN ENDPOINT ====================

@app.route('/api/analyze', methods=['POST'])
@require_api_key
def analyze():
    """
    Main endpoint for scam detection and AI response generation
    """
    try:
        # Parse request
        data = request.get_json()
        
        # Validate required fields
        if not data or 'message' not in data or 'text' not in data['message']:
            return jsonify({
                'error': 'Invalid request format',
                'message': 'Required fields: message.text'
            }), 400
        
        session_id = data.get('sessionId', 'default')
        message = data['message']
        conversation_history = data.get('conversationHistory', [])
        
        message_text = message['text']
        
        # Store conversation in memory
        if session_id not in conversation_memory:
            conversation_memory[session_id] = []
        conversation_memory[session_id].append(message)
        
        # Detect scam
        fraud_status, confidence = detect_scam(message_text, conversation_history)
        
        # Extract intelligence
        extracted_intelligence = extract_intelligence(message_text)

        # Check if enough intelligence is collected (completion logic)
        intel_found = False

        if (
            extracted_intelligence["upiIds"] or
            extracted_intelligence["bankAccounts"] or
            extracted_intelligence["phishingLinks"] or
            extracted_intelligence["phoneNumbers"]
        ):
            intel_found = True
        
        # Generate AI reply
        ai_reply = generate_ai_reply(message_text, conversation_history, fraud_status)
        
        # Store AI response in memory
        ai_message = {
            'sender': 'ai',
            'text': ai_reply,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        conversation_memory[session_id].append(ai_message)
        
        # If scam confirmed and intelligence found, send final callback
        if fraud_status == "Fraud" and intel_found:

            total_messages = len(conversation_memory.get(session_id, []))

            send_final_result(
                session_id=session_id,
                intelligence=extracted_intelligence,
                total_messages=total_messages
            )

        # Build response
        response = {
                    'status': 'success',     # <-- ADD THIS LINE
                    'reply': ai_reply,
                    'fraud_status': fraud_status,
                    'confidence': confidence,
                    'extractedIntelligence': extracted_intelligence
                }
                
        logger.info(f"Session {session_id}: Fraud={fraud_status}, Confidence={confidence}%")
                
        return jsonify(response), 200
                
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

        # ==================== HEALTH CHECK ====================


# ==================== SESSION MANAGEMENT ====================

@app.route('/api/sessions/<session_id>', methods=['GET'])
@require_api_key
def get_session(session_id):
    """Get conversation history for a session"""
    if session_id in conversation_memory:
        return jsonify({
            'sessionId': session_id,
            'messages': conversation_memory[session_id]
        }), 200
    else:
        return jsonify({
            'error': 'Session not found'
        }), 404

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@require_api_key
def delete_session(session_id):
    """Clear a session"""
    if session_id in conversation_memory:
        del conversation_memory[session_id]
        return jsonify({
            'message': 'Session cleared',
            'sessionId': session_id
        }), 200
    else:
        return jsonify({
            'error': 'Session not found'
        }), 404

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== RUN SERVER ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    logger.info(f"Starting Scam Honeypot API on port {port}")
    logger.info(f"API Key authentication enabled")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )