
@app.route("/api/analyze", methods=["POST"])
@require_api_key
def analyze():

    try:

        # Get raw JSON (never crash)
        data = request.get_json(silent=True)

        if data is None:
            data = {}

        logger.info(f"Incoming data: {data}")

        # Try ALL possible formats
        message_text = ""

        if isinstance(data, dict):

            # Case 1: { message: { text: "hi" } }
            if "message" in data and isinstance(data["message"], dict):
                message_text = data["message"].get("text", "")

            # Case 2: { message: "hi" }
            elif "message" in data and isinstance(data["message"], str):
                message_text = data["message"]

            # Case 3: { text: "hi" }
            elif "text" in data:
                message_text = data.get("text", "")

        # Case 4: Empty / garbage → fallback
        if not message_text:
            message_text = "Hello"

        session_id = data.get("sessionId", "default")

        history = data.get("conversationHistory", [])

        # Save user msg
        user_msg = {
            "sender": "user",
            "text": message_text,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        if session_id not in conversation_memory:
            conversation_memory[session_id] = []

        conversation_memory[session_id].append(user_msg)

        # Detect
        fraud, confidence = detect_scam(message_text)

        # Extract
        intel = extract_intelligence(message_text)

        # AI reply
        reply = generate_ai_reply(message_text, history)

        # Save AI msg
        conversation_memory[session_id].append({
            "sender": "ai",
            "text": reply,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        # Send callback if fraud
        if fraud == "Fraud" and (
            intel["upiIds"] or
            intel["bankAccounts"] or
            intel["phishingLinks"] or
            intel["phoneNumbers"]
        ):

            total = len(conversation_memory[session_id])

            send_final_result(session_id, intel, total)

        # FINAL RESPONSE (GUVI EXPECTS THIS)
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
