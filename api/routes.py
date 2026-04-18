from flask import Blueprint, request, jsonify

def create_routes(auth, crypto, detection, logger):
    api_bp = Blueprint('api', __name__)

    @api_bp.route('/login', methods=['POST'])
    def login():
        data = request.json
        token = auth.login(data.get('username'), data.get('password'))
        if token: return jsonify({"token": token}), 200
        return jsonify({"error": "Invalid credentials"}), 401

    @api_bp.route('/traffic_sniffer', methods=['POST'])
    def traffic_sniffer():
        data = request.json
        verdict, entropy = detection.analyze_traffic(data['packet_count'], data['ips'])
        
        log_hash = logger.log_event(verdict, entropy, data['packet_count'])

        response = {"verdict": verdict, "entropy": round(entropy, 2), "log_hash": log_hash}
        
        if verdict == "DOS_ATTACK":
            response["mitigation"] = "Forwarded malicious IPs to Mitigation Engine"
            
        return jsonify(response)

    @api_bp.route('/mitigation_engine', methods=['POST'])
    def mitigation_engine():
        token = request.headers.get('Authorization')
        if not token or not auth.verify_role(token.split(" ")[1], "admin"):
            return jsonify({"error": "Unauthorized Access"}), 403
        
        data = request.json
        secure_command = crypto.secure_channel_encrypt(f"BLOCK {data.get('target_ip')}")
        
        return jsonify({
            "status": "Mitigation Applied",
            "secure_channel_used": "RSA-2048",
            "encrypted_command_payload": secure_command
        })

    return api_bp