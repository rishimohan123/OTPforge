from flask import Flask, request, jsonify
from flask_cors import CORS
import pyotp, base64, time, logging, threading

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

USER_KEYS = {}
RATE_LIMIT = {}
RATE_LIMIT_LOCK = threading.Lock()
MAX_REQUESTS = 60
WINDOW = 60

def is_base32(s):
    try:
        base64.b32decode(s.upper(), casefold=True)
        return True
    except Exception:
        return False

def rate_limited(ip):
    with RATE_LIMIT_LOCK:
        now = time.time()
        data = RATE_LIMIT.get(ip, {"count": 0, "start": now})
        if now - data["start"] > WINDOW:
            data = {"count": 0, "start": now}
        data["count"] += 1
        RATE_LIMIT[ip] = data
        return data["count"] > MAX_REQUESTS

@app.before_request
def log_request():
    ip = request.remote_addr
    logging.info(f"{ip} {request.method} {request.path}")
    if rate_limited(ip):
        return jsonify({"error": "rate limit exceeded"}), 429

@app.route("/get-otp", methods=["POST"])
def get_otp():
    try:
        data = request.get_json(force=True)
        key = data.get("key")
        type_ = data.get("type", "").lower()
        username = data.get("username", "default")

        if not key:
            key = pyotp.random_base32()
            USER_KEYS[username] = {"key": key, "counter": 0}
        if not is_base32(key):
            return jsonify({"error": "invalid key"}), 400
        if username not in USER_KEYS:
            USER_KEYS[username] = {"key": key, "counter": 0}

        user = USER_KEYS[username]
        if type_ == "time":
            totp = pyotp.TOTP(key)
            otp = totp.now()
            remaining = int(totp.interval - (time.time() % totp.interval))
            return jsonify({
                "status": "ok",
                "type": "time",
                "username": username,
                "key": key,
                "otp": otp,
                "remaining_seconds": remaining
            }), 200
        elif type_ == "counter":
            counter = user["counter"]
            hotp = pyotp.HOTP(key)
            otp = hotp.at(counter)
            USER_KEYS[username]["counter"] += 1
            return jsonify({
                "status": "ok",
                "type": "counter",
                "username": username,
                "key": key,
                "otp": otp,
                "counter_used": counter,
                "next_counter": USER_KEYS[username]["counter"]
            }), 200
        else:
            return jsonify({"error": "unsupported type"}), 400
    except Exception as e:
        logging.error(f"Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "not found"}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "invalid method"}), 405

if __name__ == "__main__":
    logging.info("OTPForge running at http://127.0.0.1:5005/get-otp")
    app.run(host="0.0.0.0", port=5005)
