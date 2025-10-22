import os, re, base64
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from jose import jwt

def _env(name: str) -> str | None:
    v = os.getenv(name)
    if v is None:
        return None
    return v.strip().strip('"').strip("'").replace("\r", "")

# --- Lee env ---
APP_ID = _env("APP_ID")  # ej: vpaas-magic-cookie-xxxx
KEY_ID = _env("KEY_ID")  # ej: vpaas-magic-cookie-xxxx/123456
PRIVATE_KEY_PEM = _env("PRIVATE_KEY_PEM")
PRIVATE_KEY_PEM_B64 = _env("PRIVATE_KEY_PEM_BASE64")

# Normaliza KEY_ID
if KEY_ID:
    if KEY_ID.lower().startswith("kid="):
        KEY_ID = KEY_ID.split("=", 1)[1].strip()
    KEY_ID = re.sub(r"\s+", "", KEY_ID)

# Si APP_ID falta o no matchea, lo derivamos desde KEY_ID
derived_app_id = None
if KEY_ID and "/" in KEY_ID:
    derived_app_id = KEY_ID.split("/", 1)[0]

auto_fix_msgs = []
if (not APP_ID) and derived_app_id:
    APP_ID = derived_app_id
    auto_fix_msgs.append("APP_ID derivado automáticamente desde KEY_ID.")
elif APP_ID and derived_app_id and (not KEY_ID.startswith(APP_ID + "/")):
    APP_ID = derived_app_id  # preferimos la parte izquierda del KEY_ID
    auto_fix_msgs.append("APP_ID no coincidía; se reemplazó por la parte izquierda de KEY_ID.")

errors = []
if not APP_ID:
    errors.append("Falta APP_ID.")
if not KEY_ID:
    errors.append("Falta KEY_ID.")

# Carga clave privada
PRIVATE_KEY_BYTES = None
if PRIVATE_KEY_PEM and PRIVATE_KEY_PEM_B64:
    errors.append("Define SOLO una de PRIVATE_KEY_PEM o PRIVATE_KEY_PEM_BASE64, no ambas.")
elif PRIVATE_KEY_PEM:
    PRIVATE_KEY_BYTES = PRIVATE_KEY_PEM.encode("utf-8")
elif PRIVATE_KEY_PEM_B64:
    try:
        PRIVATE_KEY_BYTES = base64.b64decode(PRIVATE_KEY_PEM_B64, validate=False)
    except Exception as e:
        errors.append(f"PRIVATE_KEY_PEM_BASE64 invalida: {e}")
else:
    errors.append("No encontré PRIVATE_KEY_PEM ni PRIVATE_KEY_PEM_BASE64.")

# Flask
app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": {"origins": "*"}})
WEB_DIR = (Path(__file__).resolve().parents[1] / "web").resolve()

@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")

@app.route("/<path:filename>")
def web_files(filename):
    return send_from_directory(WEB_DIR, filename)

@app.get("/ping")
def ping():
    return "pong"

@app.get("/api/debug-env")
def debug_env():
    return jsonify({
        "APP_ID_present": bool(APP_ID),
        "KEY_ID_present": bool(KEY_ID),
        "KEY_ID_startswith_APP_ID": (bool(APP_ID) and bool(KEY_ID) and KEY_ID.startswith(APP_ID + "/")),
        "has_PRIVATE_KEY_PEM": bool(PRIVATE_KEY_PEM),
        "has_PRIVATE_KEY_PEM_BASE64": bool(PRIVATE_KEY_PEM_B64),
        "using_base64_key": bool(PRIVATE_KEY_PEM_B64),
        "auto_fix_msgs": auto_fix_msgs,
        "errors": errors,
        "APP_ID_preview": (APP_ID[:18] + "..." if APP_ID else None),
        "KEY_ID_preview": (KEY_ID[:18] + "..." if KEY_ID else None),
    })

def build_jaas_token(room: str, name: str, email: str | None, moderator: bool) -> str:
    if errors:
        raise RuntimeError("Config inválida: " + " | ".join(errors))
    now = datetime.now(timezone.utc)
    payload = {
        "aud": "jitsi",
        "iss": "chat",
        "sub": APP_ID,          # AppID correcto (auto-derivado si hacía falta)
        "room": room,           # nombre simple, sin AppID
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "context": {
            "user": { "name": name or "Invitado", "email": email },
            "features": {
                "recording": False,
                "livestreaming": False,
                "transcription": False,
            },
        },
        "moderator": bool(moderator),
    }
    headers = { "kid": KEY_ID }  # Debe ser APP_ID/NUM_ID
    return jwt.encode(payload, PRIVATE_KEY_BYTES, algorithm="RS256", headers=headers)

@app.get("/api/token")
def api_token():
    room = request.args.get("room", "*")
    name = request.args.get("name", "Invitado")
    email = request.args.get("email")
    moderator = request.args.get("moderator", "false").lower() in ("1", "true", "yes")
    try:
        token = build_jaas_token(room=room, name=name, email=email, moderator=moderator)
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": str(e), "hint": "/api/debug-env"}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
