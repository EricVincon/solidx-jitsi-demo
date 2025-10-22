import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from jose import jwt
from dotenv import load_dotenv
import base64

# === Cargar variables de entorno (.env local o envs del proveedor) ===
load_dotenv()

APP_ID = os.getenv("APP_ID")  # p.ej. vpaas-magic-cookie-xxxx
KEY_ID = os.getenv("KEY_ID")  # p.ej. vpaas-magic-cookie-xxxx/123456
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
PRIVATE_KEY_PEM_BASE64 = os.getenv("PRIVATE_KEY_PEM_BASE64")  # NUEVO

assert APP_ID, "Falta APP_ID en variables de entorno"
assert KEY_ID, "Falta KEY_ID en variables de entorno"

# === Cargar clave privada (preferentemente desde env en base64) ===
if PRIVATE_KEY_PEM_BASE64:
    PRIVATE_KEY_PEM = base64.b64decode(PRIVATE_KEY_PEM_BASE64)
else:
    priv_path = Path(__file__).with_name(PRIVATE_KEY_PATH)
    with open(priv_path, "rb") as f:
        PRIVATE_KEY_PEM = f.read()

# === App Flask ===
app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Carpeta web (../web)
WEB_DIR = (Path(__file__).resolve().parents[1] / "web").resolve()

# === Web (frontend) ===
@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")

@app.route("/<path:filename>")
def web_files(filename):
    # Sirve cualquier archivo de /web (css, imágenes, etc.)
    # Importante: para rutas "profundas" tipo /APP_ID/sala, devolvemos index.html
    file_path = (WEB_DIR / filename)
    if file_path.exists() and file_path.is_file():
        return send_from_directory(WEB_DIR, filename)
    return send_from_directory(WEB_DIR, "index.html")

# === Healthcheck ===
@app.get("/ping")
def ping():
    return "pong"

# === JWT JAAS ===
def build_jaas_token(room: str, name: str, email: str | None, moderator: bool) -> str:
    now = datetime.now(timezone.utc)
    nbf = int(now.timestamp())
    exp = int((now + timedelta(minutes=60)).timestamp())

    payload = {
        "aud": "jitsi",
        "iss": "chat",
        "sub": APP_ID,        # tu AppID
        "room": room,         # "*" o nombre simple (sin APP_ID delante)
        "nbf": nbf,
        "exp": exp,
        "context": {
            "user": {"name": name or "Invitado", "email": email},
            "features": {
                "recording": False,
                "livestreaming": False,
                "transcription": False,
            },
        },
        "moderator": bool(moderator),
    }
    headers = {"kid": KEY_ID}  # formato: APP_ID/KEY_NUM

    token = jwt.encode(claims=payload, key=PRIVATE_KEY_PEM, algorithm="RS256", headers=headers)
    return token

@app.get("/api/token")
def api_token():
    room = request.args.get("room", "*")
    name = request.args.get("name", "Invitado")
    email = request.args.get("email")
    moderator = request.args.get("moderator", "false").lower() in ("1", "true", "yes")
    token = build_jaas_token(room=room, name=name, email=email, moderator=moderator)
    return jsonify({"token": token})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
