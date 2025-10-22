import os, base64, re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from jose import jwt
from dotenv import load_dotenv

# === Cargar .env (local). En Render, vienen de Environment Variables ===
load_dotenv()

APP_ID = os.getenv("APP_ID")  # p.ej. vpaas-magic-cookie-xxxx
KEY_ID = os.getenv("KEY_ID")  # p.ej. vpaas-magic-cookie-xxxx/123456
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")

assert APP_ID, "Falta APP_ID en .env / Environment"
assert KEY_ID, "Falta KEY_ID en .env / Environment"
assert KEY_ID.startswith(APP_ID + "/"), "KEY_ID debe tener formato APP_ID/NUM_ID"

def _try_load_private_key() -> bytes:
    """
    Intenta, en este orden:
    1) PRIVATE_KEY_PEM (PEM crudo, multilinea)
    2) PRIVATE_KEY_PEM_BASE64 (Base64 de todo el PEM, con o sin saltos)
    3) Archivo local PRIVATE_KEY_PATH (para dev local)
    """
    # 1) PEM crudo (multilinea)
    pem_raw = os.getenv("PRIVATE_KEY_PEM")
    if pem_raw and "BEGIN PRIVATE KEY" in pem_raw:
        return pem_raw.encode("utf-8")

    # 2) Base64 del PEM
    b64_val = os.getenv("PRIVATE_KEY_PEM_BASE64")
    if b64_val:
        # Normalizar: quitar espacios/blancos y saltos
        compact = re.sub(r"\s+", "", b64_val)
        # Arreglar padding si falta (múltiplo de 4)
        missing = len(compact) % 4
        if missing:
            compact += "=" * (4 - missing)
        try:
            return base64.b64decode(compact, validate=False)
        except Exception as e:
            raise RuntimeError(f"PRIVATE_KEY_PEM_BASE64 inválido: {e}")

    # 3) Archivo local (dev)
    priv_path = Path(__file__).with_name(PRIVATE_KEY_PATH)
    if priv_path.exists():
        return priv_path.read_bytes()

    raise RuntimeError("No se encontró ninguna clave: defina PRIVATE_KEY_PEM o PRIVATE_KEY_PEM_BASE64 o el archivo local.")

PRIVATE_KEY_PEM = _try_load_private_key()

# === App Flask ===
app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Carpeta web (../web relativo a este archivo)
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
        "KEY_ID_startswith_APP_ID": bool(KEY_ID and KEY_ID.startswith(APP_ID + "/")),
        "has_PRIVATE_KEY_PEM_BASE64": bool(os.getenv("PRIVATE_KEY_PEM_BASE64")),
        "has_PRIVATE_KEY_PEM": bool(os.getenv("PRIVATE_KEY_PEM")),
        "using_file_key": not (os.getenv("PRIVATE_KEY_PEM_BASE64") or os.getenv("PRIVATE_KEY_PEM")),
    })

def build_jaas_token(room: str, name: str, email: str | None, moderator: bool) -> str:
    now = datetime.now(timezone.utc)
    nbf = int(now.timestamp())
    exp = int((now + timedelta(minutes=60)).timestamp())

    payload = {
        "aud": "jitsi",
        "iss": "chat",
        "sub": APP_ID,      # AppID
        "room": room,       # "*" o nombre corto de sala (sin APP_ID)
        "nbf": nbf,
        "exp": exp,
        "context": {
            "user": {
                "name": name or "Invitado",
                "email": email,
            },
            "features": {
                "recording": False,
                "livestreaming": False,
                "transcription": False,
            },
        },
        "moderator": bool(moderator),
    }

    headers = { "kid": KEY_ID }  # APP_ID/KEY_NUMBER

    token = jwt.encode(
        claims=payload,
        key=PRIVATE_KEY_PEM,
        algorithm="RS256",
        headers=headers
    )
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
