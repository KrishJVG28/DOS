from flask import Flask
from config import Config
from core.crypto import CryptoEngine
from core.auth import AuthEngine
from core.detection import HybridDetectionEngine
from database.db_setup import init_db
from database.secure_logger import SecureLogger
from api.routes import create_routes
from flask import render_template
import sqlite3

app = Flask(__name__)
app.config.from_object(Config)

init_db()

crypto_engine = CryptoEngine()
auth_engine = AuthEngine(Config.SECRET_KEY)
auth_engine.register_admin("admin", "admin123")
detection_engine = HybridDetectionEngine(Config.ENTROPY_THRESHOLD)
secure_logger = SecureLogger(crypto_engine)

app.register_blueprint(create_routes(auth_engine, crypto_engine, detection_engine, secure_logger))

@app.route('/')
def dashboard():
    conn = sqlite3.connect('database/security_logs.db')
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    cursor.execute("SELECT id, datetime(timestamp, 'localtime') as timestamp, verdict, entropy, packet_count, hash FROM threat_logs ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    
    logs = [dict(row) for row in rows]
    
    logs.reverse()
    
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    print("G9 Secure System initializing...")
    print("SQL Database Bound.")
    print("Cryptography modules loaded.")
    app.run(debug=True, port=5000)