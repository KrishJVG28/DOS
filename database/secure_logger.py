import sqlite3
from database.db_setup import DB_PATH

class SecureLogger:
    def __init__(self, crypto_engine):
        self.crypto = crypto_engine

    def get_last_hash(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT hash FROM threat_logs ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "GENESIS"

    def log_event(self, verdict, entropy, packet_count):
        prev_hash = self.get_last_hash()
        alert_data = {"verdict": verdict, "entropy": entropy, "packet_count": packet_count}
        
        nonce, ciphertext = self.crypto.encrypt_payload(alert_data)
        current_hash = self.crypto.generate_hash(f"{verdict}_{entropy}_{ciphertext}", prev_hash)
        signature = self.crypto.sign_alert(current_hash)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threat_logs (verdict, entropy, packet_count, nonce, encrypted_payload, hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (verdict, entropy, packet_count, nonce, ciphertext, current_hash, signature))
        conn.commit()
        conn.close()
        
        return current_hash