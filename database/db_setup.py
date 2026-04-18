import sqlite3
import os

DB_PATH = "database/security_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            verdict TEXT,
            entropy REAL,
            packet_count INTEGER,
            nonce TEXT,
            encrypted_payload TEXT,
            hash TEXT,
            signature TEXT
        )
    ''')
    conn.commit()
    conn.close()