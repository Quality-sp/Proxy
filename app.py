from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sqlite3, datetime

app = Flask(__name__)
CORS(app)

def get_db():
    db = sqlite3.connect('whitelist.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        ip_limit INTEGER DEFAULT 1
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS ips (
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        ip TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    db.execute("INSERT OR IGNORE INTO keys (key, expires_at, ip_limit) VALUES ('12345', '2026-12-31 00:00:00', 1)")
    db.commit()

init_db()

@app.route('/')
def index():
    return send_file('whitelist-manager.html')

@app.route('/auth', methods=['POST'])
def auth():
    key = request.json.get('key')
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Invalid key'}), 401
    return jsonify({'success': True, 'expires_at': row['expires_at'], 'ip_limit': row['ip_limit']})

@app.route('/ips', methods=['GET'])
def get_ips():
    key = request.args.get('key')
    db = get_db()
    rows = db.execute("SELECT * FROM ips WHERE key=?", (key,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/ips', methods=['POST'])
def add_ip():
    data = request.json
    key = data.get('key')
    ip = data.get('ip')
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Invalid key'}), 401
    count = db.execute("SELECT COUNT(*) FROM ips WHERE key=?", (key,)).fetchone()[0]
    if count >= row['ip_limit']:
        return jsonify({'success': False, 'message': 'IP limit reached'}), 400
    existing = db.execute("SELECT * FROM ips WHERE key=? AND ip=?", (key, ip)).fetchone()
    if existing:
        return jsonify({'success': False, 'message': 'IP already registered'}), 400
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute("INSERT INTO ips (key, ip, created_at) VALUES (?,?,?)", (key, ip, now))
    db.commit()
    return jsonify({'success': True})

@app.route('/ips/<int:ip_id>', methods=['DELETE'])
def delete_ip(ip_id):
    key = request.args.get('key')
    db = get_db()
    db.execute("DELETE FROM ips WHERE id=? AND key=?", (ip_id, key))
    db.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
