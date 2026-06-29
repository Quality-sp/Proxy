from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sqlite3, datetime

app = Flask(__name__)
CORS(app)

ADMIN_PASSWORD = 'admin123'

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
        ip_limit INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS ips (
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        ip TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    db.execute("INSERT OR IGNORE INTO keys (key, expires_at, ip_limit, created_at) VALUES ('12345', '2026-12-31 00:00:00', 1, '2026-01-01 00:00:00')")
    db.commit()

init_db()

def check_admin(req):
    return req.headers.get('X-Admin-Password') == ADMIN_PASSWORD

@app.route('/')
def index():
    return send_file('whitelist-manager.html')

@app.route('/admin')
def admin():
    return send_file('admin.html')

@app.route('/auth', methods=['POST'])
def auth():
    key = request.json.get('key')
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Invalid key'}), 401
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if now > row['expires_at']:
        return jsonify({'success': False, 'message': 'Key expired'}), 401
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
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if now > row['expires_at']:
        return jsonify({'success': False, 'message': 'Key expired'}), 400
    count = db.execute("SELECT COUNT(*) FROM ips WHERE key=?", (key,)).fetchone()[0]
    if count >= row['ip_limit']:
        return jsonify({'success': False, 'message': 'IP limit reached'}), 400
    existing = db.execute("SELECT * FROM ips WHERE key=? AND ip=?", (key, ip)).fetchone()
    if existing:
        return jsonify({'success': False, 'message': 'IP already registered'}), 400
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

# ── ADMIN ROUTES ──
@app.route('/admin/keys', methods=['GET'])
def admin_get_keys():
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    db = get_db()
    keys = db.execute("SELECT k.*, COUNT(i.id) as ip_count FROM keys k LEFT JOIN ips i ON k.key = i.key GROUP BY k.id").fetchall()
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    result = []
    for k in keys:
        d = dict(k)
        d['expired'] = now > k['expires_at']
        result.append(d)
    return jsonify(result)

@app.route('/admin/keys', methods=['POST'])
def admin_create_key():
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.json
    key = data.get('key')
    expires_at = data.get('expires_at')
    ip_limit = data.get('ip_limit', 1)
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    try:
        db.execute("INSERT INTO keys (key, expires_at, ip_limit, created_at) VALUES (?,?,?,?)", (key, expires_at, ip_limit, now))
        db.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'message': 'Key already exists'}), 400

@app.route('/admin/keys/<int:key_id>', methods=['DELETE'])
def admin_delete_key(key_id):
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    db = get_db()
    key_row = db.execute("SELECT key FROM keys WHERE id=?", (key_id,)).fetchone()
    if key_row:
        db.execute("DELETE FROM ips WHERE key=?", (key_row['key'],))
    db.execute("DELETE FROM keys WHERE id=?", (key_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/admin/keys/<int:key_id>', methods=['PUT'])
def admin_update_key(key_id):
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.json
    db = get_db()
    db.execute("UPDATE keys SET expires_at=?, ip_limit=? WHERE id=?",
               (data.get('expires_at'), data.get('ip_limit'), key_id))
    db.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
