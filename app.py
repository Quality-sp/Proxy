from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import psycopg2, psycopg2.extras, datetime, os

app = Flask(__name__)
CORS(app)

ADMIN_PASSWORD = 'Ironmonterboss123'

def get_db():
    return psycopg2.connect(os.environ['DATABASE_URL'], sslmode='require')

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS keys (
        id SERIAL PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        duration_days INTEGER NOT NULL DEFAULT 1,
        expires_at TIMESTAMP,
        ip_limit INTEGER DEFAULT 1,
        created_at TIMESTAMP NOT NULL,
        activated_at TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS ips (
        id SERIAL PRIMARY KEY,
        key TEXT NOT NULL,
        ip TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL
    )''')
    cur.execute("INSERT INTO keys (key, duration_days, ip_limit, created_at) VALUES ('12345', 30, 1, NOW()) ON CONFLICT (key) DO NOTHING")
    db.commit()
    cur.close()
    db.close()

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
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
    row = cur.fetchone()
    if not row:
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'Invalid key'}), 401
    now = datetime.datetime.now()
    if not row['activated_at']:
        expires = now + datetime.timedelta(days=row['duration_days'])
        cur.execute("UPDATE keys SET activated_at=%s, expires_at=%s WHERE key=%s", (now, expires, key))
        db.commit()
        cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
        row = cur.fetchone()
    if row['expires_at'] and now > row['expires_at']:
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'Key expired'}), 401
    result = {
        'success': True,
        'expires_at': row['expires_at'].strftime('%Y-%m-%d %H:%M:%S'),
        'ip_limit': row['ip_limit'],
        'activated_at': row['activated_at'].strftime('%Y-%m-%d %H:%M:%S') if row['activated_at'] else None
    }
    cur.close(); db.close()
    return jsonify(result)

@app.route('/ips', methods=['GET'])
def get_ips():
    key = request.args.get('key')
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ips WHERE key=%s", (key,))
    rows = cur.fetchall()
    cur.close(); db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/ips', methods=['POST'])
def add_ip():
    data = request.json
    key = data.get('key')
    ip = data.get('ip')
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM keys WHERE key=%s", (key,))
    row = cur.fetchone()
    if not row:
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'Invalid key'}), 401
    now = datetime.datetime.now()
    if row['expires_at'] and now > row['expires_at']:
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'Key expired'}), 400
    cur.execute("SELECT COUNT(*) as c FROM ips WHERE key=%s", (key,))
    count = cur.fetchone()['c']
    if count >= row['ip_limit']:
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'IP limit reached'}), 400
    cur.execute("SELECT * FROM ips WHERE key=%s AND ip=%s", (key, ip))
    if cur.fetchone():
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'IP already registered'}), 400
    cur.execute("INSERT INTO ips (key, ip, created_at) VALUES (%s, %s, %s)", (key, ip, now))
    db.commit()
    cur.close(); db.close()
    return jsonify({'success': True})

@app.route('/ips/<int:ip_id>', methods=['DELETE'])
def delete_ip(ip_id):
    key = request.args.get('key')
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM ips WHERE id=%s AND key=%s", (ip_id, key))
    db.commit()
    cur.close(); db.close()
    return jsonify({'success': True})

@app.route('/admin/keys', methods=['GET'])
def admin_get_keys():
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT k.*, COUNT(i.id) as ip_count FROM keys k LEFT JOIN ips i ON k.key = i.key GROUP BY k.id ORDER BY k.id DESC")
    keys = cur.fetchall()
    cur.close(); db.close()
    now = datetime.datetime.now()
    result = []
    for k in keys:
        d = dict(k)
        d['expired'] = bool(k['expires_at'] and now > k['expires_at'])
        d['activated'] = bool(k['activated_at'])
        d['expires_at'] = k['expires_at'].strftime('%Y-%m-%d %H:%M:%S') if k['expires_at'] else None
        d['activated_at'] = k['activated_at'].strftime('%Y-%m-%d %H:%M:%S') if k['activated_at'] else None
        d['created_at'] = k['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        result.append(d)
    return jsonify(result)

@app.route('/admin/keys', methods=['POST'])
def admin_create_key():
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.json
    key = data.get('key')
    duration_days = data.get('duration_days', 1)
    ip_limit = data.get('ip_limit', 1)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO keys (key, duration_days, ip_limit, created_at) VALUES (%s, %s, %s, NOW())",
                   (key, duration_days, ip_limit))
        db.commit()
        cur.close(); db.close()
        return jsonify({'success': True})
    except:
        db.rollback()
        cur.close(); db.close()
        return jsonify({'success': False, 'message': 'Key already exists'}), 400

@app.route('/admin/keys/<int:key_id>', methods=['DELETE'])
def admin_delete_key(key_id):
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT key FROM keys WHERE id=%s", (key_id,))
    row = cur.fetchone()
    if row:
        cur.execute("DELETE FROM ips WHERE key=%s", (row['key'],))
    cur.execute("DELETE FROM keys WHERE id=%s", (key_id,))
    db.commit()
    cur.close(); db.close()
    return jsonify({'success': True})

@app.route('/admin/keys/<int:key_id>', methods=['PUT'])
def admin_update_key(key_id):
    if not check_admin(request):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.json
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE keys SET duration_days=%s, ip_limit=%s WHERE id=%s",
               (data.get('duration_days'), data.get('ip_limit'), key_id))
    db.commit()
    cur.close(); db.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
