from flask import Flask, request, jsonify, render_template_string
from models import Session, User
from auth import hash_password, verify_password, generate_token, decode_token
from functools import wraps

app = Flask(__name__)

# JWT 验证中间件
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        return f(payload['user_id'], *args, **kwargs)
    return decorated

# 1. POST /auth/login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    session = Session()
    user = session.query(User).filter_by(username=data.get('username')).first()
    session.close()
    if user and verify_password(data.get('password', ''), user.password_hash):
        return jsonify({'token': generate_token(user.id)})
    return jsonify({'error': 'Invalid credentials'}), 401

# 2. GET /api/data (受保护)
@app.route('/api/data')
@token_required
def get_data(user_id):
    return jsonify({'data': [{'id': 1, 'title': 'Secure Post'}, {'id': 2, 'title': 'Another Post'}]})

# 3. 自定义端点 — ⚠️ 含 SSTI 漏洞（用于 CVE 复现）
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: 用户输入直接拼入模板字符串
    template = f'<h1>Hello {name}</h1>'
    return render_template_string(template)

if __name__ == '__main__':
    # 初始化测试用户
    session = Session()
    if not session.query(User).filter_by(username='admin').first():
        user = User(username='admin', password_hash=hash_password('admin123'))
        session.add(user)
        session.commit()
    session.close()
    app.run(debug=True, port=5000)