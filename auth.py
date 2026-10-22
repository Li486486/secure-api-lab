import jwt, bcrypt, datetime
SECRET_KEY = 'your-secret-key-change-in-production'

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    
    # 如果 token 是 bytes 类型（旧版 PyJWT），则解码为 str；如果是 str（新版），则保持不变
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None