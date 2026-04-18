import bcrypt
import jwt
import datetime

class AuthEngine:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.users_db = {} 

    def register_admin(self, username, password, role="admin"):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.users_db[username] = {"hash": hashed, "role": role}

    def login(self, username, password):
        user = self.users_db.get(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user["hash"]):
            payload = {"username": username, "role": user["role"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            return jwt.encode(payload, self.secret_key, algorithm="HS256")
        return None

    def verify_role(self, token, required_role):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload["role"] == required_role
        except:
            return False