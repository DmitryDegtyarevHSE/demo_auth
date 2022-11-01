from typing import Optional
import hmac
import hashlib
import base64
import json
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


SECRET_KEY = "6e6d1754d27994703afe911508dff7baf36891caccf68dafefe9cacf50f9afe2"
PASSWORD_SALT = "670293dacfd4fe7fc14dea38e1945cbd4dba7553c82c50c5d6a2e949b95a58ff"

users = {
	"dmitry@edu.hse.ru":{
		"name": "dmitry",
		"password": '5c598437d3b8a8614a88f5656e2adf57b6b1fa79bfb4dcbbddcabe0d304b65eb',
		"balance": 100_100
		},
	"alex@edu.hse.ru":{
		"name": "alex",
		"password": '966d48beb80037409b1d6801e21f78cd6c705586d7d9353efa3eae2f5e73a05c',
		"balance": 250
		}

}


def sign_data(data: str) -> str:
    "Возвращает подписанные данные data"
    return hmac.new(
        SECRET_KEY.encode(),
        msg = data.encode(),
        digestmod = hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    print(username_signed)
    username_b64, sign = username_signed.split('.')
    username = base64.b64decode(username_b64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(password: str, password_hash: str) -> bool:
    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower() == password_hash.lower()

app = FastAPI()

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)

    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie("username")
        return response
    try:
        user = users[valid_username]
        return Response(f"Привет, {user['name']}!", media_type="text/html")
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie("username")
        return response


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form()):
    user = users.get(username)
    if not user or not verify_password(password, user['password']):
        return Response(json.dumps({"success": False,
                                    "message": "Пользователь не найден"
                                   }),
                                   media_type = "application/json")
    
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response = Response(json.dumps({"success": True,
                                    "message": f"Привет, {user['name']}! Ваш баланс: {user['balance']}"
                                       }), media_type = "application/json")
    response.set_cookie(key="username", value=username_signed)
    return response

