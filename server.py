import struct
import sys

from pymongo import MongoClient
from datetime import datetime
import json
import os
import socketserver
import uuid
import html
import requests
import pyotp
import subprocess

from util.multipart import parse_multipart
from util.request import Request
from util.response import Response
from util.router import Router
from util.hello_path import hello_path
from util.auth import extract_credentials, validate_password, hash_password, verify_password, hash_token, \
    generate_auth_token, decodeHelper
from util.websockets import generate_ws_frame,compute_accept,parse_ws_frame
from dotenv import load_dotenv
load_dotenv()
websocket_connections = set()
active_ws_connections = set()
from threading import Lock, Timer

active_users = {}
active_calls = {}
active_ws_users = {}
active_users_lock = Lock()
active_ws_users_id = {}
socket_mapping = {}


API_KEY = "90uBf0XhCKWcFaHIETqBxJkAqaIzM1cQ"
MAX_DURATION = 60
client = MongoClient("mongodb://localhost:27017/")
db = client["server"]
messages_collection = db["CSE312"]
users_collection = db["users"]
videos_collection = db["videos"]
drawings_collection = db["drawing"]
direct_messages_collection = db["direct_messages"]
video_calls_collection = db["video_calls"]

def publicfile(request, handler):
    mineType = {".html": "text/html",".css": "text/css",".js": "text/javascript",".jpg": "image/jpeg",".ico": "image/x-icon",".gif": "image/gif",".webp": "image/webp",".png": "image/png",".json": "application/json",".svg":"image/svg+xml",".mp4": "video/mp4",".mp3": "audio/mpeg"}
    path = request.path.replace("/","",1)

    if os.path.exists(path):
        with open(path, "rb") as f:
            content = f.read()
        if len(path.split(".",1)) > 1:
            extension = "." + path.split(".",1)[1]
            mine_type = {"Content-Type": mineType.get(extension)}
            res = Response()
            res.bytes(content)
            res.headers(mine_type)
            handler.request.sendall(res.to_data())
    else:
        res = Response().set_status(404, "Not Found")
        res.text("404 Not Found")
        handler.request.sendall(res.to_data())


def render(request, handler, page_file):
    layout = "public/layout/layout.html"
    page = "public/" + page_file

    if os.path.exists(layout) and os.path.exists(page):
        with open(layout, "r", encoding="utf-8") as layout_file:
            layoutContent = layout_file.read()
        with open(page, "r", encoding="utf-8") as page_file:
            pageContent = page_file.read()

        allContent = layoutContent.replace("{{content}}", pageContent)
        res = Response()
        res.text(allContent)
        res.headers({"Content-Type": "text/html"})
        handler.request.sendall(res.to_data())
    else:
        res = Response().set_status(404, "Not Found")
        handler.request.sendall(res.to_data())


def create_chat(request, handler):
    res = Response()
    auth_token = request.cookies.get("auth_token")
    user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None
    body = json.loads(request.body.decode())
    original_content = body.get("content", "")
    session_id = request.cookies.get("session")

    if original_content.startswith('/'):
        if not user or user.get("oauth_provider") != "github" or not user.get("github_access_token"):
            res = Response().set_status(400, "Bad Request").text("Commands require GitHub OAuth login")
            handler.request.sendall(res.to_data())
            return

        parts = original_content[1:].split()
        if not parts:
            res = Response().set_status(400, "Bad Request").text("Empty command")
            handler.request.sendall(res.to_data())
            return

        command = parts[0].lower()
        if command == "repos" or command == "star" or command == "createissue":
            pass
        else:
            res = Response().set_status(400, "Bad Request").text("Unknown command")
            handler.request.sendall(res.to_data())
            return
        args = parts[1:]
        headers = {"Authorization": f"token {user['github_access_token']}"}

        try:
            if command == "repos":
                if len(args) < 1:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return
                username = args[0]
                response = requests.get(f"https://api.github.com/users/{username}/repos", headers=headers)
                if response.status_code != 200:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return

                repos = response.json()[:50]
                repo_links = [f'<a href="{repo["html_url"]}">{repo["name"]}</a>' for repo in repos]
                content = "Repositories:<br>" + "<br>".join(repo_links)

            elif command == "star":
                if len(args) < 1 or '/' not in args[0]:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return
                repo = args[0]
                response = requests.put(f"https://api.github.com/user/starred/{repo}", headers=headers)
                if response.status_code not in [204, 304]:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return
                content = f'⭐ Starred <a href="https://github.com/{repo}">{repo} click text to view</a>'

            elif command == "createissue":
                if len(args) < 2 or '/' not in args[0]:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return
                repo = args[0]
                title = ' '.join(args[1:])
                response = requests.post(
                    f"https://api.github.com/repos/{repo}/issues",
                    headers=headers,
                    json={"title": title, "body": ""}
                )
                if response.status_code != 201:
                    res = Response().set_status(400, "Bad Request").text("Unknown error")
                    handler.request.sendall(res.to_data())
                    return
                issue_url = response.json()["html_url"]
                content = f'📝 Created issue: <a href="{issue_url}">{title} click text to view</a>'

            else:
                res = Response().set_status(400, "Bad Request").text("Unknown error")
                handler.request.sendall(res.to_data())
                return

        except Exception as e:
            res = Response().set_status(400, "Bad Request").text(str(e))
            handler.request.sendall(res.to_data())
            return
    else:
        content = html.escape(original_content)

    if user:
        user_id = user["user_id"]
        author = user["username"]
        imageURL = user.get("imageURL")
        if not imageURL:
            existing_message = messages_collection.find_one({"user_id": user_id})
            if existing_message:
                imageURL = existing_message.get("imageURL")
            else:
                response = requests.get(f"https://api.dicebear.com/9.x/croodles-neutral/svg?seed={auth_token}")
                if response.status_code == 200:
                    save_dir = "public/imgs/profile-pics"
                    os.makedirs(save_dir, exist_ok=True)
                    filename = f"{auth_token}.svg"
                    save_path = os.path.join(save_dir, filename)
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                    imageURL = f"/public/imgs/profile-pics/{filename}"
                    users_collection.update_one(
                        {"user_id": user_id},
                        {"$set": {"imageURL": imageURL}}
                    )
    # if user:
    #     user_id = user["user_id"]
    #     existing_message = messages_collection.find_one({"user_id": user_id})
    #     author = user["username"]
    #     if existing_message:
    #         imageURL = existing_message.get("imageURL")
    #     else:
    #         response = requests.get(f"https://api.dicebear.com/9.x/croodles-neutral/svg?seed={auth_token}")
    #         if response.status_code == 200:
    #             profile_pic_dir = "public/imgs/profile-pics"
    #             os.makedirs(profile_pic_dir, exist_ok=True)
    #             profile_pic_path = f"{profile_pic_dir}/{auth_token}.svg"
    #             with open(profile_pic_path, "wb") as f:
    #                 f.write(response.content)
    #             imageURL = f"/public/imgs/profile-pics/{auth_token}.svg"
    else:
        if not session_id:
            session_id = str(uuid.uuid4())
            author = f"User-{session_id[:8]}"
            response = requests.get(f"https://api.dicebear.com/9.x/croodles-neutral/svg?seed={session_id}")
            if response.status_code == 200:
                profile_pic_dir = "public/imgs/profile-pics"
                os.makedirs(profile_pic_dir, exist_ok=True)
                profile_pic_path = f"{profile_pic_dir}/{session_id}.svg"
                with open(profile_pic_path, "wb") as f:
                    f.write(response.content)
                imageURL = f"/public/imgs/profile-pics/{session_id}.svg"
        else:
            existing_message = messages_collection.find_one({"session_id": session_id})
            if existing_message:
                author = existing_message["author"]
                imageURL = existing_message.get("imageURL")
            else:
                author = f"User-{session_id[:8]}"
                response = requests.get(f"https://api.dicebear.com/9.x/croodles-neutral/svg?seed={session_id}")
                if response.status_code == 200:
                    profile_pic_dir = "public/imgs/profile-pics"
                    os.makedirs(profile_pic_dir, exist_ok=True)
                    profile_pic_path = f"{profile_pic_dir}/{session_id}.svg"
                    with open(profile_pic_path, "wb") as f:
                        f.write(response.content)
                    imageURL = f"/public/imgs/profile-pics/{session_id}.svg"
                else:
                    imageURL = "/public/imgs/profile-pics/default.svg"

    message_id = str(uuid.uuid4())
    message = {
        "id": message_id,
        "session_id": session_id,
        "author": author,
        "content": content,
        "updated": False,
        "reactions": '',
        "imageURL": imageURL,
        "user_id": user["user_id"] if user else None
    }
    messages_collection.insert_one(message)

    if "Cookie" not in request.headers:
        res.cookies({"session": session_id + ";HttpOnly;Path=/"})

    res.text("message sent")
    handler.request.sendall(res.to_data())


def get_chats(request, handler):
    all_messages = list(messages_collection.find({}, {"_id": 0, "session": 0}))
    # all_reactions = list(messages_collection.find({}, {"reactions": 0, "session": 0}))
    data = {"messages": all_messages}
    res = Response().json(data)
    handler.request.sendall(res.to_data())

def update_chat(request, handler):
    chat_id = request.path.split("/")[-1]
    data = json.loads(request.body.decode())
    new_content = html.escape(data["content"])
    message = messages_collection.find_one({"id": chat_id})
    session_id = request.cookies.get("session")
    if session_id:
        if session_id != message["session_id"]:
            res = Response().set_status(403, "Forbidden").text("You can only update your own messages.")
            handler.request.sendall(res.to_data())
            return

        messages_collection.update_one({"id": chat_id}, {"$set": {"content": new_content, "updated": True}})
        res = Response().text("Message updated successfully.")
        handler.request.sendall(res.to_data())
        return

    if not message:
        res = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(res.to_data())
        return

    auth_token = request.cookies.get("auth_token")
    user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None

    if not user or message.get("user_id") != user["user_id"]:
        res = Response().set_status(403, "Forbidden").text("You can only update your own messages.")
        handler.request.sendall(res.to_data())
        return

    messages_collection.update_one({"id": chat_id}, {"$set": {"content": new_content, "updated": True}})
    res = Response().text("Message updated successfully.")
    handler.request.sendall(res.to_data())

def delete_chat(request, handler):
    chat_id = request.path.split("/")[-1]
    message = messages_collection.find_one({"id": chat_id})
    if not message:
        res = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(res.to_data())
        return

    session_id = request.cookies.get("session")
    if session_id:
        if session_id != message["session_id"]:
            res = Response().set_status(403, "Forbidden").text("You can only delete your own messages.")
            res.cookies({"session": session_id})
            handler.request.sendall(res.to_data())
            return

        messages_collection.delete_one({"id": chat_id})
        res = Response().text("Message deleted successfully.")
        handler.request.sendall(res.to_data())
        return

    auth_token = request.cookies.get("auth_token")
    user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None

    if not user or message.get("user_id") != user["user_id"]:
        res = Response().set_status(403, "Forbidden").text("You can only delete your own messages.")
        handler.request.sendall(res.to_data())
        return

    messages_collection.delete_one({"id": chat_id})
    res = Response().text("Message deleted successfully.")
    handler.request.sendall(res.to_data())

def add_reaction(request, handler):
    message_id = request.path.split("/")[-1]
    data = json.loads(request.body.decode())
    emoji = html.escape(data["emoji"])

    message = messages_collection.find_one({"id": message_id})
    session_id = request.cookies.get("session")
    if not session_id:
        res = Response().set_status(403, "Forbidden").text("Forbidden.")
        handler.request.sendall(res.to_data())
        return

    if not isinstance(message.get("reactions"), dict):
        message["reactions"] = {}

    if emoji in message["reactions"] and session_id in message["reactions"][emoji]:
        res = Response().set_status(403, "Forbidden").text("You already reacted with this emoji.")
        handler.request.sendall(res.to_data())
        return

    message["reactions"].setdefault(emoji, []).append(session_id)
    messages_collection.update_one({"id": message_id}, {"$set": {"reactions": message["reactions"]}})

    res = Response().text("Reaction added successfully.")
    handler.request.sendall(res.to_data())

def remove_reaction(request, handler):
    message_id = request.path.split("/")[-1]
    data = json.loads(request.body.decode())
    emoji = html.escape(data["emoji"])

    message = messages_collection.find_one({"id": message_id})
    if not message:
        res = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(res.to_data())
        return

    session_id = request.cookies.get("session")
    if not session_id:
        res = Response().set_status(403, "Forbidden").text("Forbidden.")
        handler.request.sendall(res.to_data())
        return

    reactions = message.get("reactions", {})
    if emoji not in reactions or session_id not in reactions[emoji]:
        res = Response().set_status(403, "Forbidden").text("You can only remove your own reactions.")
        handler.request.sendall(res.to_data())
        return

    reactions[emoji].remove(session_id)
    if not reactions[emoji]:
        del reactions[emoji]

    messages_collection.update_one({"id": message_id}, {"$set": {"reactions": reactions}})
    res = Response().text("Reaction removed successfully.")
    handler.request.sendall(res.to_data())


def update_nickname(request, handler):
    session_id = request.cookies.get("session")
    data = json.loads(request.body.decode())
    new_nickname = html.escape(data.get("nickname", "").strip())

    if not new_nickname:
        res = Response().set_status(400, "Bad Request").text("Nickname cannot be empty.")
        handler.request.sendall(res.to_data())
        return

    existing_name = messages_collection.find_one({"author": new_nickname})
    if existing_name:
        res = Response().set_status(400, "Bad Request").text("Nickname exists.")
        handler.request.sendall(res.to_data())
        return

    messages_collection.update_many({"session_id": session_id},{"$set": {"author": new_nickname}})

    res = Response().text("Nickname updated successfully.")
    handler.request.sendall(res.to_data())


def register_user(request, handler):
    credentials = extract_credentials(request)
    if len(credentials) > 2:
        username = credentials["username"]
        password = credentials["password"]
    else:
        username,password = extract_credentials(request)

    if not username or not password:
        res = Response().set_status(400, "Bad Request").text("Username and password are required.")
        handler.request.sendall(res.to_data())
        return

    if not validate_password(password):
        res = Response().set_status(400, "Bad Request").text("Password does not meet the requirements.")
        handler.request.sendall(res.to_data())
        return

    if users_collection.find_one({"username": username}):
        res = Response().set_status(400, "Bad Request").text("Username already exists.")
        handler.request.sendall(res.to_data())
        return

    user_id = str(uuid.uuid4())
    hashed_password = hash_password(password)

    user = {"user_id": user_id,"username": username,"password": hashed_password,"auth_token": None}

    users_collection.insert_one(user)

    session_id = request.cookies.get("session")
    if session_id:
        messages_collection.update_many({"session_id": session_id, "user_id": None},{"$set": {"user_id": user_id}})

    res = Response().text("Registration successful.")
    handler.request.sendall(res.to_data())


def login_user(request, handler):
    credentials = extract_credentials(request)
    if len(credentials) > 2:
        username = credentials["username"]
        password = credentials["password"]
        totp_code = credentials.get("totpCode", "")

        user = users_collection.find_one({"username": username})

        if not user or not verify_password(user["password"], password):
            res = Response().set_status(400, "Unauthorized").text("Invalid username or password.")
            handler.request.sendall(res.to_data())
            return

        if user.get("totp_secret"):
            if not totp_code:
                res = Response().set_status(401, "Unauthorized").text("TOTP code required for 2FA.")
                handler.request.sendall(res.to_data())
                return

            totp = pyotp.TOTP(user["totp_secret"])
            if not totp.verify(totp_code, valid_window=1):
                res = Response().set_status(401, "Unauthorized").text("Invalid TOTP code.")
                handler.request.sendall(res.to_data())
                return
    else:
        username, password = extract_credentials(request)

    if not username or not password:
        res = Response().set_status(400, "Bad Request").text("Username and password are required.")
        handler.request.sendall(res.to_data())
        return

    user = users_collection.find_one({"username": username})

    if not user or not verify_password(user["password"], password):
        res = Response().set_status(400, "Unauthorized").text("Invalid username or password.")
        handler.request.sendall(res.to_data())
        return

    auth_token = generate_auth_token()
    hashed_token = hash_token(auth_token)
    users_collection.update_one({"user_id": user["user_id"]}, {"$set": {"auth_token": hashed_token}})

    res = Response().text("Login successful.")

    session_id = request.cookies.get("session")
    user_id = user["user_id"]
    existing_message = messages_collection.find_one({"user_id": user_id})
    if session_id:
        if existing_message:
            imageURL = existing_message.get("imageURL")
            messages_collection.update_many({"session_id": session_id},{"$set": {"author": username,"imageURL": imageURL,"user_id": user_id}})
        else: messages_collection.update_many({"session_id": session_id},{"$set": {"author": username,"user_id": user_id}})

    res.headers({"Location": "/chat"})
    res.cookies({"auth_token": auth_token + ";Max-Age=3600;HttpOnly","session": "deleted;Max-Age=0;HttpOnly"})
    handler.request.sendall(res.to_data())


def logout_user(request, handler):
    auth_token = request.cookies.get("auth_token")

    if not auth_token:
        res = Response().set_status(400, "Not Found").text("No user found/no auth_token").headers({"Location": "/chat"})
        handler.request.sendall(res.to_data())
        return

    user = users_collection.find_one({"auth_token": hash_token(auth_token)})
    print(user)
    if user is None:
        res = Response().set_status(400, "Not Found").text("No user found/invalid token").headers({"Location": "/chat"})
        handler.request.sendall(res.to_data())
        return

    if auth_token:
        hashed_token = hash_token(auth_token)

        user = users_collection.find_one({"auth_token": hashed_token})
        if user:
            users_collection.update_one({"user_id": user["user_id"]}, {"$set": {"auth_token": None}})

    res = Response().set_status(302, "Found").headers({"Location": "/chat"})
    res.cookies({"auth_token": "deleted;Max-Age=0;HttpOnly","oauth_state": "deleted;Max-Age=0;HttpOnly"})
    handler.request.sendall(res.to_data())



def get_user_profile(request, handler):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        res = Response().set_status(401, "Unauthorized").json({"username": '', "id": '', "imageURL": ''})
        handler.request.sendall(res.to_data())
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})
    if not user:
        res = Response().set_status(401, "Unauthorized").json({"username": '', "id": '', "imageURL": ''})
        handler.request.sendall(res.to_data())
        return

    res = Response().json({
        "username": user["username"],
        "id": user["user_id"],
        "imageURL": user.get("imageURL", "")
    })
    handler.request.sendall(res.to_data())

def search_users(request, handler):
    query = request.path.split("?")[1] if "?" in request.path else ""
    query_params = query.split("&")
    search_term = None

    for param in query_params:
        if param.startswith("user="):
            search_term = param.split("=")[1]
            break

    if not search_term:
        return

    users = list(users_collection.find({"username": {"$regex": f"^{search_term}"}}, {"_id": 0, "user_id": 1, "username": 1}))
    output = []
    for user in users:
        print(user)
        output.append({"id": user["user_id"], "username": user["username"]})

    res = Response().json({"users": output})
    #print(b"NOooooooooooooooooooooooooooooooooooooooooooooo" + res.to_data())
    handler.request.sendall(res.to_data())


def update_profile(request, handler):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        res = Response().set_status(401, "Unauthorized").text("Unauthorized")
        handler.request.sendall(res.to_data())
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})
    if not user:
        res = Response().set_status(401, "Unauthorized").text("Unauthorized")
        handler.request.sendall(res.to_data())
        return

    credentials = extract_credentials(request)
    if len(credentials) > 2:
        username = credentials["username"]
        password = credentials["password"]
    else:
        username, password = extract_credentials(request)

    if not username:
        hashed_password = hash_password(password)
        users_collection.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"password": hashed_password}}
        )
        res = Response().text("Profile updated successfully.")
        handler.request.sendall(res.to_data())
        return
    if not password:
        users_collection.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"username": username}}
        )
        res = Response().text("Profile updated successfully.")
        handler.request.sendall(res.to_data())
        return

    if not validate_password(password):
        res = Response().set_status(400, "Bad Request").text("Password does not meet the requirements.")
        handler.request.sendall(res.to_data())
        return

    hashed_password = hash_password(password)
    users_collection.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"username": username, "password": hashed_password}}
    )

    res = Response().text("Profile updated successfully.")
    handler.request.sendall(res.to_data())

def regenerate_2fa(request, handler):
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        res = Response().set_status(401, "Unauthorized").text("Unauthorized")
        handler.request.sendall(res.to_data())
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})
    if not user:
        res = Response().set_status(401, "Unauthorized").text("Unauthorized")
        handler.request.sendall(res.to_data())
        return


    new_secret = pyotp.random_base32()
    users_collection.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"totp_secret": new_secret}}
    )

    res = Response().json({"secret": new_secret})
    handler.request.sendall(res.to_data())


def auth_github(request, handler):
    state = generate_auth_token()
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={os.getenv('GITHUB_CLIENT_ID')}&"
        f"redirect_uri=http://localhost:8080/authcallback&"
        f"scope=user:email,public_repo&"
        f"state={state}"
    )
    res = Response()
    res.set_status(302, "Found")
    res.headers({"Location": github_auth_url})
    res.cookies({"oauth_state": f"{state}; HttpOnly; Path=/"})
    handler.request.sendall(res.to_data())


def auth_callback(request, handler):
    path = request.path
    query_params = {}
    if '?' in path:
        _, query_str = path.split('?', 1)
        for param in query_str.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                key = decodeHelper(key)
                value = decodeHelper(value)
                query_params[key] = value

    code = query_params.get('code', '')
    state = query_params.get('state', '')
    stored_state = request.cookies.get('oauth_state', '')

    if not code or state != stored_state:
        res = Response().set_status(403, "Forbidden").text("Invalid request")
        handler.request.sendall(res.to_data())
        return

    token_data = {
        'client_id': os.getenv('GITHUB_CLIENT_ID'),
        'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
        'code': code,
        'redirect_uri': 'http://localhost:8080/authcallback'
    }
    headers = {'Accept': 'application/json'}
    token_res = requests.post('https://github.com/login/oauth/access_token', data=token_data, headers=headers)
    if token_res.status_code != 200:
        res = Response().set_status(400, "Bad Request").text("OAuth failed")
        handler.request.sendall(res.to_data())
        return
    access_token = token_res.json().get('access_token')

    user_res = requests.get('https://api.github.com/user', headers={'Authorization': f'token {access_token}'})
    if user_res.status_code != 200:
        res = Response().set_status(400, "Bad Request").text("Failed to fetch user data")
        handler.request.sendall(res.to_data())
        return
    user_data = user_res.json()
    username = user_data.get('login')
    email = user_data.get('email')

    if not username:
        email_res = requests.get('https://api.github.com/user/emails',
                                 headers={'Authorization': f'token {access_token}'})
        if email_res.status_code == 200:
            emails = email_res.json()
            primary_email = next((e['email'] for e in emails if e.get('primary')), None)
            username = primary_email.split('@')[0] if primary_email else None

    if not username:
        res = Response().set_status(400, "Bad Request").text("Username not found")
        handler.request.sendall(res.to_data())
        return

    user = users_collection.find_one({"username": username})
    if not user:
        user_id = str(uuid.uuid4())
        hashed_pw = hash_password(generate_auth_token())
        auth_token = generate_auth_token()
        hashed_token = hash_token(auth_token)
        users_collection.insert_one({
            "user_id": user_id,
            "username": username,
            "password": hashed_pw,
            "auth_token": hashed_token,
            "oauth_provider": "github",
            "github_access_token": access_token
        })
    else:
        auth_token = generate_auth_token()
        hashed_token = hash_token(auth_token)
        users_collection.update_one(
            {"user_id": user["user_id"]},
            {"$set": {
                "auth_token": hashed_token,
                "oauth_provider": "github",
                "github_access_token": access_token
            }}
        )

    res = Response()
    res.set_status(302, "Found")
    res.headers({"Location": "/chat"})
    res.cookies({
        "auth_token": f"{auth_token}; Max-Age=3600; HttpOnly; Path=/",
        "session": "deleted; Max-Age=0; HttpOnly"
    })
    handler.request.sendall(res.to_data())


def handle_avatar_upload(request, handler):
    res = Response()
    auth_token = request.cookies.get("auth_token")

    if not auth_token:
        res.set_status(401, "Unauthorized").text("login requesed")
        handler.request.sendall(res.to_data())
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})
    if not user:
        res.set_status(401, "Unauthorized").text("Invalid auth token")
        handler.request.sendall(res.to_data())
        return
    try:
        multipart_data = parse_multipart(request)
    except ValueError:
        res.set_status(400, "Bad Request").text("Invalid request")
        handler.request.sendall(res.to_data())
        return

    uploaded_file = None
    for part in multipart_data.parts:
        if part.name == "avatar" and part.filename:
            uploaded_file = part
            break

    if not uploaded_file:
        res.set_status(400, "Bad Request").text("not found avatar")
        handler.request.sendall(res.to_data())
        return

    allowed_extensions = {".jpg", ".jpeg", ".png", ".gif"}
    file_ext = os.path.splitext(uploaded_file.filename.lower())[1]
    if file_ext not in allowed_extensions:
        res.set_status(400, "Bad Request").text("JPG/PNG/GIF only")
        handler.request.sendall(res.to_data())
        return

    file_uuid = str(uuid.uuid4())
    new_filename = f"{file_uuid}{file_ext}"
    save_path = os.path.join("public/imgs/profile-pics", new_filename)
    image_url = f"/public/imgs/profile-pics/{new_filename}"

    if user.get("imageURL"):
        old_path = user["imageURL"].lstrip("/")
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except Exception as e:
                print(f"fail to delete old profile: {e}")

    try:
        os.makedirs("public/imgs/profile-pics", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(uploaded_file.content)
    except Exception as e:
        res.set_status(500, "Internal Error").text("failed to save profile")
        handler.request.sendall(res.to_data())
        return

    users_collection.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"imageURL": image_url}}
    )

    messages_collection.update_many(
        {"user_id": user["user_id"]},
        {"$set": {"imageURL": image_url}}
    )

    res.set_status(200, "OK").text("updated profile")
    handler.request.sendall(res.to_data())


def handle_video_upload(request, handler):
    res = Response()
    try:
        auth_token = request.cookies.get("auth_token")
        if not auth_token:
            res.set_status(401, "Unauthorized").text("Login required")
            handler.request.sendall(res.to_data())
            return

        hashed_token = hash_token(auth_token)
        user = users_collection.find_one({"auth_token": hashed_token})
        if not user:
            res.set_status(401, "Unauthorized").text("Invalid authentication token")
            handler.request.sendall(res.to_data())
            return

        multipart_data = parse_multipart(request)

        title_part = next((p for p in multipart_data.parts if p.name == "title"), None)
        description_part = next((p for p in multipart_data.parts if p.name == "description"), None)
        video_part = next((p for p in multipart_data.parts if p.name == "video" and p.filename), None)

        if not all([title_part, video_part]):
            res.set_status(400, "Bad Request").text("Missing required fields")
            handler.request.sendall(res.to_data())
            return

        if not video_part.filename.lower().endswith(".mp4"):
            res.set_status(400, "Bad Request").text("Only MP4 format is supported")
            handler.request.sendall(res.to_data())
            return

        video_id = str(uuid.uuid4())
        file_ext = os.path.splitext(video_part.filename)[1]
        filename = f"{video_id}{file_ext}"
        save_path = os.path.join("public/videos", filename)
        os.makedirs("public/videos", exist_ok=True)

        with open(save_path, "wb") as f:
            f.write(video_part.content)

        transcription_id = None

        try:
            audio_dir = "public/audio"
            os.makedirs(audio_dir, exist_ok=True)
            audio_path = os.path.join(audio_dir, f"{video_id}.mp3")

            subprocess.run(
                ["ffmpeg", "-y", "-i", save_path, "-vn", "-acodec", "libmp3lame", audio_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )

            duration = float(subprocess.check_output(
                f"ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 {save_path}",
                shell=True
            ).decode().strip())
            if duration >= 60:
                transcription_id = "Cancelled"
            if duration <= 60 and os.path.exists(audio_path):
                with open(audio_path, "rb") as audio_file:
                    files = {"file": (f"{video_id}.mp3", audio_file, "audio/mpeg")}
                    headers = {"Authorization": f"Bearer 90uBf0XhCKWcFaHIETqBxJkAqaIzM1cQ"}

                    api_response = requests.post(
                        "https://transcription-api.nico.engineer/transcribe",
                        files=files,
                        headers=headers,
                        timeout=10
                    )

                    if api_response.status_code == 200:
                        transcription_id = api_response.json().get("unique_id")

        except subprocess.CalledProcessError as e:
            print(f"Audio processing failed: {e.stderr.decode()}")
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {str(e)}")
        except Exception as e:
            print(f"Transcription error: {str(e)}")

        thumbnails = []
        thumbnail_dir = "public/imgs/thumbnails"
        os.makedirs(thumbnail_dir, exist_ok=True)

        time_points = [
            0,
            duration * 0.25,
            duration * 0.5,
            duration * 0.75,
            max(0, duration - 1)
        ]

        for index, t in enumerate(time_points):
            thumbnail_path = os.path.join(thumbnail_dir, f"{video_id}_{index}.jpg")
            cmd = [
                "ffmpeg",
                "-y",
                "-ss", str(t),
                "-i", save_path,
                "-vframes", "1",
                "-q:v", "2",
                "-vf", "scale=300:168:force_original_aspect_ratio=decrease",
                thumbnail_path
            ]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )
                if os.path.exists(thumbnail_path):
                    thumbnails.append(f"public/imgs/thumbnails/{video_id}_{index}.jpg")
                else:
                    print(f"Thumbnail generation failed: {thumbnail_path}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"FFmpeg error: {e.stderr.decode() if e.stderr else 'Unknown error'}")

        hls_dir = "public/videos"
        master_playlist = encode_hls_variants(save_path, hls_dir, video_id)

        video_data = {
            "author_id": user["user_id"],
            "title": title_part.content.decode("utf-8"),
            "description": description_part.content.decode("utf-8") if description_part else "",
            "video_path": f"public/videos/{filename}",
            "created_at": datetime.now().isoformat(),
            "id": video_id,
            "thumbnails": thumbnails,
            "thumbnailURL": thumbnails[0] if thumbnails else "",
            "duration": duration,
            "transcription_id": transcription_id,
            "hls_path": master_playlist.replace("\\","/")
        }

        videos_collection.insert_one(video_data)


        res.set_status(200, "OK").json({
            "id": video_id,
            "thumbnails": thumbnails,
            "message": "Video uploaded successfully",
            "transcription_status": "pending" if transcription_id else "failed"
        })

    except Exception as e:
        print(f"Upload error: {str(e)}")
        res.set_status(500, "Internal Server Error").text(f"Server error: {str(e)}")

    handler.request.sendall(res.to_data())


def get_all_videos(request, handler):
    videos = list(videos_collection.find({}, {"_id": 0}))
    res = Response().json({"videos": videos})
    handler.request.sendall(res.to_data())


def get_single_video(request, handler):
    video_id = request.path.split("/")[-1]
    video = videos_collection.find_one({"id": video_id}, {"_id": 0})
    if not video:
        res = Response().set_status(404, "Not Found").text("Video not found")
    else:
        res = Response().json({"video": video})

    handler.request.sendall(res.to_data())


def get_transcriptions(request, handler):
    video_id = request.path.split("/")[-1]
    video = videos_collection.find_one({"id": video_id})

    if video.get("transcription_id") == "Cancelled":
        res = Response().set_status(200, "OK").text("Transcription cancelled b/c video over 1min")
        handler.request.sendall(res.to_data())
        return

    if not video or not video.get("transcription_id"):
        res = Response().set_status(404, "Not Found").text("Transcription not found")
        handler.request.sendall(res.to_data())
        return

    try:
        headers = {"Authorization": "Bearer 90uBf0XhCKWcFaHIETqBxJkAqaIzM1cQ"}
        api_response = requests.get(
            f'https://transcription-api.nico.engineer/transcriptions/{video["transcription_id"]}',
            headers=headers,
            timeout=10
        )

        if api_response.status_code == 200:
            vtt_url = api_response.json().get("s3_url")
            vtt_response = requests.get(vtt_url)
            res = Response()
            res.headers({
                'Content-Type': 'text/vtt',
                'Cache-Control': 'max-age=3600'
            })
            res.bytes(vtt_response.content)
        elif api_response.status_code == 420:
            res = Response().set_status(425, "Too Early").text("Transcription in progress, please try again later")
        else:
            res = Response().set_status(500, "Internal Error").text("Transcription service temporarily unavailable")

    except requests.exceptions.Timeout:
        res = Response().set_status(504, "Gateway Timeout").text("Transcription service response timed out")
    except Exception as e:
        res = Response().set_status(500, "Internal Error").text(str(e))

    handler.request.sendall(res.to_data())


def update_thumbnail(request, handler):
    video_id = request.path.split("/")[-1]
    data = json.loads(request.body.decode())

    try:
        result = videos_collection.update_one(
            {"id": video_id},
            {"$set": {"thumbnailURL": data["thumbnailURL"]}}
        )

        if result.modified_count == 0:
            res = Response().set_status(404, "Not Found").json({"message": "Video not found"})
        else:
            res = Response().json({"message": "Thumbnail updated successfully"})

    except Exception as e:
        res = Response().set_status(500, "Internal Error").json({"message": str(e)})

    handler.request.sendall(res.to_data())


def encode_hls_variants(input_path, output_dir, video_id):
    variants = [
        {"height": 720, "bitrate": "3000k", "audio": "128k"},
        {"height": 480, "bitrate": "1500k", "audio": "96k"}
    ]

    hls_path = os.path.join(output_dir, video_id)
    os.makedirs(hls_path, exist_ok=True)

    for var in variants:
        subprocess.run([
            'ffmpeg', '-y', '-i', input_path,
            '-vf', f'scale=-2:{var["height"]}',
            '-c:v', 'libx264', '-b:v', var["bitrate"],
            '-c:a', 'aac', '-b:a', var["audio"],
            '-f', 'hls',
            '-hls_time', '10',
            '-hls_list_size', '0',
            '-hls_segment_filename', f'{hls_path}/{var["height"]}p_%03d.ts',
            f'{hls_path}/{var["height"]}p.m3u8'
        ], check=True)

    master_content = '#EXTM3U\n#EXT-X-VERSION:3\n'
    for var in variants:
        master_content += (
            f'#EXT-X-STREAM-INF:BANDWIDTH={int(var["bitrate"][:-1]) * 1000},RESOLUTION=1280x{var["height"]}\n'
            f'{var["height"]}p.m3u8\n'
        )

    master_path = os.path.join(hls_path, 'master.m3u8')
    with open(master_path, 'w') as f:
        f.write(master_content)
    return master_path


def handle_websocket_upgrade(request, handler):
    auth_token = request.cookies.get("auth_token")
    user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None
    username = user.get("username")
    if request.headers.get("Upgrade", "").lower() != "websocket":
        res = Response().set_status(400, "Bad Request").text("Not a websocket request")
        handler.request.sendall(res.to_data())
        return

    client_key = request.headers.get("Sec-WebSocket-Key", "")
    if not client_key:
        res = Response().set_status(400, "Bad Request").text("Missing Sec-WebSocket-Key")
        handler.request.sendall(res.to_data())
        return

    accept_key = compute_accept(client_key)
    res = Response()
    res.set_status(101, "Switching Protocols")
    res.headers({
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Accept": accept_key
    })
    handler.request.sendall(res.to_data())

    with active_users_lock:
        active_users[handler.request] = username

    broadcast_user_list()

    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        handler.request.close()
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})
    if not user:
        handler.request.close()
        return

    active_ws_users[handler.request] = user["username"]
    if user["username"] not in active_ws_users_id:
        active_ws_users_id.update({user["username"]: id(handler.request)})

    websocket_connections.add(handler.request)
    current_message = {
        'opcode': None,
        'payload': bytearray(),
        'fragmented': False
    }

    try:
        all_strokes = list(drawings_collection.find({}, {"_id": 0}))
        init_message = {
            "messageType": "init_strokes",
            "strokes": all_strokes
        }
        handler.request.sendall(generate_ws_frame(json.dumps(init_message).encode('utf-8')))

        buffer = bytearray()
        handler.request.setblocking(False)

        while True:
            try:
                chunk = handler.request.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                while True:
                    if len(buffer) < 2:
                        break

                    first_byte = buffer[0]
                    second_byte = buffer[1]
                    fin = (first_byte >> 7) & 0x01
                    opcode = first_byte & 0x0F
                    mask_bit = (second_byte >> 7) & 0x01
                    payload_len = second_byte & 0x7F

                    header_len = 2
                    if payload_len == 126:
                        if len(buffer) < 4:
                            break
                        payload_len = int.from_bytes(buffer[2:4], byteorder='big')
                        header_len += 2
                    elif payload_len == 127:
                        if len(buffer) < 10:
                            break
                        payload_len = int.from_bytes(buffer[2:10], byteorder='big')
                        header_len += 8

                    mask_key = None
                    if mask_bit:
                        header_len += 4
                        if len(buffer) < header_len:
                            break
                        mask_key = buffer[header_len - 4:header_len]
                    if len(buffer) < header_len + payload_len:
                        break

                    frame_data = bytes(buffer[:header_len + payload_len])
                    del buffer[:header_len + payload_len]

                    frame = parse_ws_frame(frame_data)

                    if current_message['fragmented']:
                        if opcode != 0x0:
                            close_frame = generate_ws_frame(b'')
                            handler.request.sendall(close_frame)
                            raise ConnectionResetError("Protocol error: Unexpected opcode during fragmentation")

                        current_message['payload'].extend(frame.payload)

                        if fin:
                            process_complete_message(
                                handler,
                                current_message['opcode'],
                                bytes(current_message['payload']),
                                request
                            )
                            current_message['opcode'] = None
                            current_message['payload'] = bytearray()
                            current_message['fragmented'] = False
                    else:
                        if opcode == 0x0:
                            close_frame = generate_ws_frame(b'')
                            handler.request.sendall(close_frame)
                            raise ConnectionResetError("Protocol error: Continuation frame without context")

                        current_message['opcode'] = opcode

                        if not fin:
                            current_message['fragmented'] = True
                            current_message['payload'].extend(frame.payload)
                        else:
                            process_complete_message(handler, opcode, frame.payload, request)

                    if opcode == 0x8:
                        close_code = 1000
                        if len(frame.payload) >= 2:
                            close_code = int.from_bytes(frame.payload[:2], 'big')
                        handler.request.sendall(generate_ws_frame(b''))
                        raise ConnectionResetError(f"Client closed connection with code {close_code}")

                    elif opcode == 0x9:
                        handler.request.sendall(generate_ws_frame(frame.payload))

            except BlockingIOError:
                continue
            except ConnectionResetError as e:
                print(f"Connection reset: {str(e)}")
                break
            except Exception as e:
                print(f"WebSocket error: {str(e)}")
                break

    finally:
        try:
            with active_users_lock:
                if handler.request in active_users:
                    del active_users[handler.request]
            broadcast_user_list()
            websocket_connections.discard(handler.request)
            active_ws_users_id.pop(user["username"])
            handler.request.close()
            socket_id = id(handler.request)
            for call_id in list(active_calls.keys()):
                if socket_id in active_calls[call_id]["participants"]:
                    remove_from_call(call_id, socket_id)
            if socket_id in socket_mapping:
                del socket_mapping[socket_id]
            print(f"WebSocket connection closed. Active connections: {len(websocket_connections)}")
        except Exception as e:
            print(f"Error during connection cleanup: {str(e)}")


def process_complete_message(handler, opcode, payload, request):
    auth_token = request.cookies.get("auth_token")
    user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None
    username = user.get("username")
    try:
        if opcode == 0x1:
            message = payload.decode('utf-8', 'strict')
            msg = json.loads(message)
            # print(msg)
            current_user = get_current_user(handler,request)

            if msg.get("messageType") == "echo_client":
                response = {
                    "messageType": "echo_server",
                    "text": msg["text"]
                }
                handler.request.sendall(generate_ws_frame(json.dumps(response).encode()))

            elif msg.get("messageType") == "get_all_users":
                if not current_user:
                    send_error(handler, "Authentication required")
                    return

                all_users = list(users_collection.find(
                    {},
                    {"_id": 0, "username": 1, "user_id": 1}
                ))

                response = {
                    "messageType": "all_users_list",
                    "users": all_users
                }
                handler.request.sendall(generate_ws_frame(json.dumps(response).encode()))

            elif msg.get("messageType") == "select_user":
                if not current_user:
                    send_error(handler, "Authentication required")
                    return

                target_user = msg.get("targetUser")
                if not target_user:
                    send_error(handler, "Invalid target user")
                    return

                history = list(direct_messages_collection.find({
                    "$or": [
                        {"$and": [
                            {"fromUser": username},
                            {"toUser": target_user}
                        ]},
                        {"$and": [
                            {"fromUser": target_user},
                            {"toUser": username}
                        ]}
                    ]
                }, {"_id": 0}))

                response = {
                    "messageType": "message_history",
                    "messages": [{
                        "messageType": "direct_message",
                        "fromUser": msg["fromUser"],
                        "text": msg["text"],
                    } for msg in history]
                }
                handler.request.sendall(generate_ws_frame(json.dumps(response).encode()))

            elif msg.get("messageType") == "direct_message":
                if not current_user:
                    send_error(handler, "Authentication required")
                    return

                target_user = msg.get("targetUser")
                message_text = msg.get("text", "").strip()

                target_user_data = users_collection.find_one(
                    {"username": target_user},
                    {"_id": 0, "username": 1}
                )
                if not target_user_data:
                    send_error(handler, "User not found")
                    return

                message_data = {
                    "messageType": "direct_message",
                    "fromUser": username,
                    "toUser": target_user,
                    "text": message_text,
                }
                direct_messages_collection.insert_one(message_data.copy())
                forward_msg = {
                    "messageType": "direct_message",
                    "fromUser": username,
                    "text": message_text,
                }
                handler.request.sendall(generate_ws_frame(json.dumps(forward_msg).encode()))

                receiver_conn = find_user_connection(target_user)
                if receiver_conn:
                    try:
                        receiver_conn.sendall(generate_ws_frame(json.dumps(forward_msg).encode()))
                    except:
                        remove_connection(receiver_conn)

            elif msg.get("messageType") == "drawing":
                required_fields = ["startX", "startY", "endX", "endY", "color"]
                if all(field in msg for field in required_fields):
                    drawings_collection.insert_one({
                        "startX": msg["startX"],
                        "startY": msg["startY"],
                        "endX": msg["endX"],
                        "endY": msg["endY"],
                        "color": msg["color"],
                        "timestamp": datetime.now().isoformat()
                    })

                    broadcast_frame = generate_ws_frame(message.encode('utf-8'))
                    for conn in websocket_connections:
                        try:
                            conn.sendall(broadcast_frame)
                        except:
                            websocket_connections.discard(conn)
                            conn.close()

            elif msg.get("messageType") == "get_calls":
                calls = list(video_calls_collection.find({}, {"_id": 0, "id": 1, "name": 1}))
                response = {
                    "messageType": "call_list",
                    "calls": calls
                }
                handler.request.sendall(generate_ws_frame(json.dumps(response).encode()))

            elif msg.get("messageType") == "join_call":
                call_id = msg.get("callId")
                if not call_id:
                    send_error(handler, "Missing call ID")
                    return

                auth_token = request.cookies.get("auth_token")
                user = users_collection.find_one({"auth_token": hash_token(auth_token)}) if auth_token else None
                if not user:
                    send_error(handler, "Authentication required")
                    return
                username = user["username"]

                socket_obj = handler.request
                socket_id = id(socket_obj)
                socket_mapping[socket_id] = socket_obj

                if call_id not in active_calls:
                    call_data = video_calls_collection.find_one({"id": call_id})
                    if not call_data:
                        send_error(handler, "Room not found")
                        return
                    active_calls[call_id] = {
                        "name": call_data["name"],
                        "participants": {}
                    }

                active_calls[call_id]["participants"][socket_id] = {
                    "username": username,
                    "socket_obj": socket_obj
                }

                handler.request.sendall(generate_ws_frame(json.dumps({
                    "messageType": "call_info",
                    "name": active_calls[call_id]["name"]
                }).encode()))


                # print(active_calls[call_id]["participants"].items())
                existing_participants = [
                    {"socketId": str(id), "username": info["username"]}
                    for id, info in active_calls[call_id]["participants"].items()
                ]

                #print(existing_participants)
                handler.request.sendall(generate_ws_frame(json.dumps({
                    "messageType": "existing_participants",
                    "participants": existing_participants
                }).encode()))
                join_msg = {
                    "messageType": "user_joined",
                    "socketId": str(socket_id),
                    "username": username
                }
                broadcast_to_call(call_id, join_msg,socket_id)

            elif msg.get("messageType") in ["offer", "answer", "ice_candidate"]:
                call_id = get_current_call(id(handler.request))
                if not call_id:
                    return

                target_socket_id = msg["socketId"]
                sender_info = active_calls[call_id]["participants"].get(id(handler.request))

                if not sender_info:
                    return
                if msg["messageType"] == "ice_candidate":
                    mtype = "candidate"
                else:
                    mtype = str(msg["messageType"])
                forward_msg = {
                    "messageType": msg["messageType"],
                    "socketId": str(id(handler.request)),
                    "username": sender_info["username"],
                    mtype: msg[mtype]
                }
                target_info = active_calls[call_id]["participants"].get(int(target_socket_id))
                # print(target_info)
                if target_info:
                    if target_info["socket_obj"] != sender_info["socket_obj"]:
                        try:
                            target_info["socket_obj"].sendall(generate_ws_frame(json.dumps(forward_msg).encode()))
                        except:
                            remove_from_call(call_id, int(target_socket_id))

    except UnicodeDecodeError:
        print("Invalid UTF-8 in message")
    except json.JSONDecodeError:
        print("Invalid JSON format")
    except KeyError as e:
        print(f"Missing field: {str(e)}")

def get_current_user(handler, request):
    return list(users_collection.find({}, {"_id": 0, "user_id": 0, "password": 0, "auth_token": 0, "oauth_provider": 0, "github_access_token": 0, "totp_secret": 0, "imageURL": 0}))

def find_user_connection(username):
    for conn, user in active_users.items():
        if user == username:
            return conn
    return None

def remove_connection(conn):
    if conn in active_users:
        del active_users[conn]
    if conn in websocket_connections:
        websocket_connections.remove(conn)
    conn.close()

def send_error(handler, message):
    error_msg = {
        "messageType": "error",
        "text": message
    }
    handler.request.sendall(generate_ws_frame(json.dumps(error_msg).encode()))

def broadcast_user_list():
    with active_users_lock:
        users = [{"username": name} for name in active_users.values()]
    message = {
        "messageType": "active_users_list",
        "users": users
    }
    frame = generate_ws_frame(json.dumps(message).encode('utf-8'))
    with active_users_lock:
        for conn in active_users:
            try:
                conn.sendall(frame)
            except:
                if conn in active_users:
                    del active_users[conn]

def handle_create_call(request, handler):
    try:
        data = json.loads(request.body.decode())
        call_id = str(uuid.uuid4())
        video_calls_collection.insert_one({
            "id": call_id,
            "name": data["name"],
            "created_at": datetime.now().isoformat()
        })
        res = Response().json({"id": call_id})
    except Exception as e:
        res = Response().set_status(400, "Bad Request").text(str(e))
    handler.request.sendall(res.to_data())


def broadcast_to_call(call_id, message, exclude_socket_id):
    if call_id not in active_calls:
        return

    participants = active_calls[call_id]["participants"]
    to_remove = []

    for socket_id, info in participants.items():
        if socket_id == exclude_socket_id:
            continue

        socket_obj = info["socket_obj"]
        try:
            socket_obj.sendall(generate_ws_frame(json.dumps(message).encode()))
        except Exception as e:
            print(f"Failed to send message to {socket_id}: {str(e)}")
            to_remove.append(socket_id)

    for socket_id in to_remove:
        remove_from_call(call_id, socket_id)

def remove_from_call(call_id, socket_id):
    if call_id not in active_calls:
        return

    participants = active_calls[call_id]["participants"]
    if socket_id in participants:
        username = participants[socket_id]["username"]

        del participants[socket_id]
        if socket_id in socket_mapping:
            del socket_mapping[socket_id]
        leave_msg = {
            "messageType": "user_left",
            "socketId": str(socket_id),
            "username": username
        }
        broadcast_to_call(call_id, leave_msg,socket_id)
        if not participants:
            Timer(300, lambda: cleanup_empty_call(call_id)).start()


def cleanup_empty_call(call_id):
    if call_id in active_calls and not active_calls[call_id]["participants"]:
        del active_calls[call_id]


def get_current_call(socket_id):
    for call_id, call_data in active_calls.items():
        if socket_id in call_data["participants"]:
            return call_id
    return None


class MyTCPHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/hello", hello_path, True)
        # TODO: Add your routes here
        self.router.add_route("GET", "/public", publicfile, False)
        self.router.add_route("GET", "/", lambda req, hnd: render(req, hnd, "index.html"), True)
        self.router.add_route("GET", "/chat", lambda req, hnd: render(req, hnd, "chat.html"), True)
        self.router.add_route("POST", "/api/chats", create_chat,False)
        self.router.add_route("GET", "/api/chats", get_chats,False)
        self.router.add_route("PATCH", "/api/chats/", update_chat,False)
        self.router.add_route("DELETE", "/api/chats/", delete_chat,False)
        self.router.add_route("PATCH", "/api/reaction/", add_reaction, False)
        self.router.add_route("DELETE", "/api/reaction/", remove_reaction, False)
        self.router.add_route("PATCH", "/api/nickname", update_nickname, False)
        self.router.add_route("GET", "/register", lambda req, hnd: render(req, hnd, "register.html"), True)
        self.router.add_route("GET", "/login", lambda req, hnd: render(req, hnd, "login.html"), True)
        self.router.add_route("POST", "/register", register_user, False)
        self.router.add_route("POST", "/login", login_user, False)
        self.router.add_route("GET", "/logout", logout_user, False)
        self.router.add_route("GET", "/api/users/@me", get_user_profile, False)
        self.router.add_route("GET", "/settings", lambda req, hnd: render(req, hnd, "settings.html"), True)
        self.router.add_route("GET", "/search-users", lambda req, hnd: render(req, hnd, "search-users.html"), True)
        self.router.add_route("GET", "/api/users/search", search_users, False)
        self.router.add_route("POST", "/api/users/settings", update_profile, False)
        self.router.add_route("POST", "/api/totp/enable", regenerate_2fa, False)
        self.router.add_route("GET", "/authgithub", auth_github, True)
        self.router.add_route("GET", "/authcallback", auth_callback, False)
        self.router.add_route("GET", "/change-avatar", lambda req, hnd: render(req, hnd, "change-avatar.html"), True)
        self.router.add_route("GET", "/videotube", lambda req, hnd: render(req, hnd, "videotube.html"), True)
        self.router.add_route("GET", "/videotube/upload", lambda req, hnd: render(req, hnd, "upload.html"), True)
        self.router.add_route("GET", "/videotube/videos/", lambda req, hnd: render(req, hnd, "view-video.html"), False)
        self.router.add_route("POST", "/api/users/avatar", handle_avatar_upload, False)
        self.router.add_route("POST", "/api/videos", handle_video_upload, False)
        self.router.add_route("GET", "/api/videos", get_all_videos, True)
        self.router.add_route("GET", "/api/videos/", get_single_video, False)
        self.router.add_route("GET", "/api/transcriptions/", get_transcriptions, False)
        self.router.add_route("PUT", "/api/thumbnails/", update_thumbnail, False)
        self.router.add_route("GET", "/videotube/set-thumbnail", lambda req, hnd: render(req, hnd, "set-thumbnail.html"), False)
        self.router.add_route("GET", "/test-websocket", lambda req, hnd: render(req, hnd, "test-websocket.html"), True)
        self.router.add_route("GET", "/drawing-board", lambda req, hnd: render(req, hnd, "drawing-board.html"), True)
        self.router.add_route("GET", "/direct-messaging", lambda req, hnd: render(req, hnd, "direct-messaging.html"),True)
        self.router.add_route("GET", "/video-call", lambda req, hnd: render(req, hnd, "video-call.html"), True)
        self.router.add_route("GET", "/video-call/", lambda req, hnd: render(req, hnd, "video-call-room.html"), False)
        self.router.add_route("GET", "/websocket", handle_websocket_upgrade, False)
        self.router.add_route("POST", "/api/video-calls", handle_create_call, False)
        super().__init__(request, client_address, server)



    def handle(self):
        buffer = b''
        headers_end = -1
        while headers_end == -1:
            data = self.request.recv(4096)
            if not data:
                break
            buffer += data
            headers_end = buffer.find(b'\r\n\r\n')

        if headers_end == -1:
            res = Response().set_status(400, "Bad Request").text("Invalid headers")
            self.request.sendall(res.to_data())
            return

        headers_part = buffer[:headers_end]
        body_start = headers_end + 4
        body_part = buffer[body_start:] if body_start < len(buffer) else b''

        try:
            temp_request = Request(headers_part + b'\r\n\r\n' + body_part)
            content_length = int(temp_request.headers.get('Content-Length', 0))
        except (KeyError, ValueError):
            content_length = 0

        remaining = content_length - len(body_part)
        while remaining > 0:
            data = self.request.recv(min(4096, remaining))
            if not data:
                break
            body_part += data
            remaining -= len(data)

        full_request = Request(headers_part + b'\r\n\r\n' + body_part)
        # print("--- received data ---")
        # print(headers_part + b'\r\n\r\n' + body_part)
        # print(body_part)
        # print("--- end of data ---\n\n")
        self.router.route_request(full_request, self)

        # received_data = self.request.recv(2048)
        # print(self.client_address)
        # print("--- received data ---")
        # print(received_data)
        # print("--- end of data ---\n\n")
        # request = Request(received_data)
        #
        # self.router.route_request(request, self)


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()

