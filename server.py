from pymongo import MongoClient
import json
import os
import socketserver
import uuid
import html
import requests
from util.request import Request
from util.response import Response
from util.router import Router
from util.hello_path import hello_path
from util.auth import extract_credentials, validate_password, hash_password, verify_password, hash_token, \
    generate_auth_token

client = MongoClient("mongodb://localhost:27017/")
db = client["server"]
messages_collection = db["CSE312"]
users_collection = db["users"]

def publicfile(request, handler):
    mineType = {".html": "text/html",".css": "text/css",".js": "text/javascript",".jpg": "image/jpeg",".ico": "image/x-icon",".gif": "image/gif",".webp": "image/webp",".png": "image/png",".json": "application/json",".svg":"image/svg+xml"}
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
    content = html.escape(body.get("content", ""))

    session_id = request.cookies.get("session")

    if user:
        user_id = user["user_id"]
        existing_message = messages_collection.find_one({"user_id": user_id})
        author = user["username"]
        if existing_message:
            imageURL = existing_message.get("imageURL")
        else:
            response = requests.get(f"https://api.dicebear.com/9.x/croodles-neutral/svg?seed={auth_token}")
            if response.status_code == 200:
                profile_pic_dir = "public/imgs/profile-pics"
                os.makedirs(profile_pic_dir, exist_ok=True)
                profile_pic_path = f"{profile_pic_dir}/{auth_token}.svg"
                with open(profile_pic_path, "wb") as f:
                    f.write(response.content)
                imageURL = f"/public/imgs/profile-pics/{auth_token}.svg"
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
    username, password = extract_credentials(request)

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
    res.cookies({"auth_token": auth_token + ";Max-Age=3600;HttpOnly","session":";Max-Age=0;HttpOnly"})
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
    res.cookies({"auth_token": ";Max-Age=0"})
    handler.request.sendall(res.to_data())


def get_user_profile(request, handler):
    auth_token = request.cookies.get("auth_token")

    if not auth_token:
        res = Response().set_status(401, "Unauthorized").json({"username": '', "id": ''})
        handler.request.sendall(res.to_data())
        return

    hashed_token = hash_token(auth_token)
    user = users_collection.find_one({"auth_token": hashed_token})

    if not user:
        res = Response().set_status(401, "Unauthorized").json({"username": '', "id": ''})
        handler.request.sendall(res.to_data())
        return

    res = Response().json({"username": user["username"], "id": user["user_id"]})
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
    res = Response().json({"users": users})
    print(b"NOooooooooooooooooooooooooooooooooooooooooooooo" + res.to_data())
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
        super().__init__(request, client_address, server)



    def handle(self):
        received_data = self.request.recv(2048)
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        request = Request(received_data)

        self.router.route_request(request, self)


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
