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

client = MongoClient("mongodb://localhost:27017/")
db = client["server"]
messages_collection = db["CSE312"]

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
    body = json.loads(request.body.decode())
    content = html.escape(body.get("content", ""))

    session_id = request.cookies.get("session")
    chat_id = str(uuid.uuid4())
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
            imageURL = "/public/imgs/profile-pics/default.svg"
    else:
        existing_message = messages_collection.find_one({"session_id": session_id})
        if existing_message:
            author = existing_message["author"]
            imageURL = existing_message.get("imageURL", "/public/imgs/profile-pics/default.svg")
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
    message = {"id": message_id,"session_id": session_id,"author": author,"content": content,"updated": False,"reactions": '',"imageURL": imageURL}
    messages_collection.insert_one(message)

    if "Cookie: " not in request.headers:
        res.cookies({"session": session_id})
    res.text("message sent")
    handler.request.sendall(res.to_data())

def get_chats(request, handler):
    all_messages = list(messages_collection.find({}, {"_id": 0, "session": 0}))
    # all_reactions = list(messages_collection.find({}, {"reactions": 0, "session": 0}))
    session_id = request.cookies.get("session")
    data = {"messages": all_messages}
    res = Response().json(data)
    res.cookies({"session": session_id})
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

    session_id = request.cookies.get("session")
    if session_id != message["session_id"]:
        res = Response().set_status(403, "Forbidden").text("You can only update your own messages.")
        handler.request.sendall(res.to_data())
        return

    messages_collection.update_one({"id": chat_id}, {"$set": {"content": new_content, "updated": True}})
    res = Response().text("Message updated successfully.")
    handler.request.sendall(res.to_data())

def delete_chat(request, handler):
    chat_id = request.path.split("/")[-1]
    message = messages_collection.find_one({"id": chat_id})
    #print(message)
    if not message:
        res = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(res.to_data())
        return

    session_id = request.cookies.get("session")
    # print(request.cookies)
    # print("session_id", session_id)
    if session_id != message["session_id"]:
        res = Response().set_status(403, "Forbidden").text("You can only delete your own messages.")
        res.cookies({"session": session_id})
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
