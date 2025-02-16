from pymongo import MongoClient
import json
import os
import socketserver
import uuid
import html
from util.request import Request
from util.response import Response
from util.router import Router
from util.hello_path import hello_path

client = MongoClient("mongodb://localhost:27017/")
db = client["server"]
messages_collection = db["CSE312"]

def publicfile(request, handler):
    mineType = {".html": "text/html",".css": "text/css",".js": "application/javascript",".jpg": "image/jpeg",".ico": "image/x-icon"}
    file_path = request.path[len("/public"):]  # Remove "/public" prefix
    full_path = os.path.join("public", file_path.lstrip("/"))

    if os.path.exists(full_path) and os.path.isfile(full_path):
        with open(full_path, "rb") as f:
            content = f.read()

        file_extension = os.path.splitext(full_path)[1]
        mime_type = mineType.get(file_extension, "application/octet-stream")

        response = Response()
        response.bytes(content)
        response.headers({"Content-Type": mime_type})

        handler.request.sendall(response.to_data())
    else:
        response = Response().set_status(404, "Not Found").text("404 Not Found")
        handler.request.sendall(response.to_data())


def render_page(request, handler, page_file):
    layout_path = os.path.join("public", "layout/layout.html")
    page_path = os.path.join("public", page_file)

    if os.path.exists(layout_path) and os.path.exists(page_path):
        with open(layout_path, "r", encoding="utf-8") as layout_file:
            layout_content = layout_file.read()
        with open(page_path, "r", encoding="utf-8") as page_file:
            page_content = page_file.read()

        rendered_content = layout_content.replace("{{content}}", page_content)

        response = Response()
        response.text(rendered_content)
        response.headers({"Content-Type": "text/html"})

        handler.request.sendall(response.to_data())
    else:
        response = Response().set_status(404, "Not Found")
        handler.request.sendall(response.to_data())

def handle_create_chat(request, handler):
    """Handles POST /api/chats - Creates a new chat message"""
    response = Response()
    body = json.loads(request.body.decode())  # Parse JSON request body
    content = html.escape(body.get("content", ""))  # Escape HTML

    # Retrieve session cookie
    session_id = request.cookies.get("session")
    # print(request.cookies)
    # print("session_id", session_id)
    chat_id = str(uuid.uuid4())
    if not session_id:
        session_id = str(uuid.uuid4())  # Generate new session ID
        author = f"User-{session_id[:8]}"  # Assign a random username
    else:
        # Find existing user's author name
        existing_message = messages_collection.find_one({"session_id": session_id})
        author = existing_message["author"] if existing_message else f"User-{session_id[:8]}"

    message_id = str(uuid.uuid4())  # Unique ID for message
    message = {
        "id": message_id,
        "session_id": session_id,
        "author": author,
        "content": content,
        "updated": False,
    }

    messages_collection.insert_one(message)

    if "Cookie: " not in request.headers:
        response.cookies({"session":session_id})
    response.text(response.statusText + response.statusText)
    handler.request.sendall(response.to_data())

def get_chats(request, handler):
    all_messages = list(messages_collection.find({}, {"_id": 0, "session": 0}))  # Exclude MongoDB ID & session
    response_data = {"messages": all_messages}

    response = Response().json(response_data)
    handler.request.sendall(response.to_data())

def update_chat(request, handler):
    chat_id = request.path.split("/")[-1]  # Extract message ID from URL
    data = json.loads(request.body.decode())
    new_content = html.escape(data["content"])  # Escape HTML

    # Find the message in DB
    message = messages_collection.find_one({"id": chat_id})
    if not message:
        response = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(response.to_data())
        return

    # Check if user owns the message
    session_id = request.cookies.get("session")
    if session_id != message["session_id"]:
        response = Response().set_status(403, "Forbidden").text("You can only update your own messages.")
        handler.request.sendall(response.to_data())
        return

    # Update the message
    messages_collection.update_one({"id": chat_id}, {"$set": {"content": new_content, "updated": True}})
    response = Response().text("Message updated successfully.")
    handler.request.sendall(response.to_data())

def delete_chat(request, handler):
    chat_id = request.path.split("/")[-1]  # Extract message ID from URL

    # Find the message in DB
    message = messages_collection.find_one({"id": chat_id})
    #print(message)
    if not message:
        response = Response().set_status(404, "Not Found").text("Message not found.")
        handler.request.sendall(response.to_data())
        return

    # Check if user owns the message
    session_id = request.cookies.get("session")
    # print(request.cookies)
    # print("session_id", session_id)
    if session_id != message["session_id"]:
        response = Response().set_status(403, "Forbidden").text("You can only delete your own messages.")
        handler.request.sendall(response.to_data())
        return

    # Delete the message
    messages_collection.delete_one({"id": chat_id})
    response = Response().text("Message deleted successfully.")
    handler.request.sendall(response.to_data())

class MyTCPHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/hello", hello_path, True)
        # TODO: Add your routes here
        self.router.add_route("GET", "/public", publicfile, False)
        self.router.add_route("GET", "/", lambda req, hnd: render_page(req, hnd, "index.html"), True)
        self.router.add_route("GET", "/chat", lambda req, hnd: render_page(req, hnd, "chat.html"), True)
        self.router.add_route("POST", "/api/chats", handle_create_chat,False)
        self.router.add_route("GET", "/api/chats", get_chats,False)
        self.router.add_route("PATCH", "/api/chats/", update_chat,False)
        self.router.add_route("DELETE", "/api/chats/", delete_chat,False)
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
