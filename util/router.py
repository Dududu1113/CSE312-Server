from util.response import Response


class Router:

    def __init__(self):
        self.routes = []

    def add_route(self, method, path, action, exact_path=False):
        self.routes.append([method, path, action, exact_path])

    def route_request(self, request, handler):
        for method, path, action, exact_path in self.routes:
            if request.method == method:
                if (exact_path and request.path == path) or (not exact_path and request.path.startswith(path)):
                    action(request, handler)
                    return
        res = Response()
        res.text("404 Not Found")
        res.set_status(404,"Not Found")
        handler.request.sendall(res.to_data())