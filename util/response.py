import json
from http import cookies


class Response:
    def __init__(self):
        self.statusCode = 200
        self.statusText = 'OK'
        self.addHeaders = {"X-Content-Type-Options": "nosniff"}
        self.addCookies = {}
        self.addBody = b''

    def set_status(self, code, text):
        self.statusCode = code
        self.statusText = text
        return self

    def headers(self, headers):
        self.addHeaders.update(headers)
        return self

    def cookies(self, cookie):
        self.addCookies.update(cookie)
        return self

    def bytes(self, data):
        self.addBody += data
        return self

    def text(self, data):
        self.addBody += data.encode()
        return self

    def json(self, data):
        self.addBody = json.dumps(data).encode()
        self.addHeaders['Content-Type'] = 'application/json'
        return self

    def to_data(self):
        if "Content-Type" not in self.addHeaders:
            self.addHeaders["Content-Type"] = "text/plain; charset=utf-8"
        self.addHeaders["Content-Length"] = str(len(self.addBody))
        url = "HTTP/1.1 " + str(self.statusCode) + " " + self.statusText + "\r\n"
        for key in self.addHeaders:
            if self.addHeaders[key] is not None:
                url += key + ": " + self.addHeaders[key] + "\r\n"
        for key in self.addCookies:
            if self.addCookies[key] is not None:
                url += key + "=" + self.addCookies[key] + "\r\n"
        url += "\r\n"
        url = url.encode()+self.addBody
        return url


def test1():
    res = Response()
    # res.text("hello")
    res.headers({"Content-Type": None})
    # res.headers({"hahahahaha": "chaojinb"})
    # res.cookies({"cookie1": "cookie1", "cookie2": "cookie2"})
    # res.cookies({"cookie3": "cookie4", "cookie5": "cookie6"})
    expected = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello'
    actual = res.to_data()
    print(actual)
    print(expected)


if __name__ == '__main__':
    test1()
