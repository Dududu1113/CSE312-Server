import json


class Response:
    def __init__(self):
        self.statusCode = '200'
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
        self.addBody += data.encode("utf-8")
        return self

    def json(self, data):
        self.addBody = json.dumps(data).encode("utf-8")
        self.addHeaders['Content-Type'] = 'application/json'
        return self

    def to_data(self):
        if "Content-Type" not in self.addHeaders:
            self.addHeaders["Content-Type"] = "text/plain; charset=utf-8"
        url = f"HTTP/1.1 {self.statusCode} {self.statusText}\r\n"
        # print(self.addHeaders)
        # print(self.addCookies)
        self.addHeaders["Content-Length"] = str(len(self.addBody))
        for key, value in self.addHeaders.items():
            if self.addHeaders[key] is not None:
                url += f"{key}: {value}\r\n"
        for key, value in self.addCookies.items():
            if self.addCookies[key] is not None:
                url += f"Set-Cookie: {key}={value};"
        if url[-1] == ";":
            url = url[:-1]
        # print(b''+url.encode())
        # print(b"iiiiiiiiiiiiii" + url[-1].encode())
        if url[-1] == "\n":
            url += "\r\n"
        else:
            url += "\r\n\r\n"
        print(b"This issssssssss: " + url.encode())
        url = url.encode() + self.addBody
        return url


def test1():
    res = Response()
    res.text("hello")
    expected = b'HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello'
    actual = res.to_data()
    print(actual)
    print(expected)


if __name__ == '__main__':
    test1()
