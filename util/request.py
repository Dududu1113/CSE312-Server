class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables

        self.body = b""
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}


        urlsplit = request.split(b"\r\n\r\n")
        self.body = urlsplit[1]
        headers = urlsplit[0]
        self.method = headers.decode().split("\r\n")[0].split(" ")[0]
        self.path = headers.decode().split("\r\n")[0].split(" ")[1]
        self.http_version = headers.decode().split("\r\n")[0].split(" ")[2]
        headersLine = headers.decode().split("\r\n",1)[1]
        headersLineSplit = headersLine.split("\r\n")
        for header in headersLineSplit:
            #print(header)
            if ": " in header:
                key, value = header.split(": ")
                self.headers[key] = value.strip()
        if "Cookie" in self.headers:
            cookies = self.headers["Cookie"]
            cookieValue = cookies.split(";")
            for cookie in cookieValue:
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    self.cookies[key.strip()] = value.strip()
        #print(request.decode())
        #print("here is the what I want to print: " + self.headers["Host"])

def test1():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n')
    # print("from here is the tests")
    # print(request.headers["Connection"])
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct

    def test2():
        request = Request(b'POST / HTTP/1.1\r\nHost: localhost:6666\r\nConnection: keep-alive\r\nCookie: user=abc; session=123;\r\n\r\nthis is body')
        assert request.method == "POST"
        assert request.path == "/"
        assert request.http_version == "HTTP/1.1"
        assert "Host" in request.headers
        assert request.headers["Host"] == "localhost:6666"
        assert "Connection" in request.headers
        assert request.headers["Connection"] == "keep-alive"
        assert "Cookie" in request.headers
        assert request.cookies["user"] == "abc"
        assert request.cookies["session"] == "123"
        assert request.body == b'this is body'

if __name__ == '__main__':
    test1()
