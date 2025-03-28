import re

class MultipartData:
    def __init__(self, boundary, parts):
        self.boundary = boundary
        self.parts = parts

class Part:
    def __init__(self, headers, name, content, filename):
        self.headers = headers
        self.name = name
        self.content = content
        self.filename = filename

def parse_multipart(request):
    content_type = request.headers.get("Content-Type", "")
    boundary_match = re.search(r"boundary=([^;]+)", content_type, re.IGNORECASE)
    if not boundary_match:
        raise ValueError("Boundary not found in Content-Type header")
    boundary = boundary_match.group(1).strip('"')
    delimiter = boundary.encode("ascii")
    body = request.body
    parts = body.split(delimiter)
    # print("--------------------------------")
    # print("lenss: " + str(len(parts)))
    # print("--------------------------------")
    multipart_parts = []

    for part in parts[1:-1]:
        part = part.lstrip(b"\r\n").rstrip(b"\r\n")
        headers_end = part.find(b"\r\n\r\n")
        if headers_end == -1:
            continue

        headers_block = part[:headers_end]
        content = part[headers_end + 4 :].rstrip(b"\r\n--")
        headers = {}
        for line in headers_block.split(b"\r\n"):
            if b":" in line:
                key, value = line.split(b": ", 1)
                headers[key.decode()] = value.decode()

        content_disp = headers.get("Content-Disposition", "")
        name_match = re.search(r'name="([^"]+)"', content_disp)
        filename_match = re.search(r'filename="([^"]+)"', content_disp)
        name = name_match.group(1) if name_match else None
        filename = filename_match.group(1) if filename_match else None

        multipart_parts.append(Part(headers, name, content, filename))
        # print("ssssssssssssssssssssssssssssssssssssssssssss")
        # print(headers)
        # print(name)
        # print(content)
        # print(filename)
        # print("ssssssssssssssssssssssssssssssssssssssssssss")

    return MultipartData(boundary, multipart_parts)


# import unittest
#
# class MockRequest:
#     """模拟 Request 类，用于测试"""
#     def __init__(self, headers, body):
#         self.headers = headers
#         self.body = body
#
# class TestJPGUpload(unittest.TestCase):
#
#     def test_parse_multipart_jpg(self):
#         # Simulated JPG data (small sample)
#         jpg_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10'
#
#         # Multipart request body construction
#         boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
#         body = (
#             f'--{boundary}\r\n'
#             'Content-Disposition: form-data; name="image"; filename="test.jpg"\r\n'
#             'Content-Type: image/jpeg\r\n\r\n'
#         ).encode() + jpg_data + b'\r\n'
#
#         body += f'--{boundary}--\r\n'.encode()
#
#         # Mock Request object
#         headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
#         request = MockRequest(headers, body)
#
#         # Parse the multipart request
#         result = parse_multipart(request)
#
#         # Check boundary
#         self.assertEqual(result.boundary, boundary)
#
#         # Check parts
#         self.assertEqual(len(result.parts), 1)
#
#         # Check JPG Part
#         jpg_part = result.parts[0]
#         self.assertEqual(jpg_part.headers['Content-Disposition'], 'form-data; name="image"; filename="test.jpg"')
#         self.assertEqual(jpg_part.headers['Content-Type'], 'image/jpeg')
#         self.assertEqual(jpg_part.content, jpg_data)
#
# if __name__ == "__main__":
#     unittest.main(verbosity=2)