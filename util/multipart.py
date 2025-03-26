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
    # 提取 boundary
    content_type = request.headers.get("Content-Type", "")
    boundary_match = re.search(r"boundary=([^;]+)", content_type, re.IGNORECASE)
    if not boundary_match:
        raise ValueError("Boundary not found in Content-Type header")
    boundary = boundary_match.group(1).strip('"')

    # 生成正确分隔符（包含 \r\n 前缀）
    delimiter = boundary.encode("ascii")
    body = request.body


    # 分割请求体
    parts = body.split(delimiter)
    print("--------------------------------")
    print(parts)
    print(len(parts))
    print("--------------------------------")
    multipart_parts = []

    for part in parts[1:-1]:  # 跳过首尾空部分
        print(part)
        part = part.lstrip(b"\r\n").rstrip(b"\r\n")
        headers_end = part.find(b"\r\n\r\n")
        if headers_end == -1:
            continue

        # 分离头部和内容
        headers_block = part[:headers_end]
        content = part[headers_end + 4 :]  # 跳过 \r\n\r\n

        # 解析头部
        headers = {}
        for line in headers_block.split(b"\r\n"):
            if b":" in line:
                key, value = line.split(b": ", 1)
                headers[key.decode().lower()] = value.decode()

        # 提取 name 和 filename（忽略大小写）
        content_disp = headers.get("content-disposition", "").lower()
        name_match = re.search(r'name="([^"]+)"', content_disp)
        filename_match = re.search(r'filename="([^"]+)"', content_disp)
        name = name_match.group(1) if name_match else None
        filename = filename_match.group(1) if filename_match else None

        multipart_parts.append(Part(headers, name, content, filename))
        print("ssssssssssssssssssssssssssssssssssssssssssss")
        print(headers)
        print(name)
        print(content)
        print(filename)
        print("ssssssssssssssssssssssssssssssssssssssssssss")

    return MultipartData(boundary, multipart_parts)