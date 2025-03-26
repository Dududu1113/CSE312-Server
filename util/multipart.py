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

from urllib.parse import unquote


def parse_multipart(request):
    content_type = request.headers.get('Content-Type', '')
    boundary_match = re.search(r'boundary=([^;]+)', content_type, re.IGNORECASE)
    if not boundary_match:
        raise ValueError("Boundary not found in Content-Type header")
    boundary = boundary_match.group(1).strip('"')

    # 构造分隔符为 "--boundary"
    delimiter = b'--' + boundary.encode('ascii')
    body = request.body

    # 处理起始分隔符（若存在）
    if body.startswith(delimiter):
        body = body[len(delimiter):]

    # 处理结束分隔符（若存在）
    end_delimiter = delimiter + b'--'
    if body.endswith(end_delimiter):
        body = body[:-len(end_delimiter)]

    # 分割请求体，每个分片以 \r\n--boundary 分隔
    parts = body.split(b'\r\n' + delimiter)

    multipart_parts = []
    for part in parts[1:-1]:  # 跳过首尾空部分
        part = part.lstrip(b'\r\n').rstrip(b'\r\n')
        headers_end = part.find(b'\r\n\r\n')

        if headers_end == -1:
            continue

        headers_block = part[:headers_end]
        content = part[headers_end + 4:]

        headers = {}
        for line in headers_block.split(b'\r\n'):
            if b':' in line:
                key, value = line.split(b': ', 1)
                headers[key.decode().lower()] = value.decode()

        content_disp = headers.get('content-disposition', '')
        filename = None
        name = None

        # 提取 filename 和 name
        if 'filename' in content_disp:
            filename_match = re.search(r'filename="([^"]+)"', content_disp)
            if filename_match:
                filename = filename_match.group(1)

        if 'name' in content_disp:
            name_match = re.search(r'name="([^"]+)"', content_disp)
            if name_match:
                name = name_match.group(1)

        # 仅处理字段名为 "avatar" 且包含文件名的部分
        if name == 'avatar' and filename:
            multipart_parts.append(Part(headers, name, content, filename))
        print(multipart_parts)

    return MultipartData(boundary, multipart_parts)
