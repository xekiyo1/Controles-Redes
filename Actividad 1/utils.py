import json


# 							//////// 				Funciones de Procesamiento de texto				/////////////////


def receive_client_request(connection_socket, buff_size=4096) -> bytes:
    full_message = b""
    while True:
        recv_message = connection_socket.recv(buff_size)
        if not recv_message:
            break
        full_message += recv_message
        if b"\r\n\r\n" in full_message or b"\n\n" in full_message:
            break
    return full_message


def receive_full_message(connection_socket, buff_size=4096) -> bytes:
    full_message = b""
    content_length = None
    header_end_idx = -1

    while True:
        chunk = connection_socket.recv(buff_size)
        if not chunk:
            break
        full_message += chunk

        if header_end_idx == -1:
            if b"\r\n\r\n" in full_message:
                header_end_idx = full_message.find(b"\r\n\r\n") + 4
            elif b"\n\n" in full_message:
                header_end_idx = full_message.find(b"\n\n") + 2

            if header_end_idx != -1:
                header_text = full_message[:header_end_idx].decode("iso-8859-1", errors="replace")
                for line in header_text.splitlines():
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            content_length = 0
                        break
                
                if content_length is None and ("204" in header_text or "304" in header_text):
                    content_length = 0

        if header_end_idx != -1:
            if content_length is not None:
                body_downloaded = len(full_message) - header_end_idx
                if body_downloaded >= content_length:
                    break
            else:
                if b"\r\n0\r\n\r\n" in full_message or full_message.endswith(b"0\r\n\r\n"):
                    break

    return full_message



def parse_HTTP_message(http_message: bytes) -> dict:
    message = http_message.decode("iso-8859-1")

    if "\r\n\r\n" in message:
        headers_part, body = message.split("\r\n\r\n", 1)
    elif "\n\n" in message:
        headers_part, body = message.split("\n\n", 1)
    else:
        headers_part, body = message, ""

    lines = headers_part.splitlines()
    start_line = lines[0] if lines else ""

    head_dict = {}
    for line in lines[1:]:
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            head_dict[header_name.strip()] = header_value.strip()

    return {"start_line": start_line, "head": head_dict, "body": body}



def create_HTTP_message(message: dict) -> bytes:
    start_line = message.get("start_line", "")
    head_dict = message.get("head", {})
    body = message.get("body", "")

    lines = [start_line]

    if isinstance(head_dict, dict):
        for header_name, header_value in head_dict.items():
            lines.append(f"{header_name}: {header_value}")
    elif isinstance(head_dict, list):
        for header_line in head_dict:
            lines.append(header_line.strip())

    headers_string = "\r\n".join(lines) + "\r\n\r\n"
    full_message = headers_string + body

    return full_message.encode("iso-8859-1")
    
def big_brother(answer: bytes, forbidden: dict) -> bytes:
	
    good_msg = answer.decode("iso-8859-1")

    for item in forbidden["forbidden_words"]:
        for word, replacement in item.items():
            good_msg = good_msg.replace(word,replacement)

    return good_msg.encode("iso-8859-1")


def get_request_link(parsed_message: dict) -> str:

    start_line = parsed_message.get("start_line", "")
    head = parsed_message.get("head", {})
    host = head.get("Host", "")
 
    parts = start_line.split(" ")
    uri = parts[1] if len(parts) >= 2 else ""
 
    if uri.startswith("http://") or uri.startswith("https://"):
        return uri.split("://", 1)[1]
 
    return host + uri




def isForbidden(link: str ,forbidden: dict) -> bool:

    for site in forbidden["blocked"]:
        if site in link:
            return True
    return False

def forbid() -> bytes:

    html_forbid = """<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
    <h1>403 Forbidden - Sitio Bloqueado</h1>
    <p>El acceso a este dominio no esta permitido por el proxy.</p>
    <img src="/gato.jpg" alt="Gato de bloqueo">
</body>
</html>"""

    forbid_bytes = html_forbid.encode("iso-8859-1")
    content_length = len(forbid_bytes)

    response = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
                ).encode("iso-8859-1") + forbid_bytes

    return response


def cat_guard(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        image_bytes = f.read()
    
    content_length = len(image_bytes)

    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: image/jpeg\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("iso-8859-1")

    return headers + image_bytes

    
    
