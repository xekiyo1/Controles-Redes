import socket
import json
from utils import *

with open("config.json", "r", encoding="utf-8") as file: # Cargamos el json como data
    data = json.load(file)

def nun_proxy(message: dict) -> bytes: # Proxy que no hace nada* (pone el header X-ElQuePregunta)

    host = message["head"].get("Host", "")

    if ":" in host:
        host, port = host.split(":", 1)
        port = int(port)
    else:
        port = 80

    formatted_request = create_HTTP_message(message)

    mid_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mid_socket.connect((host, port))
    mid_socket.sendall(formatted_request)

    server_ans = receive_full_message(mid_socket, 4096)
    mid_socket.close()
    
    return server_ans
    
def sum_proxy(message: dict, data: dict) -> bytes:
    server_ans = nun_proxy(message)
    if not server_ans:
        return b""

    parsed_ans = parse_HTTP_message(server_ans)
    body_bytes = parsed_ans["body"].encode("iso-8859-1")
    
    modified_body_bytes = big_brother(body_bytes, data)
    parsed_ans["body"] = modified_body_bytes.decode("iso-8859-1")
    
    if isinstance(parsed_ans["head"], dict):
        parsed_ans["head"]["Content-Length"] = str(len(modified_body_bytes))

    return create_HTTP_message(parsed_ans)

if __name__ == "__main__":
    IP_VM = "localhost"
    buff_size = 4096
    server_socket_address = (IP_VM, 8000)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_socket_address)
    server_socket.listen(3)

    print('... Esperando clientes')
    while True:
        client_socket, client_socket_address = server_socket.accept()
        
        recv_message = receive_client_request(client_socket, buff_size)
        
        if recv_message:
            parsed_req = parse_HTTP_message(recv_message)
            start_line = parsed_req.get("start_line", "")
            link = get_request_link(parsed_req)

            if "/gato.jpg" in start_line:
                respuesta_bytes = cat_guard("gato_guardia.jpg")

            elif isForbidden(link, data):
                respuesta_bytes = forbid()

            else:
                parsed_req["head"]["X-ElQuePregunta"] = data["user"]
                respuesta_bytes = sum_proxy(parsed_req, data)

            client_socket.sendall(respuesta_bytes)

        client_socket.close()
        print(f"conexión con {client_socket_address} ha sido cerrada")
