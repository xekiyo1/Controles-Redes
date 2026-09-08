import socket
from collections import Counter
from dnslib import DNSRecord, QTYPE

ROOT_IP = "198.41.0.4"
PORT = 8000
HOST = "127.0.0.1"  # Cambiar por IP_VM si corresponde

history_20 = []
cache_data = {}


def update_cache_policy(qname: str, response_bytes: bytes):
    global history_20, cache_data

    history_20.append(qname)
    if len(history_20) > 20:
        history_20.pop(0)

    counts = Counter(history_20)
    top_3_domains = {domain for domain, _ in counts.most_common(3)}

    if qname in top_3_domains and response_bytes:
        cache_data[qname] = response_bytes

    keys_to_delete = [domain for domain in cache_data if domain not in top_3_domains]
    for domain in keys_to_delete:
        del cache_data[domain]


def serve_from_cache(cached_response: bytes, incoming_query: bytes) -> bytes:
    incoming_id = DNSRecord.parse(incoming_query).header.id
    record = DNSRecord.parse(cached_response)
    record.header.id = incoming_id
    return bytes(record.pack())


def send_udp_query(query_bytes: bytes, target_ip: str, target_port: int = 53) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(query_bytes, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def extract_ip_from_additional(parsed_msg, ns_name: str) -> str:
    for record in parsed_msg.ar:
        if QTYPE.get(record.rtype) == "A" and str(record.rname) == ns_name:
            return str(record.rdata)
    for record in parsed_msg.ar:
        if QTYPE.get(record.rtype) == "A":
            return str(record.rdata)
    return None


def resolver(mensaje_consulta: bytes, ip_addr: str = ROOT_IP, ns_name: str = ".") -> bytes:
    parsed_query = DNSRecord.parse(mensaje_consulta)
    qname = str(parsed_query.get_q().get_qname())

    print(f"Consultando '{qname}' a '{ns_name}' con dirección IP '{ip_addr}'")

    response_bytes = send_udp_query(mensaje_consulta, ip_addr)
    if not response_bytes:
        return b""

    parsed_response = DNSRecord.parse(response_bytes)

    has_a_record = any(QTYPE.get(rr.rtype) == "A" for rr in parsed_response.rr)
    if parsed_response.header.a > 0 and has_a_record:
        return response_bytes

    if parsed_response.header.auth > 0:
        found_ns_name = None
        for auth_rr in parsed_response.auth:
            if QTYPE.get(auth_rr.rtype) == "NS":
                found_ns_name = str(auth_rr.rdata)
                break

        if found_ns_name:
            next_ip = extract_ip_from_additional(parsed_response, found_ns_name)

            if next_ip:
                return resolver(mensaje_consulta, ip_addr=next_ip, ns_name=found_ns_name)
            else:
                ns_query_bytes = bytes(DNSRecord.question(found_ns_name).pack())
                ns_response_bytes = resolver(ns_query_bytes, ip_addr=ROOT_IP, ns_name=".")

                if ns_response_bytes:
                    parsed_ns_resp = DNSRecord.parse(ns_response_bytes)
                    for rr in parsed_ns_resp.rr:
                        if QTYPE.get(rr.rtype) == "A":
                            resolved_ns_ip = str(rr.rdata)
                            return resolver(mensaje_consulta, ip_addr=resolved_ns_ip, ns_name=found_ns_name)

    return b""


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((HOST, PORT))
    print(f"Servidor Resolver escuchando en {HOST}:{PORT}...")

    while True:
        try:
            data, client_addr = server_sock.recvfrom(4096)
            if not data:
                continue

            parsed_req = DNSRecord.parse(data)
            qname = str(parsed_req.get_q().get_qname())

            if qname in cache_data:
                print(f"[CACHE] Respondiendo '{qname}' desde el Caché Top 3")
                response_bytes = serve_from_cache(cache_data[qname], data)
                update_cache_policy(qname, cache_data[qname])
            else:
                print(f"[SIN CACHE] Resolviendo '{qname}' iterativamente")
                response_bytes = resolver(data, ip_addr=ROOT_IP, ns_name=".")

                if response_bytes:
                    update_cache_policy(qname, response_bytes)

            if response_bytes:
                server_sock.sendto(response_bytes, client_addr)

        except Exception as e:
            print(f"Error procesando solicitud: {e}")


if __name__ == "__main__":
    main()