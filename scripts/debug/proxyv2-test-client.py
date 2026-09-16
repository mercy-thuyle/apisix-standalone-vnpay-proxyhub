#!/usr/bin/env python3
# scripts/debug/proxyv2-test-client.py
#
# Giả lập đúng 1 kết nối PROXY protocol v2 (TLV 0x05 = unique_id/network_id)
# rồi TLS handshake với SNI thật, để kiểm tra logic sau global-abuse-guard
# (X-Network-Id) và upstream routing (site-affinity HCM/HAN) - không thể
# dùng curl trần vì listener 443 bắt buộc PROXY-v2 trước TLS ClientHello
# (đổi từ 8443 sang 443 - xem config-proxyhub.yaml: proxy_protocol.listen_https_port).

import socket
import ssl
import struct
import sys

def send_proxyv2_request(host, target_ip, port, network_id, path="/"):
    sig = b'\r\n\r\n\x00\r\nQUIT\n'
    ver_cmd = bytes([0x21])
    fam_proto = bytes([0x11])
    addr = (
        socket.inet_aton("172.25.180.125")
        + socket.inet_aton("172.26.8.30")
        + struct.pack('!HH', 51234, port)
    )
    nid = network_id.encode()
    tlv = bytes([0x05]) + struct.pack('!H', len(nid)) + nid
    body = addr + tlv
    header = sig + ver_cmd + fam_proto + struct.pack('!H', len(body)) + body

    raw = socket.create_connection((target_ip, port), timeout=5)
    raw.sendall(header)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname=host)

    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    tls.sendall(req.encode())

    resp = b""
    while True:
        chunk = tls.recv(4096)
        if not chunk:
            break
        resp += chunk
    tls.close()
    return resp.decode(errors="replace")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "s3-hcm.sds.infiniband.vn"
    nid = sys.argv[2] if len(sys.argv) > 2 else "test-network-id-manual-verify"
    path = sys.argv[3] if len(sys.argv) > 3 else "/"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
    print(send_proxyv2_request(host, "127.0.0.1", port, nid, path))
