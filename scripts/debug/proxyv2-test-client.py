#!/usr/bin/env python3
# scripts/debug/proxyv2-test-client.py
#
# Giả lập 1 kết nối PROXY protocol v2 rồi TLS handshake với SNI thật, để
# kiểm tra logic sau global-abuse-guard (X-Network-Id/X-Client-IP) và upstream
# routing (site-affinity HCM/HAN) - không thể dùng curl trần vì listener 443
# bắt buộc PROXY-v2 trước TLS ClientHello (đổi từ 8443 sang 443 - xem
# config-proxyhub.yaml: proxy_protocol.listen_https_port).
#
# Đổi chính sách 18/09/2026: network_id (TLV 0x05 = unique_id) KHÔNG còn bắt
# buộc - global-abuse-guard không còn ngx.exit(403) khi thiếu, và
# s3-network-bucket-guard fallback tra Vault theo X-Client-IP (set từ IP
# nguồn trong PROXY-v2 header, "172.25.180.125" ở addr bên dưới) khi thiếu
# X-Network-Id. Script này giờ hỗ trợ cả 2 nhánh:
#   - Có network_id: truyền bình thường (arg 2), TLV 0x05 được gửi kèm.
#   - Không network_id: truyền chuỗi rỗng "" ở arg 2 - script BỎ HẲN TLV 0x05,
#     mô phỏng đúng client không qua HAProxy unique-id, để test nhánh fallback
#     X-Client-IP ở s3-network-bucket-guard.
#
# QUAN TRỌNG - real_ip_from (config-proxyhub.yaml): nginx chỉ tin field src
# trong TLV/address-block của PROXY-v2 khi TCP PEER THẬT (không phải giá trị
# khai trong payload) nằm trong 172.25.180.0/24. Chạy script với target_ip=
# 127.0.0.1 (mặc định, cùng host ProxyHub) khiến TCP peer luôn là 127.0.0.1
# - NGOÀI dải trusted - nên nginx bỏ qua src giả lập, $remote_addr rơi về
# 127.0.0.1 thật. Đây LÀ cơ chế chống spoof đang hoạt động đúng, không phải
# lỗi script.
#
# Để tự test được cả case "src được tin" (khớp production thật) ngay trên
# sandbox, KHÔNG cần máy khác trong dải 172.25.180.0/24: gán tạm 1 IP alias
# vào loopback rồi bind socket nguồn vào chính IP đó trước khi connect (Linux
# cho phép bind một địa chỉ bất kỳ trên interface lo, kể cả loopback), qua
# --bind-ip=. Ví dụ đủ bộ, chạy trên chính VM ProxyHub:
#
#   sudo ip addr add 172.25.180.99/32 dev lo          # 1 lần, cần sudo
#   python3 proxyv2-test-client.py s3-hcm.sds.infiniband.vn "" \
#       /test-bucket-not-onboarded/ 443 --bind-ip=172.25.180.99
#   sudo ip addr del 172.25.180.99/32 dev lo           # dọn lại sau khi xong
#
# Kỳ vọng: log s3-network-bucket-guard đổi từ "client_ip '127.0.0.1'" sang
# "client_ip '172.25.180.125'" (giá trị --src-ip, mặc định giữ nguyên
# "172.25.180.125" như trước - đổi bằng --src-ip= nếu cần IP khác). KHÔNG
# chạy --bind-ip trên IP không thuộc host mình quản lý - đây là giả lập
# nguồn, chỉ dùng cho test nội bộ trên chính sandbox.

import socket
import ssl
import struct
import sys

def send_proxyv2_request(host, target_ip, port, network_id, path="/", src_ip="172.25.180.125", bind_ip=None):
    sig = b'\r\n\r\n\x00\r\nQUIT\n'
    ver_cmd = bytes([0x21])
    fam_proto = bytes([0x11])
    addr = (
        socket.inet_aton(src_ip)
        + socket.inet_aton("172.26.8.30")
        + struct.pack('!HH', 51234, port)
    )
    if network_id:
        nid = network_id.encode()
        tlv = bytes([0x05]) + struct.pack('!H', len(nid)) + nid
    else:
        # network_id rỗng/None - bỏ hẳn TLV 0x05, mô phỏng kết nối không có
        # network identity (test nhánh fallback X-Client-IP).
        tlv = b""
    body = addr + tlv
    header = sig + ver_cmd + fam_proto + struct.pack('!H', len(body)) + body

    # bind_ip = TCP peer THẬT khi kết nối tới ProxyHub - khác src_ip (chỉ là
    # giá trị khai trong payload PROXY-v2). Chỉ khi bind_ip nằm trong dải
    # real_ip_from thì nginx mới tin src_ip; ngược lại $remote_addr = bind_ip
    # (hoặc IP hệ thống tự chọn nếu không set bind_ip).
    source_address = (bind_ip, 0) if bind_ip else None
    raw = socket.create_connection((target_ip, port), timeout=5, source_address=source_address)
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
    # --bind-ip=/--src-ip= là flag tùy chọn, tách riêng khỏi 4 tham số
    # positional cũ (host/network_id/path/port) - đặt ở đâu trên command
    # line cũng được, không ảnh hưởng thứ tự các lệnh cũ trong báo cáo.
    bind_ip = None
    src_ip = "172.25.180.125"
    positional = []
    for arg in sys.argv[1:]:
        if arg.startswith("--bind-ip="):
            bind_ip = arg.split("=", 1)[1]
        elif arg.startswith("--src-ip="):
            src_ip = arg.split("=", 1)[1]
        else:
            positional.append(arg)

    host = positional[0] if len(positional) > 0 else "s3-hcm.sds.infiniband.vn"
    # KHÔNG truyền arg2 -> dùng network_id mặc định (giữ tương thích lệnh cũ
    # trong báo cáo). Truyền arg2 = "" (chuỗi rỗng tường minh) -> bỏ TLV 0x05,
    # test nhánh không có network_id.
    nid = positional[1] if len(positional) > 1 else "test-network-id-manual-verify"
    path = positional[2] if len(positional) > 2 else "/"
    port = int(positional[3]) if len(positional) > 3 else 443

    print(f"[info] TCP bind nguồn: {bind_ip or '(mặc định hệ thống chọn)'} "
          f"| src khai trong TLV PROXY-v2: {src_ip}", file=sys.stderr)
    print(send_proxyv2_request(host, "127.0.0.1", port, nid, path, src_ip=src_ip, bind_ip=bind_ip))
