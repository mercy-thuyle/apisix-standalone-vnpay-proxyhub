# Note kỹ thuật — apisix-standalone ProxyHub

> Tài liệu tham chiếu kỹ thuật chính cho cụm ProxyHub — repo GitLab riêng
> (`apisix/proxyhub.git`, tách hoàn toàn khỏi `apisix-standalone` S3-storage).
> Theo đúng spec `link-local-gateway-flow-final-end.html` mục 06.
>
> Cập nhật gần nhất: 26/08/2026 — mục 1-6 đã hoàn thành phần kiến trúc/logic
> (mục 1-5 test thật, mục 6 đánh giá qua cấu trúc repo); còn lại backlog input
> bên ngoài (domain/upstream VCR-MAAS thật, Kafka topic, xác nhận VCR host).

---

## 0. Bối cảnh nghiệp vụ

### 0.1 PROXY Protocol KHÁC với giải mã TLS — 2 việc tách biệt hoàn toàn

#### a) Kịch bản bình thường — không có gì đứng giữa

```
Client ──TLS──> APISIX
```

`$remote_addr` (biến nginx đọc IP client) tự động đúng, không cần làm gì. Đây là cách cụm S3-storage hoạt động (client SDK ký SigV4 nối thẳng).

#### b) Khi có 1 tầng đứng giữa (load balancer/proxy) — 2 cách "cứu" IP thật, tuỳ tầng đó có đọc được HTTP hay không

| | Cách 1 — HTTP header (`X-Forwarded-For`) | Cách 2 — PROXY Protocol |
|---|---|---|
| Điều kiện | Tầng đứng giữa phải **giải mã được TLS, đọc được HTTP** | Tầng đứng giữa **KHÔNG đọc được HTTP** — chỉ chuyển tiếp nguyên xi luồng byte TCP/TLS (L4 passthrough) |
| Cơ chế | Proxy tự thêm 1 dòng text vào HTTP request | Trước khi gửi dữ liệu thật, gửi thêm vài chục byte ở đầu kết nối nói "kết nối này đến từ IP X, port Y" — APISIX cần listener đặc biệt để bóc |
| Dùng phổ biến ở | Hầu hết reverse proxy/CDN thông thường | Khi tầng trước là pure TCP passthrough |

**PROXY Protocol tiêu chuẩn chỉ mang đúng 1 thứ: IP + port nguồn/đích. Không có khái niệm "tenant", "network", hay bất kỳ thông tin nghiệp vụ nào khác.**

#### c) ProxyHub dùng Cách 2 — vì sao, và vì sao còn phải "chế" thêm `network_id`

**Vì sao Cách 2 (không phải Cách 1):** tầng đứng giữa ở đây (`socat`/HAProxy nằm trong network namespace `ovnmeta-<netid>` — mỗi network ảo OpenStack Neutron/OVN của khách hàng có 1 namespace riêng) **cố tình không giải mã TLS** — TLS phải xử lý tập trung tại đúng 1 chỗ (ProxyHub), không rải cert ra hàng trăm network namespace (khó quản lý, khó xoay vòng cert). Vì không giải mã TLS nên không có cách nào đọc/thêm HTTP header được → bắt buộc dùng PROXY Protocol.

**Vì sao cần thêm `network_id` — thứ PROXY Protocol chuẩn KHÔNG hề có:** có hàng trăm network ảo khác nhau (mỗi khách hàng 1 network riêng) cùng đổ traffic về 1 điểm ProxyHub duy nhất. Chỉ dựa IP nguồn **không đủ** để biết traffic của khách hàng nào — IP trong các network ảo hoàn toàn có thể trùng nhau giữa các tenant (đặc thù overlay network, không phải lỗi thiết kế). Giải pháp: mượn 1 field mở rộng có sẵn trong PROXY Protocol v2 gọi là **TLV** (Type-Length-Value — field tuỳ biến, PROXY-v2 cho phép nhét thêm thông tin ngoài IP/port) — cụ thể field `unique_id` (vốn HAProxy sinh ra để trace/correlate request qua nhiều proxy nối tiếp, KHÔNG phải để mang tenant ID) — rồi nhét `network_id` vào đó thay vì dùng đúng mục đích gốc.

#### d) Luồng đúng, đầy đủ vai trò từng thành phần

```
[VM khách hàng, trong network namespace ovnmeta-<netid>]
        │ (traffic ra ngoài từ VM)
        ▼
[HAProxy — chạy TRONG namespace đó]
        │  gán unique-id-format <network_id> vào TLV unique_id (0x05)
        │  bọc toàn bộ trong PROXY Protocol v2 header (send-proxy-v2 proxy-v2-options unique-id)
        ▼
[unix socket — nội bộ trong namespace]
        ▼
[socat — bridge từ unix socket ra macvlan interface (dải v180)]
        │  CHỈ forward nguyên xi byte, KHÔNG đụng vào nội dung
        ▼
[macvlan v180] ──► [APISIX/ProxyHub — proxy_protocol.listen_https_port :8443]
        │
        ├─ 1. Bóc PROXY-v2 header (nginx core, listen ... proxy_protocol)
        │     → $proxy_protocol_addr (IP), $proxy_protocol_tlv_unique_id (network_id)
        │
        ├─ 2. real_ip_header=proxy_protocol → rewrite $remote_addr
        │
        ├─ 3. TLS ClientHello bắt đầu NGAY SAU phần PROXY-v2 — APISIX MỚI giải mã TLS
        │     tại bước này, dùng cert của chính APISIX (apisix_routes/ssls/*.yaml)
        │
        └─ 4. global-abuse-guard.yaml (serverless-pre-function) đọc 2 biến trên,
              set header chuẩn X-Client-IP / X-Network-Id cho toàn bộ pipeline phía sau
```

**Phân công rõ 2 vai trò dễ nhầm lẫn:**
- **HAProxy** — bên sinh ra PROXY Protocol v2 + TLV `unique_id` (phần "đóng gói thông minh").
- **socat** — bên chuyển tiếp thuần byte từ unix socket ra tới macvlan interface (phần "ống dẫn", không hiểu/không đụng vào nội dung).

Cả 2 đều **không hề chạm vào nội dung TLS** — dữ liệu TLS được chuyển tiếp nguyên vẹn, còn nguyên bản mã hoá, từ VM tới tận APISIX.

#### e) Vì sao APISIX đọc được — không phải phép màu, là tính năng nginx core có thật

`proxy_protocol_tlv_unique_id` không phải biến tự chế — là biến **nginx core mã nguồn mở** (không phải NGINX Plus), có từ bản 1.23.2 trở lên (`$proxy_protocol_tlv_<tên>` cho các TLV có tên chuẩn: `alpn`, `authority`, `unique_id`). APISIX 3.17 build trên OpenResty 1.27.1.2 — thoả điều kiện version. Cơ chế: khi khai `listen 8443 ssl proxy_protocol;` (sinh ra từ `apisix.proxy_protocol.listen_https_port` trong `config-proxyhub.yaml`), nginx tự bóc PROXY-v2 header trước khi xử lý gì khác trên kết nối đó — không cần module/patch thêm.

#### f) Tóm tắt — bảng trả lời nhanh khi thuyết trình

| | PROXY Protocol chuẩn | ProxyHub |
|---|---|---|
| Mang thông tin gì | Chỉ IP + port nguồn/đích | Thêm `network_id` (mượn field `unique_id`, dùng sai mục đích gốc — chủ đích) |
| Vì sao cần PROXY Protocol (không phải header) | Tầng trước là pure TCP/TLS passthrough | Giống — lý do cụ thể: TLS phải tập trung 1 chỗ (ProxyHub), không rải ra từng network namespace |
| Danh tính client | Chỉ cần IP là đủ phân biệt | IP KHÔNG đủ (trùng giữa các network ảo) → cần thêm `network_id` mới phân biệt được tenant |
| Ai giải mã TLS | — | Chỉ APISIX/ProxyHub, **không phải** socat/HAProxy |

**Điểm quan trọng nhất khi bị hỏi "sao không làm đơn giản hơn":** độ phức tạp (giao thức lạ, field dùng sai mục đích) chỉ tồn tại đúng 1 chỗ duy nhất — ngay tại cửa vào ProxyHub. Sau bước `global-abuse-guard.yaml`, toàn bộ hệ thống phía sau (route, plugin, kể cả cụm S3-storage nếu traffic đi tiếp qua đó) chỉ thấy 2 HTTP header chuẩn (`X-Client-IP`, `X-Network-Id`) — không ai phải hiểu PROXY Protocol/TLV cả.

### 0.2 Vai trò các bên & khái niệm `network_id`

| Thành phần | Vai trò |
|---|---|
| **KaaS** | Dịch vụ team OpenStack trong doanh nghiệp — route `route-maas` |
| **S3** | Hệ thống object storage team Mercy (cùng doanh nghiệp) — route `route-s3` |
| **VCR** | Container registry team VCR (cùng doanh nghiệp) — route `route-vcr`, path-guard `/kaas` |
| **Khách hàng** | Người dùng được cấp VM qua OpenStack của doanh nghiệp — mỗi VM nằm trong 1 Neutron network riêng |
| **`network_id`** | Định danh network ảo (Neutron network) của VM khách hàng đó — dùng để ProxyHub biết traffic gọi ra ngoài (tới KaaS/S3/VCR) thuộc network/tenant nào, vì chỉ dựa IP nguồn là không đủ (IP có thể trùng giữa các network ảo khác nhau, đặc thù overlay network) |

KaaS/S3/VCR đều là service **nội bộ cùng doanh nghiệp**, ProxyHub đóng vai trò gateway tập trung duy nhất mà mọi VM khách hàng phải đi qua để gọi tới 3 service này — vừa giải quyết bài toán network reachability (VM subnet không route thẳng được tới backend), vừa là điểm kiểm soát chính sách tập trung (bucket allowlist theo network_id — mục 4).

---

## 1. Trạng thái tổng quan

| Mục (kế hoạch triển khai) | Trạng thái |
|---|---|
| Mục 1 — PROXY Protocol v2, chuẩn hoá `X-Network-Id`/`X-Client-IP` | ✅ Hoàn thành, đã test thật |
| Mục 2 — Route theo SNI/Host tới VCR/S3/MAAS | ✅ Hoàn thành, fix gốc (3 route tách `hosts` riêng, không còn dùng `priority`) — upstream backend thật (VCR/MAAS) vẫn chờ input bên ngoài, xem "Tồn đọng" |
| Mục 3 — VCR path-guard (`/kaas`) | ✅ Hoàn thành, đã test thật (plugin `uri-blocker`, 2 case: pass `/kaas`, block `/other-path`) |
| Mục 4 — S3 bucket allowlist qua Vault (custom plugin) | ✅ Hoàn thành, đã test thật (3 case: allow/deny bucket/deny network) |
| Mục 5 — Multisite (2 site, 1 bộ config chung) | ✅ Kiến trúc đã chốt (repo riêng, `DC_PROFILE=proxyhub` cố định) |
| Mục 6 — Khả năng mở rộng thêm site/service | ✅ Đã đánh giá — kiến trúc hiện tại (fragment 3-file-per-service, 1 config nhiều instance) đã tự scale, không cần refactor |

---

## 2. Đã hoàn thành

### 2.1 Kiến trúc repo & GitOps

- Tách repo GitLab riêng cho ProxyHub (`apisix/proxyhub.git`) — độc lập hoàn toàn khỏi `apisix-standalone` (S3-storage), lý do: `merge-fragments.sh`/`gitsync.sh` **không filter fragment theo profile thật** (chỉ dùng `DC_PROFILE` để đặt tên file output) — dùng chung repo sẽ gộp nhầm route S3/ProxyHub vào cùng 1 file.
- `DC_PROFILE` giữ nguyên tên biến + toàn bộ logic cũ (không đổi thành `SITE_ID`) — chỉ khác: giá trị luôn cố định `proxyhub` ở mọi site (không phân biệt `hcm`/`han` như S3), vì ProxyHub dùng **1 bộ config chung cho 2 site**, chỉ khác instance vật lý (giữ blast-radius isolation theo spec).
- `README.md` + `docker-compose.yaml` viết lại từ template S3-storage, lược bỏ phần không phù hợp:
  - Bỏ `redis`/`redis-exporter` (S3 dùng thử nghiệm QoS cross-node, ProxyHub chưa cần).
  - Bỏ 5 custom plugin S3 (`s3-accesskey-extractor`, `s3-qos-consumer`, `s3-traffic-classifier`, ...) — gắn chặt SigV4/AKID, không tái dùng được.
  - Bỏ `apisix_routes/consumer_groups/` + `consumers/` — ProxyHub xác định danh tính qua `network_id` (TLV), không qua APISIX Consumer.
  - Giữ `dashboard/` theo yêu cầu (dù đề xuất ban đầu là bỏ).

### 2.2 Mục 1 — PROXY Protocol v2 + chuẩn hoá header

**Vì sao không dùng `ssl.listen` thường:** PROXY-v2 là preamble ở tầng TCP, đứng trước TLS ClientHello — cần listener riêng biệt hiểu được `proxy_protocol`, không thể gắn thêm vào `ssl.listen` sẵn có. Xác nhận qua `config-default.yaml` chính thức của APISIX + cộng đồng (DigitalOcean case tương tự) + source `ngx_tpl.lua`.

**Config `apisix_config/config-proxyhub.yaml`:**
```yaml
apisix:
  proxy_protocol:
    listen_https_port: 8443
    enable_tcp_pp: false

nginx_config:
  http:
    real_ip_header: "proxy_protocol"
    real_ip_from:
      - "172.25.180.0/24"    # TODO: xác nhận đúng CIDR macvlan v180 thật
```

**Global rule chuẩn hoá header** (`apisix_routes/global_rules/global-abuse-guard.yaml` — đã GỘP chung với logic X-Node-Id cũ, xem bug #3 mục 3.3):
```lua
local network_id = ngx.var.proxy_protocol_tlv_unique_id
if not network_id or network_id == "" then
  return ngx.exit(403)
end
ngx.req.set_header("X-Network-Id", network_id)
ngx.req.set_header("X-Client-IP", ngx.var.remote_addr)
```

`network_id` lấy từ TLV `unique_id` (0x05) của PROXY-v2 — do HAProxy gán qua `unique-id-format <network_id>` + `send-proxy-v2 proxy-v2-options unique-id`. Biến `$proxy_protocol_tlv_unique_id` là tính năng nginx core mã nguồn mở từ bản 1.23.2, APISIX 3.17 (OpenResty 1.27.1.2) thoả điều kiện.

**Test thật đã pass** (dùng script `test-proxy-v2.py`, xem mục 5).

### 2.3 Mục 4 — S3 bucket allowlist qua Vault

**Kiến trúc:** custom plugin `s3-network-bucket-guard.lua` đọc `X-Network-Id` → tách bucket từ Host (virtual-hosted-style) hoặc URI (path-style) → gọi Vault KV v2 qua `vault-kv-client.lua` (dùng `resty.http`, **không** qua cơ chế `secret_providers`/`$secret://` built-in của APISIX — cơ chế đó chỉ resolve giá trị tĩnh lúc load config, không lookup động theo key runtime được) → cache `lua_shared_dict` (TTL 60s) → so khớp `buckets` allowlist → allow/deny.

**Vault path:** `cloud/profile/app/apisix-proxyhub/network-buckets/<network_id>` — namespace riêng (`app/apisix-proxyhub/*`), tách khỏi `app/apisix/*` của cụm S3-storage. Value format:
```json
{"buckets": ["bucket-test-1", "bucket-test-2"]}
```

**Quyết định thiết kế quan trọng:**
- `fail_open: false` (mặc định) — Vault sập → chặn hết S3 traffic (ưu tiên đúng chính sách hơn uptime).
- `network_id` không có trong Vault → **luôn fail-closed**, bất kể `fail_open` (khác loại lỗi với "Vault hạ tầng chết").

**3 case test đã pass** (04:13, 26/08/2026):
| Case | network_id | bucket | Kết quả |
|---|---|---|---|
| Được phép | `test-network-id` | `bucket-test-1` | `200`, pass qua upstream |
| Bucket không được phép | `test-network-id` | `bucket-khong-ton-tai` | `403 "bucket not in allowlist for this network"` |
| Network lạ | `network-id-khong-ton-tai` | `bucket-test-1` | `403 "network not authorized for any bucket"` |

### 2.4 Mục 2 — Route theo SNI/Host (fix gốc, thay cho `priority` tạm)

3 route (`route-vcr`, `route-s3`, `route-maas`) đã tách `hosts` riêng biệt hoàn toàn:

| Route | `hosts` | `uri` | `service_id` |
|---|---|---|---|
| `route-s3` | `s3-hcm.sds.infiniband.vn`, `*.s3-hcm.sds.infiniband.vn` | `/*` | `service-upstream-s3` |
| `route-vcr` | `vcr.infiniband.vn`, `*.vcr.infiniband.vn` | `/*` (lọc path qua `uri-blocker`, xem 2.5) | `service-upstream-vcr` |
| `route-maas` | `maas.infiniband.vn`, `*.maas.infiniband.vn` | `/*` | `service-upstream-maas` |

Radix router phân biệt được ngay từ bước match `hosts` — không còn cạnh tranh thứ tự merge như bug #3.6, nên đã bỏ hẳn `priority: 10` khỏi `route-s3.yaml`. Đây là fix gốc thật sự, không phải tạm.

**Domain hiện dùng là domain tượng trưng** (`vcr.infiniband.vn`, `maas.infiniband.vn`) — do chưa có domain sản phẩm thật từ team VCR/MAAS, dùng để tách namespace SNI cho đúng logic trong lúc chờ. Cert: cả 2 host trên match SNI của `ssl-infiniband.vn.yaml` (`*.infiniband.vn`), **khác** với `ssl-sds.infiniband.vn.yaml` (`*.sds.infiniband.vn`) đang dùng cho `route-s3` — 2 file cert riêng biệt, cần inject đúng cert/key vào đúng file, không dùng lẫn.

**Backend upstream (`upstream-vcr.yaml`, `upstream-maas.yaml`) vẫn trỏ tạm 3 node Cloudian** `172.26.29.231-233:8443` — chủ đích, vì mục 2 chỉ giải quyết bài toán routing (route đúng request tới đúng service theo host), không phụ thuộc backend thật đã có hay chưa. Khi test qua `/kaas` (2.5), response 404 nhận được là response thật của Cloudian (redirect `/s3/login.htm`) — xác nhận request đã tới đúng backend tạm, không phải lỗi.

### 2.5 Mục 3 — VCR path-guard `/kaas` qua plugin `uri-blocker`

**Kiến trúc:** dùng plugin có sẵn `uri-blocker` (đã bật trong `plugins:` của `config-proxyhub.yaml`) thay vì router-level `uri` — lý do chọn: cho phép trả `rejected_code`/`rejected_msg` tuỳ biến (403 + message rõ ràng) thay vì 404 mặc định của router khi không route nào khớp.

**Config `route-vcr.yaml`:**
```yaml
plugins:
  uri-blocker:
    block_rules:
      - "^(?!/kaas([/?]|$))"
    rejected_code: 403
    rejected_msg: "Your path not allowed on VCR route, only /kaas is served."
```

Regex dùng lookahead phủ định: match (⇒ block) MỌI uri **không** bắt đầu đúng `/kaas` + kết thúc bằng `/`, `?`, hoặc hết chuỗi — 3 điều kiện kết thúc để không chặn nhầm `/kaas` trần lẫn `/kaas?x=1` (query string). `uri-blocker` match trên `ctx.var.request_uri` (đã normalize từ APISIX ≥ 2.10.2, fix `CVE-2021-43557` — bản `3.17.0` đang dùng không bị ảnh hưởng bởi path-traversal bypass của phiên bản cũ).

**2 case test đã pass** (qua `test-proxy-v2.py`, 09:48, 26/08/2026):

| Path | Kết quả | Ghi chú |
|---|---|---|
| `/kaas` | `404` (từ Cloudian, `upstream_status: 404`, redirect `/s3/login.htm`) | Pass qua `uri-blocker`, tới đúng backend tạm — xem 2.4 |
| `/other-path` | `403`, body `{"error_msg":"Your path not allowed on VCR route, only /kaas is served."}` | Log xác nhận `uri-blocker exits with http status code 403` |

**Lưu ý vận hành:** phải test qua `test-proxy-v2.py` (giả lập PROXY-v2 + TLV `network_id`), **không dùng curl trần trực tiếp**. Curl trần bị `global-abuse-guard` (global rule, phase `rewrite`, chạy trước `access` — phase của `uri-blocker`) chặn `403` sớm vì thiếu TLV `unique_id`, response là trang lỗi HTML generic của APISIX — dễ nhầm là `uri-blocker` đang chặn trong khi thực ra request chưa bao giờ chạm tới nó.

---

## 3. Bug đã phát hiện & fix trong quá trình triển khai

### 3.1 `1-patch-template-lua.sh` — script chết vì `set -u` + biến chưa khai

**Triệu chứng:** chỉ comment 2 dòng khai biến `TPL`/`INIT` (không comment nguyên khối lệnh dùng chúng) → `set -euo pipefail` làm script thoát ngay ở dòng `docker run ... "${TPL}"` (unbound variable), các patch phía sau (`vault.lua` — patch quan trọng nhất) không bao giờ chạy tới.

**Fix:** comment/xoá NGUYÊN KHỐI lệnh Patch [1] (`ngx_tpl.lua`) và [2] (`init.lua`), không chỉ dòng khai biến. Đồng thời sửa 2 dòng ở phần tổng kết cuối script vẫn in hướng dẫn mount volume cho `ngx_tpl.lua`/`init.lua` dù 2 file đó không được tạo — nếu làm theo sẽ bind-mount vào file không tồn tại → Docker tự tạo thành directory rỗng (`Is a directory` khi load plugin).

### 3.2 `3-decrypt-certs.sh` — permission `.key` chặn gitsync đọc

**Triệu chứng:** `sed: can't read /tmp/certs/infiniband.vn.key: Permission denied` trong `inject-certs.sh` (chạy trong container `gitsync`, UID `65533`).

**Root cause:** `.key` chmod `600` (owner-only) trong khi `.cert` chmod `640` (group-read) — cả hai cùng group `65533` (do thư mục `certs/` có setgid, propagate group cho file mới), nhưng `600` không có bit group nào cả nên gitsync (không phải owner) không đọc được, dù đúng group.

**Fix:** đổi `.key` từ `chmod 600` → `chmod 640`, đối xứng với `.cert`. Vẫn không world-readable, chỉ mở thêm cho group (chỉ chứa gitsync/apisix).

### 3.3 `config-proxyhub.yaml` — `duplicate listen 0.0.0.0:8443`

**Root cause:** `proxy_protocol.listen_https_port: 8443` VÀ `ssl.listen: [{port: 8443}]` cùng khai port 8443 — đây là **2 cơ chế độc lập** trong `ngx_tpl.lua`, mỗi cái tự sinh 1 dòng `listen ... ssl` riêng trong `nginx.conf`, không phải cái này override cái kia. Xác nhận qua `config-default.yaml` chính thức + community report + source `ngx_tpl.lua` (`apache/apisix#12828`).

**Fix:** bỏ `- port: 8443` khỏi `ssl.listen`, chỉ giữ ở `proxy_protocol.listen_https_port`.

### 3.4 `merge-fragments.sh` — `while read` âm thầm drop dòng cuối file

**Triệu chứng:** `'end' expected (to close 'function' at line 1) near '<eof>'` khi load `global_rules` — function Lua bị thiếu dòng `end` cuối cùng dù file gốc trên đĩa có đủ.

**Root cause (đã tái hiện trực tiếp bằng cách chạy thử script, không suy đoán):** file fragment thiếu newline cuối (`wc -l` đếm 21 dòng, `awk 'END{print NR}'` đếm 22 — dòng 22 không có `\n` theo sau). `strip_key_header()` dùng `while IFS= read -r line; do ... done < "$1"` — gotcha kinh điển của POSIX sh: `read` trả về non-zero ở dòng cuối không có `\n`, khiến vòng lặp bỏ qua dòng đó, không báo lỗi gì.

**Fix (ở tầng script, áp dụng cho MỌI fragment tương lai, không phải chỉ 1 file):**
```sh
{ cat "$1"; echo; } | while IFS= read -r line; do ...
```
đảm bảo luôn có newline cuối trước khi đưa vào read loop, bất kể file gốc có hay không.

### 3.5 `global_rules` — 2 file cùng khai `serverless-pre-function` → APISIX loại bỏ CẢ HAI

**Triệu chứng:** `X-Network-Id` không hề được set dù global rule "đã load", request không bị reject dù thiếu network_id, cả `global-abuse-guard.yaml` (X-Node-Id) lẫn `global-network-identity.yaml` (X-Network-Id) đều không chạy.

**Root cause:** log `Found serverless-pre-function configured across different global rules. Removing it from execution list` — APISIX **chỉ cho phép 1 instance/loại plugin hiệu lực trong TOÀN BỘ `global_rules`**, không phải theo từng `id`. 2 file khác nhau cùng khai `serverless-pre-function` → bị coi là xung đột, loại bỏ khỏi execution list ở CẢ HAI, không merge/chạy cái nào.

**Fix:** gộp toàn bộ logic `serverless-pre-function` cấp global vào 1 file duy nhất (`global-abuse-guard.yaml`), xoá `global-network-identity.yaml`. Nguyên tắc rút ra: **mọi logic `serverless-pre-function` ở tầng global PHẢI gộp chung 1 file**, không được tách theo mục đích như ở route-level.

### 3.6 Routing — 3 route (VCR/S3/MAAS) dùng chung `hosts`, match không đoán trước được

**Triệu chứng:** request `Host: bucket-test-1.s3-hcm.sds.infiniband.vn` (đáng lẽ khớp `route-s3`) lại match vào `route-maas` — `plugin_config_id` (bucket-guard) gắn ở `route-s3` không được thực thi, response vẫn ra "đúng" vì `upstream-maas` (bug #3.7) tình cờ trỏ cùng IP Cloudian.

**Root cause:** `route-vcr`, `route-s3`, `route-maas` đều có `hosts: [s3-hcm.sds.infiniband.vn, *.s3-hcm.sds.infiniband.vn]` giống hệt nhau (leftover copy-paste, chưa có domain thật riêng cho VCR/MAAS). APISIX (radix router) không có tiêu chí phân biệt khi `hosts`+`uri` trùng tuyệt đối — thứ tự thắng phụ thuộc thứ tự merge, không đoán trước được.

**Fix tạm lúc phát hiện:** thêm `priority: 10` vào `route-s3.yaml` để đảm bảo thắng khi hosts trùng.

**Fix gốc (đã áp dụng — xem mục 2.4):** tách `hosts` thật riêng cho từng route (`vcr.infiniband.vn`, `s3-hcm.sds.infiniband.vn`, `maas.infiniband.vn`) — hết cạnh tranh thứ tự merge, đã bỏ `priority: 10` khỏi `route-s3.yaml`.

### 3.7 `upstream-maas.yaml` — trỏ thẳng Cloudian, giống bug `upstream-s3` trước đó

`upstream-maas.yaml` copy-paste từ template S3-storage, trỏ `172.26.29.231-233:8443` (Cloudian CMC) — MAAS lẽ ra là service hoàn toàn khác. **Chưa fix** — chủ đích giữ tạm để không phụ thuộc backend thật khi test routing/policy (xem mục 2.4), chờ domain/IP MAAS thật (tồn đọng #1).

### 3.8 `access_log_format` — field `network_id` map sai biến

`"network_id": "$http_x_route_id"` — đang lấy route_id, không phải `X-Network-Id` thật. Gây nhiễu lớn lúc debug bug #3.6 (log tưởng như network_id = "route-maas"). Đã sửa thành `"$http_x_network_id"`.

### 3.9 Vault — path bị hiểu nhầm dạng string-prefix, thực chất match theo segment path (`/`)

Test `sys/capabilities-self` trên `app/apisix-proxyhub` (không có gì theo sau) và `app/apisix` (tương tự) đều chỉ ra `["list"]` dù policy đã cấp full quyền cho `app/apisix-proxyhub/*` — vì Vault match theo path segment thật (`path "..../*"` yêu cầu có nội dung sau dấu `/`), không phải so khớp chuỗi ký tự. Test đúng phải thêm 1 segment con phía sau mới phản ánh đúng quyền.

### 3.10 Vault — secret tạo sai path qua UI (leaf thay vì folder)

**Triệu chứng:** `s3-network-bucket-guard` trả `403 "network not authorized"` dù đã tạo data trên Vault UI, `curl GET` đúng path trả `404` sạch (không phải lỗi quyền).

**Root cause:** thao tác UI lần đầu dừng path ở `app/apisix-proxyhub/` rồi gõ `network-buckets` vào ô field-key — tạo secret tại `app/apisix-proxyhub/network-buckets` (leaf), không phải tại `app/apisix-proxyhub/network-buckets/<network_id>` (folder chứa nhiều network_id). Xác nhận qua `LIST` — key `network-buckets` xuất hiện KHÔNG có dấu `/` theo sau (leaf, không phải folder).

**Fix:** tạo lại đúng path đầy đủ `app/apisix-proxyhub/network-buckets/test-network-id`, JSON toggle bật, value `{"buckets": [...]}`.

### 3.11 `route-vcr.yaml` — field `uri` khai sai kiểu (list thay vì string) → APISIX reject cả route

**Triệu chứng:** sau khi thêm `uri-blocker`, gitsync hot-reload xong nhưng route `route-vcr` không hoạt động — cả `/kaas` lẫn path khác đều không route đúng, log lặp mỗi lần reload:
```
config_yaml.lua:331: failed to check item data of [routes] err:property "uri"
validation failed: wrong type: expected string, got table
```

**Root cause:** trong lúc merge 2 hướng tiếp cận (router-level `uri` list + `uri-blocker`), file bị để lại dạng:
```yaml
uri:
  - "/*"
  # - "/kaas"
  # - "/kaas/*"
```
Field `uri` (số ít) trong schema APISIX **bắt buộc là string**, không chấp nhận array. Muốn khai nhiều pattern dạng list phải dùng field **khác tên**, `uris` (số nhiều) — đây là 2 field độc lập trong schema (`uris` là "syntactic sugar", tự APISIX gộp vào `uri` nội bộ khi load), không phải cùng 1 field chấp nhận 2 kiểu dữ liệu. APISIX từ chối toàn bộ route này khỏi execution list, im lặng không route nào khớp cho tới khi sửa field.

**Fix:** vì chỉ còn đúng 1 giá trị active (`"/*"`), trả về dạng string thay vì list:
```diff
-    uri:
-      - "/*"
-      # - "/kaas"
-      # - "/kaas/*"
+    uri: "/*"
```

---

## 4. Tồn đọng (TODO)

| # | Việc | Ưu tiên | Ghi chú |
|---|---|---|---|
| 1 | `upstream-vcr.yaml`/`upstream-maas.yaml` vẫn trỏ tạm Cloudian, cần IP/domain VCR/MAAS thật | Cao | Chờ input team VCR/MAAS — routing (mục 2) đã xong, chỉ còn backend |
| 2 | Domain thật cho VCR/MAAS (hiện dùng tượng trưng `vcr.infiniband.vn`/`maas.infiniband.vn`) | Cao | Cần trước khi go production, sandbox test không bị chặn bởi việc này |
| 3 | Xác nhận với team VCR: `*.vcr.infiniband.vn` (wildcard subdomain) có cần giữ không, hay VCR (registry) chỉ route theo path chuẩn Docker Registry API v2 (không có khái niệm subdomain-per-tenant như S3) — nghi vấn leftover copy-paste từ template S3 (cùng dạng bug #3.7) | Trung bình | Xem mục 2.4 |
| 4 | Kafka logger lỗi liên tục `not found topic, topic: apisix-proxyhub` (topic name thật đã đổi từ `apisix-gateway-${{DC_PROFILE}}` sang `apisix-${{DC_PROFILE}}` — note cũ ghi sai tên topic) | Trung bình | Không chặn traffic, nhưng cần tạo topic `apisix-proxyhub` (Strimzi `KafkaTopic` CR) hoặc tắt `kafka-logger` tạm thời — xác nhận ai sở hữu (đội Kafka hay Mercy tự tạo) |
| 5 | `X-Forwarded-Port` patch (`ngx_tpl.lua`/`init.lua`) — quyết định để mở, cần xác nhận lại khi chốt route S3 backend qua cụm S3-storage (khả năng cao cần áp lại vì thêm 1 hop gateway) | Trung bình | Xem note-kỹ-thuật-apisix.md (cụm S3) |
| 6 | Chuyển cert fetch trong `3-decrypt-certs.sh` từ decrypt AES-passphrase (`CERT_PASSPHRASE`) sang lấy trực tiếp từ Vault KV (`vault kv get -field=cert/key`) — khối lệnh đã có sẵn dạng comment ngay trong script, chỉ cần bật + xác nhận Vault mount/path cho cert (namespace khác `network-buckets` của mục 4). Luồng sau đó giữ nguyên (`./certs/<domain>.{cert,key}` → `inject-certs.sh` sed vào placeholder) | Trung bình | **Không** phải cơ chế `secret_providers`/`$secret://vault/...` native của APISIX — cơ chế đó đã xác nhận có bug (`PEM_read_bio_X509_AUX() failed`, `vault.lua` không được gọi trong `ssl_phase`) ở cụm S3-storage, quyết định không dùng lại cho ProxyHub |
| 7 | `access_log_format` field `"akid"` vẫn map `$http_x_s3_access_key` (khái niệm SigV4 cũ, không áp dụng ProxyHub) | Thấp | Cosmetic |
| 8 | README repo GitLab còn nội dung Ceph/S3-generic lẫn trong bảng "Plugin list tối ưu" — không phản ánh đúng plugin thật đang chạy | Thấp | Đã note, chờ tinh chỉnh sau |
| 9 | `scripts/libraries/decrypt-cert-helper.sh` + `cert-list-domains.txt` — chưa đổi domain list sang FQDN VCR/S3/MAAS thật; xác nhận cert `*.infiniband.vn` (dùng cho VCR/MAAS) và `*.sds.infiniband.vn` (dùng cho S3) đã inject đúng file, không lẫn | Thấp | |
| 10 | Vault policy `app/proxyhub/*` (namespace dự kiến ban đầu, KHÔNG dùng) vẫn còn tồn tại với quyền `list`-only — dọn lại nếu không dùng nữa, tránh nhầm lẫn 2 namespace tương tự tên (`app/proxyhub` vs `app/apisix-proxyhub`) | Thấp | |

---

## 5. Công cụ tham chiếu

### 5.1 `test-proxy-v2.py` — giả lập PROXY Protocol v2 + TLS để test

Không dùng `curl` trần được (global rule reject 403 nếu thiếu TLV `unique_id`), không dùng `socat` trực tiếp (không tự sinh TLV custom). Script Python thuần (`socket`/`ssl`/`struct`, không cần pip install) tự dựng đúng binary PROXY-v2 header (kèm TLV `0x05 unique_id = network_id`) rồi bắt tay TLS qua đó.

```bash
python3 test-proxy-v2.py --host 127.0.0.1 --port 8443 \
  --sni <bucket>.s3-hcm.sds.infiniband.vn \
  --network-id <network_id> \
  --path /
```

(Toàn bộ source đã gửi trong hội thoại — copy nguyên khối heredoc `cat > test-proxy-v2.py << 'PYEOF' ... PYEOF`.)

### 5.2 Debug Vault — capabilities-self (biết quyền token nhanh nhất)

```bash
curl -sk -H "X-Vault-Token: ${VAULT_TOKEN}" -X POST \
  -d '{"paths": ["cloud/profile/data/app/apisix-proxyhub/network-buckets/<key>"]}' \
  "${VAULT_ADDR}/v1/sys/capabilities-self"
```

`["read"]` = đủ quyền, `["list"]`/`["deny"]` = không đủ (`list` KHÔNG phải quyền đọc nội dung).

### 5.3 Debug Vault — LIST để biết chính xác cấu trúc thật đang tồn tại

```bash
curl -sk -H "X-Vault-Token: ${VAULT_TOKEN}" -X LIST \
  "${VAULT_ADDR}/v1/cloud/profile/metadata/app/apisix-proxyhub"
```

Key có dấu `/` theo sau = folder (còn con bên trong). Key KHÔNG có `/` = leaf (chính nó là 1 secret, dừng ở đó).

### 5.4 Đọc token/env THẬT đang chạy trong container (không phải token gõ tay ở SSH)

```bash
CONTAINER_TOKEN=$(docker exec apisix-standalone env | grep ^VAULT_TOKEN= | cut -d= -f2-)
CONTAINER_ADDR=$(docker exec apisix-standalone env | grep ^VAULT_ADDR= | cut -d= -f2-)
```

### 5.5 Đối chiếu nội dung fragment SAU KHI MERGE (không phải file fragment gốc)

```bash
grep -A 15 -- '── src: routes/s3/route-s3.yaml' apisix_routes/apisix-proxyhub.yaml
grep -n '── src:' apisix_routes/apisix-proxyhub.yaml    # liệt kê toàn bộ file đã merge
```

### 5.6 Test merge-fragments.sh cô lập, không phụ thuộc timing gitsync/container

```bash
sh scripts/runtime/merge-fragments.sh apisix_routes /tmp/test-output.yaml 2>&1 | tail -10
```
