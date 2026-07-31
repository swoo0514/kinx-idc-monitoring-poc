#!/usr/bin/env python3
"""MSP 월간 리포트 발송 — Grafana 대시보드를 PDF 로 만들어 메일로 보낸다.

Grafana OSS 에는 예약 리포트 기능이 없다(Enterprise/Cloud 전용). 있는 것은 **렌더러**뿐이고,
그것은 OSS 에서도 동작한다("Image rendering works with Grafana OSS, Grafana Enterprise, and
Grafana Cloud"). 그래서 렌더러만 붙이고 예약·조립·발송은 이 스크립트가 한다.

  Grafana /render/d/<uid>  ->  PNG  ->  PDF(페이지 분할)  ->  메일(첨부 + 대시보드 링크)

**의존성을 늘리지 않는다.** PNG 의 IDAT 는 zlib deflate 이고 PDF 의 FlateDecode +
Predictor 15 가 PNG 필터를 그대로 이해하므로, 이미지 라이브러리 없이 PDF 를 만들 수 있다.
페이지를 나눌 때만 스캔라인을 풀었다가 다시 감는다(zlib 은 표준 라이브러리).

**승인 없이 나가지 않는다.** 서사 항목이 "검토 대기" 상태면 발송을 거부한다. 값 자체에도
게이트가 걸려 있어(승인 전에는 서사가 아이템에 실리지 않음) 이중 안전이다.

사용법·근거는 ansible/DEPLOY_GUIDE.md "MSP 월간 리포트".
"""

import argparse
import json
import os
import smtplib
import struct
import sys
import urllib.parse
import urllib.request
import zlib
from email.message import EmailMessage

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

PENDING = "검토 대기 — 승인 후 게시됩니다"
PT_PER_PX = 72.0 / 96.0          # 브라우저 96dpi 기준 -> PDF 포인트
DEFAULT_PAGE_PX = 1500           # 한 페이지에 담을 세로 픽셀 (A4 비율에 가깝게)


# ── PNG 읽기 ────────────────────────────────────────────────────────────────

def png_chunks(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("PNG 가 아니다 — 렌더 결과가 오류 페이지일 수 있다")
    i = 8
    while i < len(data):
        (ln,) = struct.unpack(">I", data[i:i + 4])
        typ = data[i + 4:i + 8]
        yield typ, data[i + 8:i + 8 + ln]
        i += 8 + ln + 4


def png_decode(data: bytes):
    """반환 (width, height, RGB 픽셀 바이트). 8비트·비인터레이스만 다룬다.

    Grafana 렌더러 산출물이 그 형식이다. 아니면 즉시 실패시킨다 — 조용히 깨진 PDF 를
    만드는 것보다 낫다.
    """
    idat, w, h, bd, ct = b"", 0, 0, 0, 0
    for typ, body in png_chunks(data):
        if typ == b"IHDR":
            w, h, bd, ct, _, _, interlace = struct.unpack(">IIBBBBB", body[:13])
            if bd != 8 or ct not in (2, 6) or interlace:
                raise ValueError("지원 밖 PNG (bitdepth=%d colortype=%d interlace=%d)"
                                 % (bd, ct, interlace))
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            break
    raw = zlib.decompress(idat)
    bpp = 4 if ct == 6 else 3
    stride = w * bpp
    out = bytearray(w * h * 3)
    prev = bytearray(stride)
    pos = 0
    for y in range(h):
        ft = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        # PNG 필터 복원 — 명세 그대로. Paeth 까지 다 나온다.
        if ft == 1:
            for x in range(bpp, stride):
                line[x] = (line[x] + line[x - bpp]) & 0xFF
        elif ft == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif ft == 3:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif ft == 4:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                c = prev[x - bpp] if x >= bpp else 0
                b = prev[x]
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        elif ft != 0:
            raise ValueError("알 수 없는 PNG 필터 %d" % ft)
        prev = line
        if bpp == 3:
            out[y * w * 3:(y + 1) * w * 3] = line
        else:                      # 알파는 버린다 — 리포트 배경은 불투명하다
            row = out
            base = y * w * 3
            for x in range(w):
                row[base + x * 3:base + x * 3 + 3] = line[x * 4:x * 4 + 3]
    return w, h, bytes(out)


# ── PDF 쓰기 ────────────────────────────────────────────────────────────────

def _obj(body: bytes) -> bytes:
    return body


def png_to_pdf(w: int, h: int, rgb: bytes, page_px: int = DEFAULT_PAGE_PX) -> bytes:
    """세로로 긴 렌더 결과를 페이지로 잘라 PDF 로. 한 장짜리 긴 PDF 는 인쇄가 안 된다."""
    slices = []
    y = 0
    while y < h:
        ph = min(page_px, h - y)
        rows = bytearray()
        for r in range(y, y + ph):
            rows.append(0)                       # 필터 없음
            rows += rgb[r * w * 3:(r + 1) * w * 3]
        slices.append((ph, zlib.compress(bytes(rows), 6)))
        y += ph

    objs = [b""]                                  # 1-based
    kids = []
    page_objs = []
    # 1 catalog, 2 pages, 그 뒤로 페이지마다 (page, image, content) 3개
    for i, (ph, comp) in enumerate(slices):
        pid = 3 + i * 3
        img_id, cnt_id = pid + 1, pid + 2
        wpt, hpt = w * PT_PER_PX, ph * PT_PER_PX
        page_objs.append((pid, img_id, cnt_id, ph, comp, wpt, hpt))
        kids.append(b"%d 0 R" % pid)

    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [" + b" ".join(kids) + b"] /Count %d >>" % len(kids))
    for pid, img_id, cnt_id, ph, comp, wpt, hpt in page_objs:
        objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
                     "/Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>"
                     % (wpt, hpt, img_id, cnt_id)).encode())
        objs.append(("<< /Type /XObject /Subtype /Image /Width %d /Height %d "
                     "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode "
                     "/Length %d >>" % (w, ph, len(comp))).encode() + b"\nstream\n"
                    + comp + b"\nendstream")
        content = ("q %.2f 0 0 %.2f 0 0 cm /Im0 Do Q" % (wpt, hpt)).encode()
        objs.append(("<< /Length %d >>" % len(content)).encode()
                    + b"\nstream\n" + content + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for n in range(1, len(objs)):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + objs[n] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % len(objs)
    out += b"0000000000 65535 f \n"
    for n in range(1, len(objs)):
        out += b"%010d 00000 n \n" % offsets[n]
    out += (b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs), xref))
    return bytes(out)


# ── Grafana · Zabbix ────────────────────────────────────────────────────────

def _get(url: str, headers: dict, timeout: int = 180) -> bytes:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def grafana_auth() -> dict:
    tok = os.environ.get("GRAFANA_TOKEN", "")
    if tok:
        return {"Authorization": "Bearer " + tok}
    import base64
    u = os.environ.get("GRAFANA_USER", "admin")
    p = os.environ.get("GRAFANA_ADMIN_PASSWORD", "") or os.environ.get("GRAFANA_PASSWORD", "")
    if not p:
        raise RuntimeError("GRAFANA_TOKEN 또는 GRAFANA_ADMIN_PASSWORD 가 필요하다")
    return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (u, p)).encode()).decode()}


def render(base: str, uid: str, customer: str, width: int, height: int, days: int) -> bytes:
    q = urllib.parse.urlencode({
        "orgId": 1, "width": width, "height": height, "kiosk": "", "theme": "light",
        "from": "now-%dd" % days, "to": "now", "var-customer": customer})
    url = "%s/render/d/%s/report?%s" % (base.rstrip("/"), uid, q)
    png = _get(url, grafana_auth())
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise RuntimeError("렌더 결과가 PNG 가 아니다(권한·렌더러 확인): %r" % png[:120])
    return png


def approval_state(zbx_url: str, token: str, host: str) -> dict:
    """서사 항목이 승인됐는지 Zabbix 에서 직접 본다. 값 자체가 게이트이므로 이게 곧 상태다."""
    body = {"jsonrpc": "2.0", "method": "item.get", "id": 1,
            "params": {"host": host, "output": ["key_", "lastvalue"],
                       "filter": {"key_": ["report.summary", "report.insight",
                                           "report.period"]}}}
    req = urllib.request.Request(zbx_url, method="POST", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json-rpc",
                                          "Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=30) as r:
        res = json.loads(r.read())
    if "error" in res:
        raise RuntimeError("Zabbix: %s" % res["error"])
    return {i["key_"]: i.get("lastvalue") or "" for i in res["result"]}


# ── 메일 ────────────────────────────────────────────────────────────────────

def build_mail(sender: str, to: list, customer: str, period: str, link: str,
               pdf: bytes, filename: str) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "[KINX MSP] %s 월간 운영 리포트 (%s)" % (customer, period or "")
    m["From"] = sender
    m["To"] = ", ".join(to)
    m.set_content(
        "%s 월간 운영 리포트를 보내드립니다.\n\n"
        "집계 기간: %s\n\n"
        "첨부한 PDF 는 발송 시점의 고정본입니다. 최신 상태와 개별 항목의 상세는 아래 "
        "대시보드에서 확인하실 수 있습니다.\n%s\n\n"
        "리포트에 포함된 원인·권고는 담당자 검토를 거친 내용입니다.\n"
        "— KINX 서비스운영팀\n" % (customer, period or "(미기재)", link))
    m.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)
    return m


def send_mail(msg: EmailMessage) -> str:
    host = os.environ.get("SMTP_HOST", "")
    if not host:
        raise RuntimeError("SMTP_HOST 미설정")
    port = int(os.environ.get("SMTP_PORT", "25"))
    user, pw = os.environ.get("SMTP_USER", ""), os.environ.get("SMTP_PASSWORD", "")
    with smtplib.SMTP(host, port, timeout=30) as s:
        if os.environ.get("SMTP_STARTTLS", "").lower() in ("1", "true", "yes"):
            s.starttls()
        if user:
            s.login(user, pw)
        s.send_message(msg)
    return "%s:%d" % (host, port)


# ── 검사 ────────────────────────────────────────────────────────────────────

def selftest() -> None:
    n = 0

    def ck(c, why):
        nonlocal n
        assert c, why
        n += 1

    # 필터 5종을 모두 태운 PNG 를 만들어 왕복시킨다 — Paeth 까지 안 밟으면 의미가 없다.
    w, h = 7, 6
    px = bytes(((x * 31 + y * 17) % 256) for y in range(h) for x in range(w * 3))
    raw = bytearray()
    prev = bytes(w * 3)
    for y in range(h):
        line = px[y * w * 3:(y + 1) * w * 3]
        ft = y % 5
        enc = bytearray()
        for x in range(w * 3):
            a = line[x - 3] if x >= 3 else 0
            b = prev[x]
            c = prev[x - 3] if x >= 3 else 0
            if ft == 0:
                v = line[x]
            elif ft == 1:
                v = line[x] - a
            elif ft == 2:
                v = line[x] - b
            elif ft == 3:
                v = line[x] - ((a + b) >> 1)
            else:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                v = line[x] - pr
            enc.append(v & 0xFF)
        raw.append(ft)
        raw += enc
        prev = line

    def chunk(t, b):
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(bytes(raw)))
           + chunk(b"IEND", b""))
    dw, dh, rgb = png_decode(png)
    ck((dw, dh) == (w, h), "크기 불일치")
    ck(rgb == px, "PNG 필터 복원이 틀렸다 — PDF 이미지가 깨진다")

    pdf = png_to_pdf(w, h, rgb, page_px=2)
    ck(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"), "PDF 골격")
    ck(pdf.count(b"/Type /Page\n") + pdf.count(b"/Type /Page ") == 3,
       "6줄 이미지를 2줄씩 3페이지로 못 나눴다")
    ck(b"/Filter /FlateDecode" in pdf, "이미지 스트림 필터")
    # xref 오프셋이 실제 객체 위치를 가리켜야 뷰어가 연다
    off = int(pdf.split(b"startxref\n")[1].split(b"\n")[0])
    ck(pdf[off:off + 4] == b"xref", "startxref 가 xref 를 안 가리킨다")

    # 알파 채널은 버리고 RGB 로 (배경이 불투명한 리포트라 무해)
    png4 = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00" + bytes([1, 2, 3, 255, 4, 5, 6, 255])))
            + chunk(b"IEND", b""))
    ck(png_decode(png4)[2] == bytes([1, 2, 3, 4, 5, 6]), "RGBA 처리")

    try:
        png_decode(b"<html>error</html>")
        raise AssertionError("PNG 아닌 입력을 통과시켰다")
    except ValueError:
        n += 1

    m = build_mail("a@b", ["c@d"], "Customer-B", "2026-07-01 ~ 2026-07-31",
                   "http://g/d/x", b"%PDF-1.4 x", "r.pdf")
    ck(m["Subject"].startswith("[KINX MSP] Customer-B"), "제목")
    ck(any(p.get_filename() == "r.pdf" for p in m.iter_attachments()), "첨부 누락")
    ck("http://g/d/x" in m.get_body(("plain",)).get_content(), "대시보드 링크 누락")

    print("ALL OK (%d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="MSP 월간 리포트 PDF 생성·발송")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--customer", help="Zabbix 호스트그룹 (예: Customers/Customer-B)")
    ap.add_argument("--target", help="리포트 호스트명 (예: report-Customer-B). 승인 확인용")
    ap.add_argument("--uid", default="kinx-msp-report")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--width", type=int, default=1400)
    ap.add_argument("--height", type=int, default=2800,
                    help="렌더 세로 픽셀. 대시보드가 잘리면 키운다")
    ap.add_argument("--page-px", type=int, default=DEFAULT_PAGE_PX)
    ap.add_argument("--out", help="PDF 저장 경로 (기본 ./<고객>-<기간>.pdf)")
    ap.add_argument("--to", default=os.environ.get("REPORT_TO", ""), help="쉼표 구분")
    ap.add_argument("--send", action="store_true", help="메일 발송. 없으면 PDF 만 만든다")
    ap.add_argument("--force", action="store_true",
                    help="승인 전이어도 발송. 기본은 거부한다")
    a = ap.parse_args()

    if a.selftest:
        selftest()
        return
    if not a.customer:
        sys.exit("[!] --customer 가 필요하다 (예: Customers/Customer-B)")
    short = a.customer.rstrip("/").split("/")[-1]
    target = a.target or ("report-%s" % short)

    period, state = "", {}
    zbx = os.environ.get("ZABBIX_URL", "")
    if zbx and os.environ.get("ZABBIX_TOKEN"):
        state = approval_state(zbx.rstrip("/") + "/api_jsonrpc.php",
                               os.environ["ZABBIX_TOKEN"], target)
        period = state.get("report.period", "")
        pending = [k for k in ("report.summary", "report.insight")
                   if state.get(k, "").startswith("검토 대기")]
        if pending:
            print("[!] 승인 전이다 — %s" % ", ".join(pending))
            if a.send and not a.force:
                sys.exit("[!] 발송을 거부한다. 검토 후 msp_report.py --approve 를 먼저 "
                         "실행하거나, 알고도 보내려면 --force")
    else:
        print("[!] ZABBIX_URL/ZABBIX_TOKEN 미설정 — 승인 상태를 확인하지 못한다")

    base = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
    print("렌더: %s  (%dx%d, %d일)" % (a.customer, a.width, a.height, a.days))
    png = render(base, a.uid, a.customer, a.width, a.height, a.days)
    w, h, rgb = png_decode(png)
    pdf = png_to_pdf(w, h, rgb, a.page_px)
    pages = pdf.count(b"/Type /Page ")
    out = a.out or ("%s-%s.pdf" % (short, (period.split(" ~ ")[0] or "report").strip()))
    with open(out, "wb") as f:
        f.write(pdf)
    print("PDF: %s  (%d x %d px -> %d페이지, %.1f KB)" % (out, w, h, pages, len(pdf) / 1024))

    link = "%s/d/%s?var-customer=%s&from=now-%dd&to=now" % (
        base.rstrip("/"), a.uid, urllib.parse.quote(a.customer), a.days)
    print("링크: %s" % link)
    if not a.send:
        print("\n[드라이런] 발송하지 않았다. 보내려면 --send --to <주소>")
        return
    to = [x.strip() for x in a.to.split(",") if x.strip()]
    if not to:
        sys.exit("[!] --to 또는 REPORT_TO 가 필요하다")
    msg = build_mail(os.environ.get("REPORT_FROM", "noreply@kinx.local"), to,
                     short, period, link, pdf, os.path.basename(out))
    where = send_mail(msg)
    print("[send] %s -> %s" % (where, ", ".join(to)))


if __name__ == "__main__":
    main()
