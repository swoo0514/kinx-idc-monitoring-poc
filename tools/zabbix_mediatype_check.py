#!/usr/bin/env python3
"""mediatype.get 1콜 — 커스텀 Slack 스크립트의 발송 경로 판별 (읽기 전용)

목적·판독법은 tools/RECON_GUIDE.md 참조.
사용법은 기존 정찰 스크립트와 동일:
  (bash)        export ZABBIX_URL=... ZABBIX_TOKEN=...
  (PowerShell)  $env:ZABBIX_URL="..."; $env:ZABBIX_TOKEN="..."
  python tools/zabbix_mediatype_check.py

주의: Script형 미디어의 실행 인자(parameters)에는 Slack 웹훅 URL(크리덴셜)이 들어있을 수
있어 기본 조회에서 제외한다. 출력 결과를 저장한다면 private/ 아래에만 둘 것.
API 근거: https://www.zabbix.com/documentation/7.0/en/manual/api/reference/mediatype/get
(type: 0=Email, 1=Script, 2=SMS, 4=Webhook / status: 0=활성, 1=비활성)
인증은 Authorization: Bearer 헤더 사용 — Zabbix 6.4+ (실환경 7.0.24/7.0.27 확인됨).
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

TYPE_NAMES = {"0": "Email", "1": "Script", "2": "SMS", "4": "Webhook"}
STATUS_NAMES = {"0": "활성", "1": "비활성"}


def api_call(url, token, method, params, timeout=30, insecure=False):
    # 작업 원칙 4 를 코드로 강제한다(독스트링의 "읽기 전용"은 보증이 아니다).
    if not method.endswith(".get"):
        raise RuntimeError("read-only violation: %s — 이 도구는 .get 만 호출한다" % method)
    if not url.rstrip("/").endswith("api_jsonrpc.php"):
        url = url.rstrip("/") + "/api_jsonrpc.php"
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {
        "Content-Type": "application/json-rpc",
        "Authorization": "Bearer " + token,
    }
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, json.dumps(payload).encode("utf-8"), headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        sys.exit("[!] 접속 실패: %s" % e)
    if "error" in body:
        sys.exit("[!] API 오류: %s" % json.dumps(body["error"], ensure_ascii=False))
    return body["result"]


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass

    ap = argparse.ArgumentParser(description="미디어 타입 목록 + 사용 액션 조회 (읽기 전용)")
    ap.add_argument("--url", default=os.environ.get("ZABBIX_URL"))
    ap.add_argument("--token", default=os.environ.get("ZABBIX_TOKEN"))
    ap.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략")
    args = ap.parse_args()
    if not args.url or not args.token:
        sys.exit("[!] ZABBIX_URL / ZABBIX_TOKEN 환경변수 또는 --url/--token 필요")

    # sortfield는 mediatypeid만 허용되므로 이름순 정렬은 클라이언트에서 수행
    mtypes = api_call(args.url, args.token, "mediatype.get", {
        "output": ["mediatypeid", "name", "type", "status", "exec_path", "maxattempts"],
        "selectActions": ["actionid", "name", "status"],
    }, insecure=args.insecure)
    mtypes.sort(key=lambda m: str(m.get("name", "")))

    print("| 미디어 타입 | 종류 | 상태 | 스크립트 파일(exec_path) | 사용 액션 (상태) |")
    print("|---|---|---|---|---|")
    for m in mtypes:
        actions = ", ".join(
            "%s(%s)" % (a["name"], STATUS_NAMES.get(str(a.get("status")), "?"))
            for a in m.get("actions", [])
        ) or "-"
        print("| %s | %s | %s | %s | %s |" % (
            m.get("name", "?"),
            TYPE_NAMES.get(str(m.get("type")), "type=%s" % m.get("type")),
            STATUS_NAMES.get(str(m.get("status")), "?"),
            m.get("exec_path") or "-",
            actions,
        ))

    print()
    print("판독 힌트 (상세: tools/RECON_GUIDE.md)")
    print("- 팀 Slack을 쏘는 스크립트가 Script형 미디어로 목록에 있으면:")
    print("  발송 시 alert.get에 잡히는 구조 → '신규 Slack 발송 0건'은 실제 0건.")
    print("  → 다음 확인: 해당 미디어를 쓰는 액션의 operation 미디어 설정 (§2-2)")
    print("- 목록에 없으면: Zabbix 알림 체계 밖(크론/외부 릴레이) 발송 → alert.get")
    print("  비포착이 구조적으로 정상 = '발송 가시성 부재' 진단의 실증.")


if __name__ == "__main__":
    main()
