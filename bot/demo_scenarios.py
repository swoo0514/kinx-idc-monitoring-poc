"""봇 일반화 리허설 — 여러 사건 유형을 봇에 통과시켜 분석이 일반화되는지 확인.

랩 Zabbix 없이 수집기만 가짜로 대체하고 마스킹→LLM(실 Claude)→Slack은 진짜로 탄다.
"복제 한 장면 트릭이 아니라 디스크·서비스·보안·네트워크에도 사건에 맞는 분석을 내는가"를
빠르게(랩 chaos 없이) 검증하는 용도. 특히 보안 시나리오에선 '침해'로 다르게 결론내야 한다.

실행: python demo_scenarios.py   (ANTHROPIC_API_KEY 없으면 열화, SLACK 없으면 콘솔만)
"""

import asyncio
import os

from gateway import collector, triage


def _ctx(name, expr, key, units, recent, prejudge, logs=None, security=None,
         host="lab-app07", group="KINX WEB"):
    return {
        "event": {"eventid": "1", "name": name, "clock": recent[-1]["clock"]},
        "trigger": {"description": name, "expression": expr},
        "host": {"host": host, "name": host,
                 "interfaces": [{"ip": "192.0.2.7", "dns": ""}],
                 "hostgroups": [{"name": group}]},
        "metrics": [{"key": key, "units": units, "lastvalue": recent[-1]["value"],
                     "recent": recent}],
        "logs": logs or [],
        "security": security or [],
        "prejudge": prejudge,
    }


# 다양한 사건 유형 — 각기 다른 원인·조치·결론이 나와야 일반화 증명
SCENARIOS = [
    ("디스크 포화", "SEV2", _ctx(
        "Filesystem /data 사용률 93% on lab-app07",
        "last(/lab-app07/vfs.fs.size[/data,pused])>90", "vfs.fs.size[/data,pused]", "%",
        [{"clock": "1785400000", "value": "61"}, {"clock": "1785400600", "value": "78"},
         {"clock": "1785401200", "value": "93"}],
        {"verdict": "신규", "statement": "최근 90일 내 동일 트리거 발생 이력 없음 — 즉시 확인 권장."},
        logs=["2785401100 lab-app07 app: uploaded batch export 8.2GB to /data/tmp"])),

    ("서비스 다운", "SEV2", _ctx(
        "Process nginx is not running on lab-app07",
        "proc.num[nginx]=0", "proc.num[nginx]", "",
        [{"clock": "1785401000", "value": "4"}, {"clock": "1785401200", "value": "0"}],
        {"verdict": "재발", "statement": "최근 90일 내 동일 트리거 2회 발생(마지막 3.0일 전) — 간헐 재발. 이전 발생과의 공통점 확인 권장."},
        logs=["1785401180 lab-app07 kernel: nginx invoked oom-killer",
              "1785401185 lab-app07 systemd: nginx.service: Main process exited, killed by signal 9"])),

    ("보안 — 침해 정황", "SEV2", _ctx(
        "SSH authentication failures high on lab-app07",
        "sshd.failed>20", "sshd.failed", "",
        [{"clock": "1785401000", "value": "3"}, {"clock": "1785401200", "value": "47"}],
        {"verdict": "신규", "statement": "최근 90일 내 동일 트리거 발생 이력 없음 — 즉시 확인 권장."},
        logs=["1785401190 lab-app07 sshd: Failed password for invalid user admin from 198.51.100.44"],
        security=[{"level": 10, "desc": "SSH brute force (multiple failed logins)", "ts": "t1"},
                  {"level": 12, "desc": "Possible successful break-in after brute force", "ts": "t2"}])),

    ("네트워크 — 만성 노이즈", "SEV2", _ctx(
        "Interface Gi0/3 inbound errors on core-sw02",
        "change(/core-sw02/ifInErrors[Gi0/3])>2", "ifInErrors[Gi0/3]", "eps",
        [{"clock": "1785401000", "value": "2.1"}, {"clock": "1785401200", "value": "3.4"}],
        {"verdict": "만성", "statement": "최근 90일 내 동일 트리거 41회 발생(마지막 0.2일 전) — 알려진 반복 문제. 근본 원인 정비 대상이며 긴급도는 낮을 수 있음."},
        host="core-sw02", group="KINX NETWORK")),
]


async def main():
    print("경로:",
          "Claude" if os.environ.get("ANTHROPIC_API_KEY") else "열화(키 없음)",
          "/ Slack", "게시" if os.environ.get("SLACK_BOT_TOKEN") else "콘솔만")
    for label, sev, ctx in SCENARIOS:
        async def _fake(zbx, e, t, _c=ctx):
            return _c
        collector.collect_context = _fake
        ev = ctx["event"]
        print(f"\n{'='*70}\n▶ 시나리오: {label} ({sev})")
        result = await triage.run(ev["eventid"], "1", sev,
                                  host_display=ctx["host"]["host"], alert_name=ev["name"])
        t = result["timings"]
        print(f"  provider={result['provider']} degraded={result['degraded']} "
              f"total={t['total_s']}s (LLM {t['llm_s']}s) slack_ok={result['slack_ok']}")


if __name__ == "__main__":
    asyncio.run(main())
