"""데모 C 오프라인 리허설 — 랩 Zabbix 없이 트리아지 전 구간을 실제로 관통."""

import os
import sys

# `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 에 있으므로 부모다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import os

from gateway.alerts import collector, triage

_FAKE_CONTEXT = {
    "event": {"eventid": "10583", "name": "Filesystem /data 사용률 92% on lab-web01",
              "clock": "1753500000"},
    "trigger": {"description": "디스크 사용률 임계 초과",
                "expression": "last(/lab-web01/vfs.fs.size[/data,pused])>90"},
    "host": {"host": "lab-web01", "name": "lab-web01",
             "interfaces": [{"ip": "192.0.2.5", "dns": ""}],
             "hostgroups": [{"name": "KINX WEB"}]},
    "metrics": [{"key": "vfs.fs.size[/data,pused]", "units": "%", "lastvalue": "92.3",
                 "recent": [{"clock": "1753496400", "value": "61.2"},
                            {"clock": "1753497300", "value": "74.0"},
                            {"clock": "1753498200", "value": "85.1"},
                            {"clock": "1753500000", "value": "92.3"}]}],
    "prejudge": {"verdict": "신규",
                 "statement": "최근 90일 내 동일 트리거 발생 이력 없음 — 처음 보는 문제이므로 즉시 확인 권장."},
}


async def _fake_collect(zbx, event_id, trigger_id):
    return _FAKE_CONTEXT


async def main():
    collector.collect_context = _fake_collect  # 랩 Zabbix 대체(실 API는 랩 통합 때)
    print("경로:",
          "Claude" if os.environ.get("ANTHROPIC_API_KEY") else "열화(키 없음)",
          "/ Slack", "게시" if os.environ.get("SLACK_BOT_TOKEN") else "건너뜀")
    result = await triage.run("10583", "22001", "SEV2",
                              host_display="lab-web01",
                              alert_name="Filesystem /data 사용률 92%")
    print("\n결과:", result)
    t = result["timings"]["total_s"]
    print(f"\n{'✅ 30초 이내' if t < 30 else '⚠️ 30초 초과'} — "
          f"총 {t}s (수집 {result['timings']['collect_s']}s / "
          f"LLM {result['timings']['llm_s']}s / Slack {result['timings']['slack_s']}s), "
          f"provider={result['provider']}, slack_ok={result['slack_ok']}")


if __name__ == "__main__":
    asyncio.run(main())
