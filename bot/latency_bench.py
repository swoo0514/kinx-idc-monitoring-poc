#!/usr/bin/env python3
"""데모 C(AI 초동 분석) LLM 응답시간 실측 스크립트.

Claude API(주 경로)와 Ollama(온프레 폴백)의 트리아지 응답 지연을 같은
프롬프트로 측정한다. 사용법·판정 기준·근거 문서는 bot/BENCH_GUIDE.md 참조.

크리덴셜은 환경변수(ANTHROPIC_API_KEY)로만 읽는다. 코드·출력에 남기지 않는다.
"""

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# 트리아지 프롬프트 (데모 C 실제 페이로드 모사 — 전부 가짜 랩 데이터)
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM = """\
당신은 KINX IDC 모니터링 트리아지 봇이다. Zabbix/Wazuh 알림이 오면
수집된 컨텍스트를 근거로 초동 분석을 한국어로 회신한다.

규칙:
- 만성/신규 판정은 이미 코드가 계산해서 준다. 그 값을 그대로 쓰고 재판정하지 않는다.
- 컨텍스트에 없는 사실을 지어내지 않는다. 모르면 "컨텍스트 부족"이라고 쓴다.
- 회신 형식(Slack 게시용):
  1) 한 줄 요약 (심각도 이모지 포함)
  2) 추정 원인 (근거 데이터 인용)
  3) 지금 즉시 실행할 확인 명령 3개 (복사-붙여넣기 가능한 형태)
  4) 권장 조치 (자동 조치 가능 여부 포함)
  5) 만성/신규 코멘트
- 전체 길이는 Slack 메시지 1개 분량(공백 포함 1500자 이내)으로 제한한다."""

TRIAGE_USER = """\
[알림]
- 소스: Zabbix (사내)
- 트리거: Filesystem /data 사용률 92% (임계 90%)
- 심각도: High
- 호스트: lab-web01 (호스트그룹: KINX WEB)
- 발생 시각: 2026-07-25 14:03:12 KST

[코드 선판정]
- 만성/신규: 신규 (최근 90일 동일 트리거 발화 0회)
- 동일 호스트 동시 활성 Problem: 1건 (이 알림뿐)

[최근 메트릭 (Zabbix API, 최근 1시간)]
- vfs.fs.size[/data,pused]: 61% -> 74% -> 85% -> 92% (15분 간격, 단조 증가)
- system.cpu.util: 12~18% (평상시 수준)
- vm.memory.utilization: 41% (평상시 수준)
- proc.num[java]: 1 (변화 없음)

[최근 로그 (Loki, host="lab-web01", 최근 30분 발췌)]
2026-07-25T13:41:02 lab-web01 app[2214]: INFO batch-export started job=daily-report
2026-07-25T13:41:05 lab-web01 app[2214]: INFO writing to /data/export/tmp
2026-07-25T13:52:18 lab-web01 kernel: EXT4-fs warning (device vdb1): ext4_dx_add_entry
2026-07-25T14:01:44 lab-web01 app[2214]: WARN export still running, elapsed=20m

[보안 이벤트 (Wazuh)]
- 해당 호스트 최근 1시간 레벨 7 이상 이벤트: 0건

[참고]
- 이 호스트의 /data 는 배치 리포트 출력 경로다.
- Ansible 자동 조치 플레이북 disk_cleanup.yml 이 등록되어 있다 (승인 필요).

위 컨텍스트로 초동 분석을 회신하라."""

# 스트리밍 미사용 시 SDK 타임아웃 안전 범위 + 트리아지 회신(1500자) 여유
DEFAULT_MAX_TOKENS = 2048


# ---------------------------------------------------------------------------
# Claude API (공식 anthropic SDK, 스트리밍)
# ---------------------------------------------------------------------------

def bench_claude(model, runs, max_tokens, thinking):
    try:
        import anthropic
    except ImportError:
        sys.exit("anthropic 패키지가 없습니다: pip install anthropic")

    client = anthropic.Anthropic()
    results = []
    for i in range(runs):
        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "system": TRIAGE_SYSTEM,
            "messages": [{"role": "user", "content": TRIAGE_USER}],
        }
        if thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        t0 = time.monotonic()
        ttft = None
        chars = 0
        with client.messages.stream(**kwargs) as stream:
            for text in stream.text_stream:
                if ttft is None and text:
                    ttft = time.monotonic() - t0
                chars += len(text)
            final = stream.get_final_message()
        total = time.monotonic() - t0
        r = {
            "provider": "claude",
            "model": model,
            "run": i + 1,
            "ttft_s": round(ttft, 2) if ttft else None,
            "total_s": round(total, 2),
            "output_tokens": final.usage.output_tokens,
            "output_chars": chars,
            "stop_reason": final.stop_reason,
        }
        results.append(r)
        print(f"  run {i+1}: TTFT {r['ttft_s']}s / 총 {r['total_s']}s "
              f"/ {r['output_tokens']} tokens / stop={r['stop_reason']}")
    return results


# ---------------------------------------------------------------------------
# Ollama (/api/chat 스트리밍, 표준 라이브러리만 사용)
# ---------------------------------------------------------------------------

def bench_ollama(base_url, model, runs, max_tokens):
    results = []
    for i in range(runs):
        payload = {
            "model": model,
            "stream": True,
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM},
                {"role": "user", "content": TRIAGE_USER},
            ],
            "options": {"num_predict": max_tokens},
        }
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        t0 = time.monotonic()
        ttft = None
        chars = 0
        final_chunk = {}
        try:
            with urllib.request.urlopen(req, timeout=1800) as resp:
                for line in resp:
                    chunk = json.loads(line)
                    content = chunk.get("message", {}).get("content", "")
                    if ttft is None and content:
                        ttft = time.monotonic() - t0
                    chars += len(content)
                    if chunk.get("done"):
                        final_chunk = chunk
        except urllib.error.URLError as e:
            sys.exit(f"Ollama 접속 실패 ({base_url}): {e}")
        total = time.monotonic() - t0
        eval_count = final_chunk.get("eval_count")
        eval_dur_s = (final_chunk.get("eval_duration") or 0) / 1e9
        r = {
            "provider": "ollama",
            "model": model,
            "run": i + 1,
            "ttft_s": round(ttft, 2) if ttft else None,
            "total_s": round(total, 2),
            "output_tokens": eval_count,
            "output_chars": chars,
            "load_s": round((final_chunk.get("load_duration") or 0) / 1e9, 2),
            "prompt_eval_s": round((final_chunk.get("prompt_eval_duration") or 0) / 1e9, 2),
            "tok_per_s": round(eval_count / eval_dur_s, 1) if eval_count and eval_dur_s else None,
        }
        results.append(r)
        print(f"  run {i+1}: TTFT {r['ttft_s']}s / 총 {r['total_s']}s "
              f"/ {r['output_tokens']} tokens / {r['tok_per_s']} tok/s "
              f"(모델로드 {r['load_s']}s)")
    return results


# ---------------------------------------------------------------------------
# 요약
# ---------------------------------------------------------------------------

def summarize(results, target_s):
    by_key = {}
    for r in results:
        by_key.setdefault((r["provider"], r["model"]), []).append(r)
    print("\n===== 요약 (목표: 총 응답 " + str(target_s) + "초 이내) =====")
    for (provider, model), rs in by_key.items():
        totals = [r["total_s"] for r in rs]
        ttfts = [r["ttft_s"] for r in rs if r["ttft_s"] is not None]
        med_total = statistics.median(totals)
        verdict = "통과" if max(totals) <= target_s else (
            "조건부" if med_total <= target_s else "초과")
        print(f"[{provider}:{model}] n={len(rs)}")
        print(f"  총 시간   중앙값 {med_total:.1f}s / 최소 {min(totals):.1f}s / 최대 {max(totals):.1f}s")
        if ttfts:
            print(f"  TTFT     중앙값 {statistics.median(ttfts):.1f}s")
        print(f"  판정: {verdict} (최대값 기준. 게이트웨이+컨텍스트 수집 오버헤드는 별도)")


def main():
    p = argparse.ArgumentParser(description="데모 C LLM 응답시간 실측")
    p.add_argument("--provider", choices=["claude", "ollama", "both"], default="claude")
    p.add_argument("--claude-model", default="claude-opus-4-8")
    p.add_argument("--ollama-model", default="qwen3:8b")
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    p.add_argument("--thinking", action="store_true",
                   help="Claude adaptive thinking 켜고 측정 (기본은 끔=최저지연)")
    p.add_argument("--target", type=float, default=30.0, help="목표 초 (기본 30)")
    p.add_argument("--json-out", help="원시 결과 JSON 저장 경로")
    args = p.parse_args()

    results = []
    if args.provider in ("claude", "both"):
        print(f"== Claude API: {args.claude_model} "
              f"(thinking={'adaptive' if args.thinking else 'off'}) ==")
        results += bench_claude(args.claude_model, args.runs, args.max_tokens, args.thinking)
    if args.provider in ("ollama", "both"):
        print(f"== Ollama: {args.ollama_model} @ {args.ollama_url} ==")
        results += bench_ollama(args.ollama_url, args.ollama_model, args.runs, args.max_tokens)

    summarize(results, args.target)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n원시 결과 저장: {args.json_out}")


if __name__ == "__main__":
    main()
