"""질의 반복문 — 모델이 고르고 코드가 실행한다(§27-1).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import time
import json as _json
from .. import masking, proxy
from . import config

from .config import (CAP_NOTE, DEADLINE_S, DROP_NOTE, MAX_ROUNDS, PREWARM_TIMEOUT_S, RESULT_BYTES)
from .answer import (_blocks_text, chosen_images, render_answer, stall_note, strip_handles, system_prompt, with_evidence_note)
from .hygiene import sanitize_question, trim_history
from .session import cancelled, remember, session_key, session_masker
from .table import _alias, resolve_mentions
from .fetch.judgments import fetch_judgments
from .fetch.loki import fetch_logs
from .fetch.panels import fetch_panel, fetch_panel_list
from .fetch.wazuh import fetch_security
from .fetch.zabbix import fetch_metrics
log = logging.getLogger("gateway.ask")


def _pkg():
    """이 패키지 자신. 밖에서 갈아 끼운 이름을 **부를 때** 읽으려고 쓴다.

    파일 맨 위에서 이름을 가져오면 그 순간의 값이 굳는다. 검사와 운영 도구가
    `ask.fetch_problems = ...` 처럼 바꿔 끼우므로, 부르는 시점에 패키지에서 읽어야
    그 교체가 반영된다.
    """
    import sys

    return sys.modules[__package__]


async def run_ask(question: str, history=None, sid: str = "", table: dict = None,
                  model_fn=None, clock=None, now: int = None, user: str = "",
                  panel_fn=None, panel: dict = None) -> dict:
    """질문 하나에 답한다. 어떤 실패도 예외로 던지지 않는다.

    반환 `{"text", "trace", "rounds", "stopped", "error"}`.
    """
    import asyncio
    import json as _json

    from .. import asktools, egress, llm
    tick = clock or time.monotonic
    started = tick()
    now = int(time.time()) if now is None else now
    mk = session_masker(sid or "-")

    # **표를 먼저 만든다.** 표를 만들면서 호스트 이름이 마스커에 등록되므로, 그 뒤에
    # 질문을 가려야 표에만 있고 이름 표에는 없는 호스트가 질문에서 안 새어 나간다.
    # 반대 순서로 뒀다가 랩에서 실제로 실명이 나갔다(2026-08-18).
    if table is None:
        # **패키지에서 읽는다.** 밖에서 갈아 끼운 것이 여기서도 보여야 한다.
        from . import build_table as _build_table
        table = await _build_table(mk)
    else:
        for ent in table.values():
            mk.register("host", ent.get("host", ""))
            _alias(mk, ent.get("host", ""), ent.get("logs", ""), ent.get("security", ""))
    if not table:
        return {"text": "", "trace": [], "rounds": 0, "images": [], "stopped": "no_targets",
                "error": "조회할 수 있는 대상이 없다. 감시 서버 연결과 허용 영역을 확인하라"}

    # 이름 조각을 먼저 토큰으로 바꾼다. 마스커는 등록된 이름만 보므로 줄여 쓴 말을
    # 못 잡는다. 여기서 풀어 두면 모델이 곧바로 도구를 부를 수 있다.
    question = resolve_mentions(question, table)
    clean = sanitize_question(question, mk)
    if not clean["ok"]:
        return {"text": "", "trace": [], "rounds": 0, "images": [], "stopped": "rejected",
                "error": clean["reason"]}

    # 세션 열쇠에 신원을 넣는다. 화면이 보내는 이름만으로는 사람이 안 나뉜다.
    sid = session_key(sid, user)

    # 사람이 보던 구간. 화면이 넘겨 주므로 모델에게 받아 적으라고 시키지 않는다.
    panel_span = None
    pf = asktools.parse_when((panel or {}).get("from"))
    pt = asktools.parse_when((panel or {}).get("to"))
    if pf is not None and pt is not None and pf < pt:
        panel_span = (pf, pt)
    # 화면에서 열지 않고 질문 글만 붙여 넣는 일이 잦다. 그러면 패널 맥락이 아예 안 오고
    # 도구는 최근 창을 본다. 사람이 글에 적어 놓은 구간을 읽어 쓴다(지어내지 않는다).
    if panel_span is None:
        panel_span = asktools.span_in_text(clean["text"])

    ctx = {
        "table": table, "now": now, "panel_span": panel_span,
        "fetch_logs": lambda q, a, b, lim: fetch_logs(q, a, b, lim, mk),
        "fetch_security": lambda body: fetch_security(body, mk),
        "fetch_judgments": lambda host, days: fetch_judgments(host, days, mk),
        "fetch_metrics": lambda ent, match, a, b: fetch_metrics(ent, match, a, b, mk),
        # **패키지에서 읽는다.** 밖에서 갈아 끼운 것이 여기서도 보여야 한다.
        "fetch_problems": lambda ent: _pkg().fetch_problems(ent, mk),
        # 패널 손잡이는 이번 턴 안에서만 뜻이 있다. 모델은 pnl-3 만 보고 대시보드
        # 식별자는 서버가 들고 있는다.
        "panel_refs": {},
        "fetch_panel": (panel_fn or (
            lambda ent, target, a, b: fetch_panel(ent, target, a, b, panel))),
        "list_panels": (lambda dash: fetch_panel_list(dash, mk)),
    }

    images = []          # 화면이 그릴 그림. 모델에는 손잡이만 준다.
    # 사람이 보고 있던 패널은 **맥락으로만** 알려 준다. 무조건 붙이면 이어지는
    # 질문마다 같은 그림이 다시 그려진다. 붙일지는 모델이 정하고, 판단 기준은 지시문에
    # 적었다.
    # **지금이 언제인지 알려 준다.** 사람은 "어제 오후 3시" 처럼 상대 시각으로 말하는데,
    # 모델이 오늘 날짜를 모르면 조회를 못 하고 되묻는다(2026-08-19 랩 실측). 서버 시각을
    # 주면 모델이 계산해서 range 로 넘긴다.
    viewing = "[지금] %s UTC%s" % (asktools.window_label(now, now).split(" → ")[0],
                                   chr(10))
    if panel and panel.get("uid"):
        span = ""
        if panel_span:
            span = " 조회 구간은 %s 이며 도구가 기본으로 그 구간을 본다." % (
                asktools.window_label(*panel_span))
        viewing += ("[사람이 보고 있는 패널] %s — 이 화면을 그림으로 붙이려면 "
                    "panel_image 를 부르면 된다.%s" + chr(10)
                    ) % (mk.mask(str(panel.get("title") or "제목 없음")), span)

    hist, dropped = trim_history(history)
    # **이력도 가린다.** 화면은 사람이 읽는 글(실명으로 되돌린 것)을 이력으로
    # 되보낸다. 그대로 실으면 앞 턴의 실명이 모델에 가고, 모델은 그 이름을 도구
    # 인자로 쓴다(2026-08-18 실측).
    messages = [{"role": m["role"], "content": mk.mask(m["content"])} for m in hist]
    if dropped:
        messages.insert(0, {"role": "user", "content": DROP_NOTE})
    messages.append({"role": "user", "content": viewing + clean["text"]})
    trace, spent, stopped = [], 0, "end_turn"
    # 같은 조회를 두 번 하지 않는다. 라운드와 비용을 태우고, 결과가 같으므로 얻는 것도 없다.
    called = {}
    text = ""
    # 이번 요청의 도구 정의. 대상 토큰이 스키마에 박히므로 표 밖의 이름은 표현할 수 없다.
    specs = asktools.build_tool_specs(table)
    # 답 도구가 참조할 수 있는 값. 턴 중에 생기므로 스키마가 아니라 코드가 지킨다.
    made_images, seen_windows, final = set(), set(), {}
    # 성공한 조회 수. 답이 근거 없이 "없다" 로 닫히는 것을 막는 데 쓴다.
    ok_queries = {"n": 0}

    async def _exec_query(name, args, seen, idx):
        """조회 도구 한 번. 반환 `(화면에 붙일 그림, 모델에 줄 결과, 직렬화한 글자)`.

        **두 엔진이 이 함수를 함께 쓴다.** 중복 차단·그림 분리·마스킹이 한 곳에 있어야
        엔진을 갈아 끼울 때 한쪽만 빠지지 않는다.
        """
        key = _json.dumps([name, args], ensure_ascii=False, sort_keys=True)
        if key in seen:
            out = {"error": "이미 같은 조회를 했다. 그 결과를 쓰고 다음으로 넘어가라",
                   "previous_round": seen[key]}
        else:
            seen[key] = idx
            out = await asktools.run_tool(name, args, ctx)
        image = None
        if isinstance(out, dict) and out.get("url"):
            # **주소는 모델에 주지 않는다.** 대시보드 식별자와 호스트 실명이 들어 있다.
            # 같은 패널을 두 번 찾아오면 그림은 한 장만 붙인다. 두 번 붙이면 상태 검사가
            # 이상으로 보고 답이 통째로 버려진다(2026-08-18 실측: invalid_state).
            image = None if out.get("id") in made_images else out
            made_images.add(out.get("id"))
            out = {"image": out.get("id"), "title": mk.mask(out.get("title", "")),
                   "note": "화면에 붙였다. answer 의 image_ids 에 이 id 를 적어라"}
        if isinstance(out, dict) and out.get("window_utc"):
            seen_windows.add(out["window_utc"])
        if isinstance(out, dict) and not out.get("error"):
            ok_queries["n"] += 1
        return image, out, _json.dumps(out, ensure_ascii=False)

    async def exec_tool(name, args, seen, idx):
        """도구 하나. 답 도구는 조회가 아니라 마무리라서 따로 본다."""
        if name == "answer":
            ok, why = asktools.check_answer(args, made_images, seen_windows)
            if not ok:
                return None, {"error": why}, _json.dumps({"error": why}, ensure_ascii=False)
            final.update(args or {})
            out = {"ok": True, "note": "답을 받았다. 더 부르지 마라"}
            return None, out, _json.dumps(out, ensure_ascii=False)
        return await _exec_query(name, args, seen, idx)

    # 엔진 모듈은 여기서 들여온다. 서로를 부르므로 파일 맨 위에서 들여오면 순환이 된다.
    from .engine import _run_graph, engine_name

    if engine_name() == "graph":
        return await _run_graph(
            system_prompt(), messages, mk, sid, user, exec_tool, model_fn,
            started, tick, specs, final, made_images, ok_queries)

    def _model(msgs):
        if model_fn is not None:
            return model_fn(system_prompt(), msgs, specs)
        return llm.claude_tools(system_prompt(), msgs, specs)

    for _round in range(MAX_ROUNDS + 1):
        # 답 도구는 조회가 아니라 마무리라 상한에 세지 않는다. 두 엔진이 같은 셈법을 쓴다.
        if asktools.query_count(trace) >= MAX_ROUNDS:
            stopped = "rounds"
            break
        if tick() - started > DEADLINE_S:
            stopped = "deadline"
            break
        if cancelled(sid, started):
            stopped = "cancelled"
            break
        res = await asyncio.to_thread(egress.call_raw, lambda: _model(messages),
                                      kind="ask", user=user)
        if not res["ok"]:
            return {"text": "", "trace": trace, "rounds": len(trace), "images": images,
                    "stopped": "llm_failed",
                    "error": "모델을 부르지 못했다: %s" % res["reason"]}
        reply = res["value"]
        # **실제로 쓴 토큰으로 센다.** 추정하지 않고 응답에 실려 온 값을 남긴다.
        u = reply.get("usage") or {}
        if u:
            from .. import store
            store.record_tokens(
                    "ask", user, u.get("input_tokens"), u.get("output_tokens"),
                    cache_write=u.get("cache_creation_input_tokens") or 0,
                    cache_read=u.get("cache_read_input_tokens") or 0,
                    model=reply.get("model") or "")
        text = _blocks_text(reply.get("content")) or text
        uses = [b for b in (reply.get("content") or [])
                if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not uses:
            break
        messages = messages + [{"role": "assistant", "content": reply["content"]}]
        results = []
        for u in uses:
            # 모델이 준 인자는 토큰 상태 그대로 쓴다. 도구가 표에서 실명을 찾는다.
            image, out, blob = await exec_tool(u.get("name", ""), u.get("input") or {},
                                               called, len(trace) + 1)
            if image:
                images.append(image)
            spent += len(blob)
            if spent > RESULT_BYTES:
                out = {"error": "조회 결과가 예산을 넘어 더 못 본다. 지금까지 본 것으로 답하라"}
                blob = _json.dumps(out, ensure_ascii=False)
                stopped = "budget"
            trace.append({"tool": u.get("name", ""), "args": u.get("input") or {},
                          "error": out.get("error", ""), "bytes": len(blob)})
            results.append({"type": "tool_result", "tool_use_id": u.get("id"),
                            "content": blob})
        messages = messages + [{"role": "user", "content": results}]
        if final:
            text = render_answer(final, int((ok_queries or {}).get("n", 1)) > 0)
            break
        if stopped == "budget":
            break
    else:
        stopped = "rounds"

    # **상한에 닿았어도 답은 준다.** 조회한 것이 있는데 마무리를 안 하면 사람에게
    # 가는 글이 모델의 중간 생각이 된다.
    if stopped in ("rounds", "deadline", "budget") and not final and trace:
        if await force_answer(system_prompt(), messages, specs, user,
                              model_fn, exec_tool, trace):
            text = render_answer(final, int((ok_queries or {}).get("n", 1)) > 0)
    if stopped in ("rounds", "deadline", "budget", "cancelled", "invalid_state") and not final:
        text = (stall_note(stopped, trace)
                + ((chr(10) * 2 + text) if text else ""))
    text = with_evidence_note(text, trace, ok_queries["n"])
    remember(sid or "-", mk)
    return {"text": strip_handles(mk.unmask(text)), "trace": trace,
            "rounds": len(trace),
            "images": chosen_images(images, final), "stopped": stopped, "error": ""}


def prewarm() -> str:
    """기동 뒤 첫 질의가 느린 것을 미리 치른다. 반환은 사람이 읽을 결과 한 줄.

    2026-08-18 랩 실측으로 재기동 직후 첫 호출이 96초, 다음 호출은 6초였다. 접두사
    캐시가 비어 있고 연결도 처음이라 그렇다. 사람이 기다릴 시간이 아니므로 기동 때
    작은 호출로 대신 치른다.

    실패해도 조용히 넘어간다. 예열이 안 되면 첫 질의가 느릴 뿐이고, 기동을 막을 일은
    아니다.
    """
    import asyncio

    from .. import asktools, egress, llm
    try:
        from . import build_table as _build_table
        table = asyncio.run(_build_table(proxy.build_masker()))
        if not table:
            return "대상 표가 비어 예열을 건너뛴다"
        specs = asktools.build_tool_specs(table)
        last = ""
        # 한 번 실패했다고 그만두면 예열이 안 된 채로 사람이 첫 질의를 받는다. 배경에서
        # 도는 일이라 한 번 더 해도 사람이 기다리지 않는다.
        for _try in range(2):
            # **같은 출구를 지난다.** 여기만 빠지면 기동 때마다 동시 수·시간당 상한·
            # 토큰 계수 밖에서 도는 호출이 생긴다(2026-08-19 감사).
            res = egress.call_raw(
                lambda: llm.claude_tools(system_prompt(),
                                         [{"role": "user", "content": "준비"}], specs,
                                         timeout_s=PREWARM_TIMEOUT_S),
                kind="ask", user="(예열)")
            if res["ok"]:
                return "질의 예열 완료 (대상 %d개)" % len(table)
            last = res["reason"]
        return "질의 예열 실패: %s" % last
    except Exception as e:
        return "질의 예열 실패: %s" % e


def drop_dangling(msgs: list) -> list:
    """결과가 안 붙은 도구 요청을 끝에서 걷어 낸다.

    상한에 걸려 멈추면 마지막 남는 것이 **모델이 부르려던 도구 요청**이다. 그 요청은
    실행되지 않았으므로 결과 블록이 없고, 그대로 다시 보내면 Anthropic 이 400 으로
    거부한다(2026-08-18 랩 실측: `tool_use ids were found without tool_result blocks`).
    그러면 마무리 호출이 통째로 실패해 사람은 또 답을 못 받는다.
    """
    out = list(msgs or [])
    while out:
        m = out[-1]
        blocks = m.get("content")
        if m.get("role") != "assistant" or not isinstance(blocks, list):
            break
        if not any(isinstance(b, dict) and b.get("type") == "tool_use" for b in blocks):
            break
        out.pop()
    return out


async def force_answer(system: str, msgs: list, specs: list, user: str,
                       model_fn, exec_tool, trace: list) -> bool:
    """상한에 닿았으면 **한 번만 더** 불러 답을 받는다. 반환은 답을 받았는가.

    안 하면 사람이 받는 글이 모델의 중간 생각이다. 2026-08-18 랩 실측으로 라운드를 다
    쓴 질의의 회신이 "레벨을 더 낮춰서 전체 보안 이벤트를 확인하겠습니다." 한 줄이었다.
    조회는 열 번 했는데 그 결과가 사람에게 하나도 안 갔다.

    이 호출에는 **answer 도구만 준다.** 조회 도구를 남겨 두면 모델이 상한을 넘겨 또
    조회하려 든다.
    """
    import asyncio

    from .. import egress, llm
    only = [t for t in (specs or []) if t.get("name") == "answer"]
    if not only:
        return False
    last = drop_dangling(msgs) + [{"role": "user", "content": CAP_NOTE}]

    def _model():
        if model_fn is not None:
            return model_fn(system, last, only)
        return llm.claude_tools(system, last, only)

    res = await asyncio.to_thread(egress.call_raw, _model, kind="ask", user=user)
    if not res["ok"]:
        log.warning("마무리 호출 실패: %s", res["reason"])
        return False
    reply = res["value"]
    for b in (reply.get("content") or []):
        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "answer":
            _img, out, blob = await exec_tool("answer", b.get("input") or {},
                                              {}, len(trace) + 1)
            trace.append({"tool": "answer", "args": b.get("input") or {},
                          "error": out.get("error", ""), "bytes": len(blob)})
            return not out.get("error")
    return False
