"""질의 계약 — 가르는 질의만 던지고, 중복은 코드가 막는다.

우리가 실측한 낭비가 "같은 지표를 네 번 조회하고 라운드를 소진"이었다(2026-08-20). FORGE
분류로는 RF-12(반복·정체)이고, 정답률을 15%p 이상 떨어뜨리는 넷 중 하나다. 그 낭비를 실제로
죽이는 것이 아래 지문 중복 검출이다.
"""

import hashlib
import json
import logging

log = logging.getLogger("gateway.deep.probe")


def catalog() -> set:
    """모델이 고를 수 있는 도구. 조회문은 코드가 만들고 모델은 목록에서 고르기만 한다."""
    from ..ask import tools as asktools

    names = {t.get("name") for t in (asktools.TOOL_SPECS or []) if t.get("name")}
    return {n for n in names if n != "answer"}


def fingerprint(req: dict) -> str:
    """같은 조회인지 가리는 지문.

    **가르려는 가설이 달라도 조회가 같으면 같은 질의다** — 이유만 바꿔 적으면 중복 검출을
    피할 수 있게 두면 안 된다. 인자는 정렬하고 공백을 떨어 순서·여백으로도 못 피하게 한다.
    """
    args = {}
    for k, v in sorted((req.get("args") or {}).items()):
        args[str(k).strip()] = v.strip() if isinstance(v, str) else v
    raw = json.dumps([str(req.get("tool") or "").strip(), args],
                     sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def validate(req: dict, table: list, seen: set):
    """이 질의를 던져도 되는가. 반환 `(통과, 사유)`."""
    tool = str(req.get("tool") or "").strip()
    if tool not in catalog():
        return False, "목록에 없는 도구다: %r" % tool

    ids = {h.get("id") for h in (table or [])}
    want = [str(x) for x in (req.get("discriminates") or [])]
    if not want:
        return False, "무엇을 가르는 질의인지 안 적었다"
    unknown = [x for x in want if x not in ids]
    if unknown:
        return False, "없는 가설을 가른다고 했다: %s" % ", ".join(unknown)

    if fingerprint(req) in (seen or set()):
        return False, "중복 질의다 — 같은 조회를 이미 했다"
    return True, ""


def splits(table: list, ids: list) -> bool:
    """선언한 가설들이 실제로 갈리는가 — 예상 결과가 같으면 가르는 질의가 아니다."""
    picked = [h for h in (table or []) if h.get("id") in set(ids or [])]
    if len(picked) < 2:
        return True          # 한 가설의 참·거짓을 가르는 것도 가르는 것이다
    seen = {(str(h.get("if_true") or "").strip(),
             str(h.get("if_false") or "").strip()) for h in picked}
    return len(seen) > 1


# 빈 결과가 몇 번 나오면 그 축을 접을까. 한 번은 창이 어긋났을 수 있으니 두 번으로 둔다.
DRY_LIMIT = 2


def dry_key(req: dict):
    """빈 결과를 세는 열쇠. **시간 창은 넣지 않는다.**

    중복 검출은 조회 인자까지 넣은 지문으로 도는데, 창만 바꾸면 지문이 달라져 빠져나간다.
    랩 실증 단계 3 에서 로그를 세 번 물었고 세 번 다 비었다 — 반복·정체 실패가 이 경로로
    재발했다. 없는 것은 창을 넓혀도 없다.
    """
    args = req.get("args") or {}
    return (str(req.get("tool") or ""), str(args.get("host") or ""))


def note_dry(state: dict, req: dict) -> None:
    """이 조회가 빈 결과였음을 센다."""
    k = dry_key(req)
    d = state.setdefault("dry", {})
    d[k] = int(d.get(k) or 0) + 1


def not_dry(state: dict, req: dict):
    """또 물어도 되는가. 반환 `(허용, 사유)`."""
    n = int((state.get("dry") or {}).get(dry_key(req)) or 0)
    if n >= DRY_LIMIT:
        return False, ("%s 는 이 대상에서 이미 %d번 비었다 — 창을 바꿔도 없다"
                       % (req.get("tool"), n))
    return True, ""
