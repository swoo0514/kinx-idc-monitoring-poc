"""질의 경로의 설정값과 고정 문구. 한 곳에 모아 두 곳에서 어긋나지 않게 한다."""

import logging
import os

log = logging.getLogger("gateway.ask")


# 질의가 닿을 수 있는 감시 영역. 기본은 사내뿐이다. 넓히려면 환경변수로 적는다.
DEFAULT_ALLOWED_REALMS = "internal"


# 한 번에 받을 질문 길이. 이력까지 매 턴 다시 마스킹하므로 무한정 받을 수 없다.
QUESTION_MAX_CHARS = 500


# 세션 역치환 표를 얼마나 들고 있을지. 날아가도 사용자가 다시 물으면 되므로 짧게 잡는다.
SESSION_TTL_S = 1800


# 사람이 이름을 줄여 말할 때 쓰는 조각. 너무 짧으면 아무 데나 걸리므로 하한을 둔다.
MENTION_MIN = 4


# 대상 표 캐시 — 시한을 짧게 둔다. 낡으면 없는 호스트를 있다고 답한다. 실패는 캐시하지 않는다
TABLE_TTL_S = float(os.environ.get("ASK_TABLE_TTL_S", "60"))


# 도구 루프 — 상한이 셋이다(라운드 수·전체 시간·도구 결과 글자 수).
# 어디에 닿든 오류가 아니라 거기까지 본 것으로 답하게 한다.

# 대화 이력을 얼마나 실을지 — 오래된 것부터 버리는 미끄럼창
HISTORY_MAX_MSGS = int(os.environ.get("ASK_HISTORY_MAX_MSGS", "12"))


HISTORY_MAX_CHARS = int(os.environ.get("ASK_HISTORY_MAX_CHARS", "8000"))


DROP_NOTE = "(앞선 대화 일부는 길이 때문에 생략되었다. 필요하면 다시 물어라)"


# 상한에 닿았을 때 마지막으로 붙이는 말 — 조회는 막고 본 것으로만 답하게 한다
# 예열 호출의 상한(초). 사람이 안 기다리므로 넉넉히 둔다
PREWARM_TIMEOUT_S = float(os.environ.get("ASK_PREWARM_TIMEOUT_S", "180"))


CAP_NOTE = ("조회 상한에 닿았다. 더 조회할 수 없다. 지금까지 확인한 것만으로 answer 를 "
            "불러 답하라. 확인하지 못한 것은 확인하지 못했다고 쓴다.")


MAX_ROUNDS = int(os.environ.get("ASK_MAX_ROUNDS", "6"))


DEADLINE_S = float(os.environ.get("ASK_DEADLINE_S", "60"))


RESULT_BYTES = int(os.environ.get("ASK_RESULT_BYTES", "60000"))


ASK_SYSTEM = """\
당신은 KINX IDC 관제 담당자의 질문에 답하는 조회 도우미다. 도구로 지표·로그·보안
기록을 읽고 한국어로 답한다.

규칙:
- 호스트는 [host-...] 같은 가명 토큰으로만 지칭한다. 실명을 지어내지 마라.
- **범위를 지킨다.** 너는 이 회사의 관측 데이터(지표·로그·보안 기록)에 대해서만
  답한다. 관측과 무관한 질문(일반 지식·잡담·다른 주제)에는 답하지 말고, 무엇을 물어야
  하는지 한 문장으로 알려 준 뒤 끝내라. 길게 사양하지 마라.
- **그림은 도움이 될 때만 붙인다.** panel_image 는 사람이 보고 있는 화면을 답과 함께
  보여 줄 때, 또는 추이·모양을 말로 설명하기 어려울 때 한 번만 부른다. 같은 대화에서
  이미 붙였으면 다시 붙이지 마라. "없다"·"정상이다" 만 말하는 답에는 붙이지 마라.
- **사람이 보고 있는 패널에 대해 물었는데 조회가 비었으면, 사람에게 화면을 확인하라고
  미루지 말고 네가 panel_image 로 그 패널을 먼저 봐라.** 화면에는 값이 있는데 다른 축을
  조회해 비었을 수 있다.
- **로그에서 여러 낱말 중 하나를 찾을 때는 contains 에 `failed|invalid user` 처럼
  세로줄로 이어라.** 다섯 개까지 된다.
- **답은 answer 도구로 낸다.** 조사가 끝나면 산문으로 쓰지 말고 answer 를 불러라.
  `summary` 에 결론, `findings` 에 조회로 확인한 근거, `window_utc` 에는 도구가 돌려준
  구간을 그대로 옮기고, 그림을 붙였으면 `image_ids` 에 panel_image 가 준 id 를 적는다.
  조회를 안 했으면 `window_utc` 는 비운다. 지어내면 거부되고 다시 물어야 한다.
- 대상 토큰을 모르면 list_hosts 를 먼저 부른다.
- **사람이 절대 시각을 말하면 window_m 이 아니라 from·to 로 넘겨라.** "8월 13일 12시",
  "어제 새벽" 처럼 특정 시점을 가리키는 질문에 상대 창을 쓰면 엉뚱한 날을 보게 된다.
- **도구 결과의 status 를 반드시 읽어라.** "ok" 일 때만 빈 결과를 "없었다"로 해석한다.
  "unavailable" 은 조회가 실패한 것이고 "disabled" 는 그 축이 없는 것이다. 둘 다
  "없었다"가 아니므로 그렇게 밝혀라.
- 도구가 error 를 돌려주면 그 지시를 읽고 고쳐서 다시 부른다.
- 근거로 쓴 조회를 답에 밝힌다. 확인하지 못한 것은 확인하지 못했다고 쓴다.
- 되돌릴 수 없는 명령(RESET SLAVE·DROP·rm -rf·kill -9 등)을 권하지 마라.
- 답은 공백 포함 1200자 이내로 쓴다."""


# 관측 지식 조각. 경로는 이 파일 기준 — gateway/ask/config.py → gateway/ask → gateway → bot
_BOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FACTS_FILE = os.environ.get("ASK_FACTS_FILE",
                            os.path.join(_BOT_DIR, "ask_facts.yml"))


# 조회가 한 건도 성공하지 않았을 때 답에 붙이는 말. 사람이 화면에서 보는 문장이다.
NO_EVIDENCE = ("※ 이 답은 조회가 한 건도 성공하지 않은 상태에서 작성됐다. "
               "없다는 뜻이 아니라 확인하지 못했다는 뜻이다.")


# 사용자별 사용량 — 신원은 Grafana 가 붙이는 X-Grafana-User 로 들어온다.
# 그 헤더는 게이트웨이 포트를 Grafana 만 접근하도록 막았을 때만 믿을 수 있다.

ANON = "(미상)"


USER_MAX_CHARS = 64


MAX_PER_USER_HOUR = int(os.environ.get("ASK_MAX_PER_USER_HOUR", "60"))


# 패널 목록 캐시. 대시보드는 자주 안 바뀌는데 턴마다 Grafana 를 다시 훑었다.
PANELS_TTL_S = float(os.environ.get("ASK_PANELS_TTL_S", "60"))
