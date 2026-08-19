"""심각도 정규화 — docs/02-design/severity-normalization.md의 코드 구현. 표 개정 시 문서 먼저."""

SEV1 = "SEV1"
SEV2 = "SEV2"
SEV3 = "SEV3"
SEV4 = "SEV4"
NONE = "NONE"

SOURCE_ZABBIX_INTERNAL = "zabbix-internal"
SOURCE_ZABBIX_MSP = "zabbix-msp"
SOURCE_WAZUH = "wazuh"

# 사내 Warning(2)→SEV4 / MSP Warning(2)→SEV3 비대칭이 핵심 — 근거는 위 문서
_ZABBIX_INTERNAL = {5: SEV1, 4: SEV2, 3: SEV3, 2: SEV4, 1: SEV4, 0: NONE}
_ZABBIX_MSP = {5: SEV1, 4: SEV2, 3: SEV3, 2: SEV3, 1: SEV4, 0: NONE}


def _wazuh(level: int) -> str:
    # 10~11=SEV2 로 팀 현행 컷라인(레벨 10+ = Slack) 보존
    if level >= 14:
        return SEV1
    if level >= 10:
        return SEV2
    if level >= 7:
        return SEV3
    if level >= 3:
        return SEV4
    return NONE


def normalize(source: str, level: int) -> str:
    """(소스, 원본 심각도) → SEV. 미지 입력은 SEV2 페일세이프(놓치기보다 시끄러운 쪽)."""
    try:
        level = int(level)
    except (TypeError, ValueError):
        return SEV2
    if source == SOURCE_ZABBIX_INTERNAL:
        return _ZABBIX_INTERNAL.get(level, SEV2)
    if source == SOURCE_ZABBIX_MSP:
        return _ZABBIX_MSP.get(level, SEV2)
    if source == SOURCE_WAZUH:
        if 0 <= level <= 15:
            return _wazuh(level)
        return SEV2
    return SEV2


def notifies(sev: str) -> bool:
    """Slack 통보 대상 여부. SEV1+SEV2 = Wazuh 레벨 10+ (팀 현행 정책)."""
    return sev in (SEV1, SEV2)
