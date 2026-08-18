import React from 'react';
import { PluginPage } from '@grafana/runtime';
import { AskChat } from '../components/AskChat';

// 패널에서 넘어오면 무엇을 보고 물었는지가 주소에 실려 온다. 그 값을 첫 질문에 미리
// 넣어 두면 사람이 "이 패널" 이 무엇인지 다시 설명하지 않아도 된다.
function prefillFromQuery(): string {
  const p = new URLSearchParams(window.location.search);
  const panel = p.get("panel");
  const from = p.get("from");
  const to = p.get("to");
  const dash = p.get("dash");
  if (!panel) {
    return "";
  }
  const host = p.get("host");
  const when = from && to ? ` (구간 ${from} ~ ${to})` : "";
  const where = dash ? ` 대시보드 "${dash}" 의` : "";
  // 대상 호스트를 따로 적어 준다. 제목 안에 묻어 두면 모델이 무엇이 대상인지
  // 다시 물어보느라 한 턴을 버린다.
  const who = host ? ` 대상 호스트는 ${host} 입니다.` : "";
  return `지금${where} "${panel}" 패널을 보고 있습니다${when}.${who} 이 구간에 무슨 일이 있었는지 확인해 주십시오.`;
}

export default function PageOne() {
  return (
    <PluginPage>
      <AskChat prefill={prefillFromQuery()} />
    </PluginPage>
  );
}
