import React, { useState } from 'react';
import { Button, TextArea, Alert, Drawer } from '@grafana/ui';
import { getBackendSrv } from '@grafana/runtime';

const GATEWAY = '/api/datasources/proxy/uid/askgw/gw';

// 패널 메뉴에서 넘어오는 맥락. 무엇을 보고 물었는지를 첫 질문에 싣는다.
export type PanelContext = { pluginId?: string; panelId?: number; timeRange?: any };

export function AskBody({ onDismiss, context }: { onDismiss: () => void; context?: PanelContext }) {
  const [q, setQ] = useState('');
  const [ans, setAns] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const ask = async () => {
    setBusy(true);
    setErr('');
    try {
      const res: any = await getBackendSrv().get(`${GATEWAY}/healthz`);
      setAns(
        '질의 경로는 아직 연결 전입니다. 지금은 게이트웨이 상태만 확인합니다.\n\n' +
          JSON.stringify(res, null, 2) +
          (context ? `\n\n[화면 맥락] 패널 ${context.panelId ?? '-'}` : '')
      );
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Drawer title="관제 질의" size="md" onClose={onDismiss}>
      <TextArea
        rows={3}
        placeholder="예: 이 호스트가 지금 왜 느린가"
        value={q}
        onChange={(e) => setQ(e.currentTarget.value)}
      />
      <Button onClick={ask} disabled={busy} style={{ marginTop: 8 }}>
        {busy ? '묻는 중' : '묻기'}
      </Button>
      {err && <Alert title="실패">{err}</Alert>}
      {ans && <TextArea rows={12} value={ans} readOnly style={{ marginTop: 12 }} />}
    </Drawer>
  );
}
