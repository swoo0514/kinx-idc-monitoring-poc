import React, { useState } from 'react';
import { Button, TextArea, Alert } from '@grafana/ui';
import { PluginPage, getBackendSrv } from '@grafana/runtime';

// 게이트웨이로 가는 길. 토큰은 Grafana 가 서버 쪽에서 헤더에 넣으므로 여기에는 없다.
const GATEWAY = '/api/datasources/proxy/uid/askgw/gw';

function PageOne() {
  const [out, setOut] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const check = async () => {
    setBusy(true);
    setErr('');
    try {
      const res = await getBackendSrv().get(`${GATEWAY}/healthz`);
      setOut(JSON.stringify(res, null, 2));
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PluginPage>
      <div>
        <p>게이트웨이 연결 확인</p>
        <Button onClick={check} disabled={busy}>
          {busy ? '확인 중' : '상태 조회'}
        </Button>
        {err && <Alert title="조회 실패">{err}</Alert>}
        {out && <TextArea rows={8} value={out} readOnly />}
      </div>
    </PluginPage>
  );
}

export default PageOne;
