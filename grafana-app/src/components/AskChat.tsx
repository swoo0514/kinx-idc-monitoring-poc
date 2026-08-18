import React, { useEffect, useRef, useState } from 'react';
import { Button, TextArea, Alert, Spinner, Icon, useStyles2 } from '@grafana/ui';
import { getBackendSrv } from '@grafana/runtime';
import { GrafanaTheme2, renderMarkdown } from '@grafana/data';
import { css } from '@emotion/css';

const GATEWAY = '/api/datasources/proxy/uid/askgw/gw';

type Turn = { role: 'user' | 'assistant'; text: string; trace?: any[] };

export function AskChat({ prefill, compact }: { prefill?: string; compact?: boolean }) {
  const s = useStyles2(getStyles);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [q, setQ] = useState(prefill || '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [turns, busy]);

  const send = async () => {
    const text = q.trim();
    if (!text || busy) {
      return;
    }
    setQ('');
    setErr('');
    setTurns((t) => [...t, { role: 'user', text }]);
    setBusy(true);
    try {
      const res: any = await getBackendSrv().post(`${GATEWAY}/ask`, { question: text });
      if (res?.error) {
        setErr(res.error);
      }
      setTurns((t) => [
        ...t,
        { role: 'assistant', text: res?.text || '(답이 비어 있습니다)', trace: res?.trace },
      ]);
    } catch (e: any) {
      setErr(String(e?.data?.error || e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={compact ? s.wrapCompact : s.wrap}>
      <div className={s.stream}>
        {turns.length === 0 && (
          <div className={s.hint}>
            <img src="public/plugins/kinxidc-ask-app/img/logo.png" alt="" className={s.hintLogo} />
            <p className={s.hintTitle}>관측 데이터를 자연어로 물어보십시오.</p>
            <p className={s.dim}>예: 어느 호스트에 최근 오류 로그가 있나</p>
            <p className={s.dim}>예: vm-a 의 복제 지연을 최근 3일로 확인해줘</p>
          </div>
        )}
        {turns.map((t, i) => (
          <div key={i} className={t.role === 'user' ? s.userRow : s.botRow}>
            {t.role === 'assistant' && (
              <img src="public/plugins/kinxidc-ask-app/img/logo.png" alt="" className={s.avatar} />
            )}
            <div className={t.role === 'user' ? s.userBubble : s.botBubble}>
              {t.role === 'assistant' ? (
                <div
                  className={s.md}
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(t.text) }}
                />
              ) : (
                <div className={s.plain}>{t.text}</div>
              )}
              {t.trace && t.trace.length > 0 && (
                <div className={s.trace}>
                  {t.trace.map((x: any, j: number) => (
                    <span key={j} className={s.chip}>
                      <Icon name={x.error ? 'exclamation-triangle' : 'search'} size="xs" /> {x.tool}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {busy && (
          <div className={s.botRow}>
            <img src="public/plugins/kinxidc-ask-app/img/logo.png" alt="" className={s.avatar} />
            <div className={s.botBubble}>
              <Spinner inline /> 조회하고 있습니다. 도구를 여러 번 부를 수 있어 최대 1분이 걸립니다.
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>
      {err && (
        <Alert title="실패" severity="error">
          {err}
        </Alert>
      )}
      <div className={s.composer}>
        <TextArea
          rows={compact ? 2 : 3}
          value={q}
          placeholder="질문을 입력하고 Enter"
          className={s.input}
          onChange={(e) => setQ(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        <Button onClick={send} disabled={busy} icon="message" size="lg">
          보내기
        </Button>
      </div>
    </div>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  wrap: css`display:flex;flex-direction:column;height:calc(100vh - 160px);`,
  wrapCompact: css`display:flex;flex-direction:column;height:100%;`,
  stream: css`flex:1;overflow-y:auto;padding:${theme.spacing(2)};font-size:15px;line-height:1.65;`,
  hint: css`text-align:center;color:${theme.colors.text.secondary};margin-top:${theme.spacing(6)};`,
  hintLogo: css`width:72px;height:72px;object-fit:contain;opacity:.9;margin-bottom:${theme.spacing(2)};`,
  hintTitle: css`font-size:17px;margin-bottom:${theme.spacing(1)};`,
  dim: css`color:${theme.colors.text.disabled};font-size:13px;margin:2px 0;`,
  avatar: css`width:28px;height:28px;object-fit:contain;flex:0 0 auto;margin-top:2px;`,
  userRow: css`display:flex;justify-content:flex-end;margin-bottom:${theme.spacing(2)};`,
  botRow: css`display:flex;justify-content:flex-start;gap:${theme.spacing(1.5)};margin-bottom:${theme.spacing(2)};`,
  // 파란 강조색 대신 배경 계열의 어두운 말풍선. 긴 글을 읽는 화면이라 대비를 낮춘다.
  userBubble: css`
    max-width:78%;background:${theme.colors.background.canvas};
    border:1px solid ${theme.colors.border.medium};
    color:${theme.colors.text.primary};
    padding:${theme.spacing(1.25, 1.75)};border-radius:14px 14px 4px 14px;font-size:15px;`,
  botBubble: css`
    max-width:82%;background:${theme.colors.background.secondary};
    border:1px solid ${theme.colors.border.weak};
    padding:${theme.spacing(1.25, 1.75)};border-radius:14px 14px 14px 4px;font-size:15px;`,
  plain: css`white-space:pre-wrap;word-break:break-word;`,
  // 마크다운 본문. Grafana 가 정화해 준 HTML 을 그린다.
  md: css`
    word-break:break-word;
    p{margin:0 0 ${theme.spacing(1)} 0;}
    p:last-child{margin-bottom:0;}
    ul,ol{margin:0 0 ${theme.spacing(1)} ${theme.spacing(2.5)};}
    li{margin:2px 0;}
    code{background:${theme.colors.background.canvas};padding:1px 5px;border-radius:4px;font-size:13px;}
    pre{background:${theme.colors.background.canvas};padding:${theme.spacing(1)};border-radius:6px;overflow-x:auto;}
    pre code{background:none;padding:0;}
    strong{color:${theme.colors.text.maxContrast};}
    table{border-collapse:collapse;margin:${theme.spacing(1)} 0;}
    th,td{border:1px solid ${theme.colors.border.weak};padding:4px 8px;}
    h1,h2,h3,h4{font-size:16px;margin:${theme.spacing(1.5)} 0 ${theme.spacing(0.5)};}`,
  trace: css`margin-top:${theme.spacing(1.5)};display:flex;flex-wrap:wrap;gap:5px;`,
  chip: css`font-size:12px;padding:2px 8px;border-radius:10px;background:${theme.colors.background.canvas};border:1px solid ${theme.colors.border.weak};color:${theme.colors.text.secondary};`,
  composer: css`display:flex;gap:${theme.spacing(1)};align-items:flex-end;padding:${theme.spacing(1.5)};border-top:1px solid ${theme.colors.border.weak};`,
  input: css`font-size:15px;`,
});
