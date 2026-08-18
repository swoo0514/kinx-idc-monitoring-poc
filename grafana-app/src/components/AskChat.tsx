import React, { useEffect, useRef, useState } from 'react';
import { Button, TextArea, Alert, Spinner, Icon, useStyles2 } from '@grafana/ui';
import { getBackendSrv } from '@grafana/runtime';
import { GrafanaTheme2 } from '@grafana/data';
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
      setTurns((t) => [...t, { role: 'assistant', text: res?.text || '(답이 비어 있습니다)', trace: res?.trace }]);
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
            <Icon name="comment-alt-message" size="xl" />
            <p>관측 데이터를 자연어로 물어보십시오.</p>
            <p className={s.dim}>예: 어느 호스트에 최근 오류 로그가 있나 / 이 호스트 보안 경보를 보여줘</p>
          </div>
        )}
        {turns.map((t, i) => (
          <div key={i} className={t.role === 'user' ? s.user : s.bot}>
            <div className={t.role === 'user' ? s.userBubble : s.botBubble}>
              <pre className={s.text}>{t.text}</pre>
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
          <div className={s.bot}>
            <div className={s.botBubble}>
              <Spinner inline /> 조회하고 있습니다. 도구를 여러 번 부를 수 있어 최대 1분이 걸립니다.
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>
      {err && <Alert title="실패" severity="error">{err}</Alert>}
      <div className={s.composer}>
        <TextArea
          rows={compact ? 2 : 3}
          value={q}
          placeholder="질문을 입력하고 Enter"
          onChange={(e) => setQ(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        <Button onClick={send} disabled={busy} icon="message">보내기</Button>
      </div>
    </div>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  wrap: css`display:flex;flex-direction:column;height:calc(100vh - 160px);`,
  wrapCompact: css`display:flex;flex-direction:column;height:100%;`,
  stream: css`flex:1;overflow-y:auto;padding:${theme.spacing(1)};`,
  hint: css`text-align:center;color:${theme.colors.text.secondary};margin-top:${theme.spacing(6)};`,
  dim: css`color:${theme.colors.text.disabled};font-size:12px;`,
  user: css`display:flex;justify-content:flex-end;margin-bottom:${theme.spacing(1.5)};`,
  bot: css`display:flex;justify-content:flex-start;margin-bottom:${theme.spacing(1.5)};`,
  userBubble: css`max-width:80%;background:${theme.colors.primary.main};color:${theme.colors.primary.contrastText};padding:${theme.spacing(1,1.5)};border-radius:12px 12px 2px 12px;`,
  botBubble: css`max-width:85%;background:${theme.colors.background.secondary};border:1px solid ${theme.colors.border.weak};padding:${theme.spacing(1,1.5)};border-radius:12px 12px 12px 2px;`,
  text: css`white-space:pre-wrap;word-break:break-word;font-family:inherit;margin:0;background:none;border:none;padding:0;`,
  trace: css`margin-top:${theme.spacing(1)};display:flex;flex-wrap:wrap;gap:4px;`,
  chip: css`font-size:11px;padding:1px 6px;border-radius:10px;background:${theme.colors.background.canvas};border:1px solid ${theme.colors.border.weak};color:${theme.colors.text.secondary};`,
  composer: css`display:flex;gap:${theme.spacing(1)};align-items:flex-end;padding:${theme.spacing(1)};border-top:1px solid ${theme.colors.border.weak};`,
});
