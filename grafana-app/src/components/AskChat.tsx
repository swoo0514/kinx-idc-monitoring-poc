import React, { useCallback, useEffect, useRef, useState } from 'react';
import { TextArea, Alert, Spinner, Icon, useStyles2, ConfirmModal } from '@grafana/ui';
import { getBackendSrv } from '@grafana/runtime';
import { GrafanaTheme2, renderMarkdown } from '@grafana/data';
import { css } from '@emotion/css';

const GATEWAY = '/api/datasources/proxy/uid/askgw/gw';
const LOGO = 'public/plugins/kinxidc-ask-app/img/logo.png';

type Img = { id: string; title: string; url: string };
type Turn = { role: 'user' | 'assistant'; text: string; trace?: any[]; images?: Img[] };
type Convo = { id: string; title: string; at: number };

// 마크다운이 물결표 한 쌍을 취소선으로 읽는다. 봇이 "2026-08-12~13" 처럼 기간을
// 물결표로 적으면 그 뒤 문장까지 통째로 그어진다(2026-08-18 실측). 취소선은 우리
// 답에 쓸 일이 없으므로 물결표를 글자 그대로 보이게 한다.
function keepTildes(text: string): string {
  return String(text || '').replace(/~/g, '\\~');
}

// 패널 그림은 Grafana 가 헤들리스 브라우저로 그린다. 랩 실측으로 **질의가 없는 텍스트
// 패널도 7초**가 걸린다(2026-08-18) — 질의 시간이 아니라 브라우저를 띄우는 고정 비용이라
// 우리 쪽에서 줄일 것이 없다. 그동안 빈 칸이면 고장으로 보이므로 상태를 보여 준다.
function PanelShot({ im, s }: { im: Img; s: any }) {
  const [state, setState] = React.useState<'loading' | 'ok' | 'fail'>('loading');
  return (
    <figure className={s.shot}>
      {state !== 'ok' && (
        <div className={s.shotWait}>
          {state === 'loading' ? (
            <>
              <Spinner size="sm" /> 패널 로딩 중
            </>
          ) : (
            <>패널을 못 불러왔습니다</>
          )}
        </div>
      )}
      <img
        src={im.url}
        alt={im.title}
        className={s.shotImg}
        style={{ display: state === 'ok' ? 'block' : 'none' }}
        onLoad={() => setState('ok')}
        onError={() => setState('fail')}
      />
      <figcaption className={s.shotCap}>
        <Icon name="chart-line" size="xs" /> {im.title}
        <a
          className={s.shotLink}
          href={im.url.replace('/render/d-solo/', '/d/')}
          target="_blank"
          rel="noreferrer"
        >
          대시보드에서 보기
        </a>
      </figcaption>
    </figure>
  );
}

function ago(at: number): string {
  const m = Math.max(0, (Date.now() / 1000 - at) / 60);
  if (m < 60) {
    return Math.floor(m) + '분 전';
  }
  if (m < 1440) {
    return Math.floor(m / 60) + '시간 전';
  }
  return Math.floor(m / 1440) + '일 전';
}

export function AskChat({ prefill, compact, panel }: { prefill?: string; compact?: boolean; panel?: any }) {
  const s = useStyles2(getStyles);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [convos, setConvos] = useState<Convo[]>([]);
  const [convoId, setConvoId] = useState('');
  const [store, setStore] = useState('');
  const [q, setQ] = useState(prefill || '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [toDelete, setToDelete] = useState('');
  const endRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const r: any = await getBackendSrv().get(GATEWAY + '/ask/convos');
      setConvos(r?.convos || []);
      setStore(r?.store || '');
    } catch (e) {
      setStore('none');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [turns, busy]);

  const open = async (id: string) => {
    setErr('');
    setConvoId(id);
    try {
      const r: any = await getBackendSrv().get(GATEWAY + '/ask/convos/' + id);
      setTurns((r?.messages || []).map((m: any) => ({
        role: m.role, text: m.content, images: m.images })));
    } catch (e: any) {
      setErr(String(e?.message || e));
    }
  };

  const fresh = () => {
    setConvoId('');
    setTurns([]);
    setQ('');
    setErr('');
  };

  const stop = async () => {
    try {
      await getBackendSrv().post(GATEWAY + '/ask/cancel', { question: '', session: convoId || 'ui' });
    } catch (e) {
      // 멈춤이 실패해도 화면은 그대로 기다린다
    }
  };

  const remove = async (id: string) => {
    setToDelete('');
    try {
      await getBackendSrv().post(GATEWAY + '/ask/convos/' + id + '/delete', {});
    } catch (e) {
      // 지우기 실패는 목록 갱신으로 드러난다
    }
    if (id === convoId) {
      fresh();
    }
    refresh();
  };

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
      const res: any = await getBackendSrv().post(GATEWAY + '/ask', {
        question: text,
        convo_id: convoId,
        session: convoId || 'ui',
        // **매 턴 보낸다.** 첫 턴에만 보내면 두 번째 질문부터 게이트웨이가
        // 식별자를 못 받아 제목으로 뒤진다. 첫 턴은 맞고 둘째 턴은 틀리므로
        // 사람이 원인을 가장 짚기 어렵다. 같은 그림을 다시 붙일지는 모델이 정한다.
        panel,
      });
      if (res?.error) {
        setErr(res.error);
      }
      if (res?.convo_id && res.convo_id !== convoId) {
        setConvoId(res.convo_id);
      }
      setTurns((t) => [
        ...t,
        { role: 'assistant', text: res?.text || '(답이 비어 있습니다)', trace: res?.trace, images: res?.images },
      ]);
      refresh();
    } catch (e: any) {
      setErr(String(e?.data?.error || e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={s.layout}>
      <aside className={s.side}>
        <button className={s.newBtn} onClick={fresh}>
          <Icon name="plus" /> 새 대화
        </button>
        <div className={s.list}>
          {convos.map((c) => (
            <div key={c.id} className={c.id === convoId ? s.itemOn : s.item} onClick={() => open(c.id)}>
              <div className={s.itemTitle}>{c.title}</div>
              <div className={s.itemAgo}>{ago(c.at)}</div>
              <button
                className={s.del}
                title="지우기"
                onClick={(e) => {
                  e.stopPropagation();
                  setToDelete(c.id);
                }}
              >
                <Icon name="trash-alt" size="sm" />
              </button>
            </div>
          ))}
          {convos.length === 0 && (
            <div className={s.empty}>
              {store === 'none' ? '대화 저장소가 없어 기록이 남지 않습니다' : '아직 대화가 없습니다'}
            </div>
          )}
        </div>
      </aside>

      <main className={compact ? s.wrapCompact : s.wrap}>
        <div className={s.stream}>
          {turns.length === 0 && (
            <div className={s.hint}>
              <img src={LOGO} alt="" className={s.hintLogo} />
              <p className={s.hintTitle}>관측 데이터를 자연어로 물어보십시오.</p>
              <p className={s.dim}>예: 어느 호스트에 최근 오류 로그가 있나</p>
              <p className={s.dim}>예: vm-a 의 복제 지연을 최근 3일로 확인해줘</p>
            </div>
          )}
          {turns.map((t, i) => (
            <div key={i} className={t.role === 'user' ? s.userRow : s.botRow}>
              {t.role === 'assistant' && <img src={LOGO} alt="" className={s.avatar} />}
              <div className={t.role === 'user' ? s.userBubble : s.botBubble}>
                {t.role === 'assistant' ? (
                  <div className={s.md} dangerouslySetInnerHTML={{ __html: renderMarkdown(keepTildes(t.text)) }} />
                ) : (
                  <div className={s.plain}>{t.text}</div>
                )}
                {t.images && t.images.length > 0 && (
                  <div className={s.shots}>
                    {t.images.map((im) => (
                      <PanelShot key={im.id} im={im} s={s} />
                    ))}
                  </div>
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
              <img src={LOGO} alt="" className={s.avatar} />
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
          <div className={s.inputBox}>
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
            {busy ? (
              <button className={s.sendBtn} onClick={stop} title="멈추기">
                <Icon name="square-shape" size="lg" />
              </button>
            ) : (
              <button className={s.sendBtn} onClick={send} title="보내기">
                <Icon name="arrow-up" size="lg" />
              </button>
            )}
          </div>
        </div>
      </main>

      <ConfirmModal
        isOpen={!!toDelete}
        title="대화를 지웁니다"
        body="지운 대화는 되돌릴 수 없습니다."
        confirmText="지우기"
        onConfirm={() => remove(toDelete)}
        onDismiss={() => setToDelete('')}
      />
    </div>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  layout: css`display:flex;height:calc(100vh - 140px);`,
  side: css`
    width:240px;flex:0 0 240px;display:flex;flex-direction:column;
    border-right:1px solid ${theme.colors.border.weak};padding:${theme.spacing(1)};`,
  newBtn: css`
    display:flex;align-items:center;gap:8px;width:100%;padding:${theme.spacing(1, 1.5)};
    border:1px solid ${theme.colors.border.medium};border-radius:10px;cursor:pointer;
    background:${theme.colors.background.secondary};color:${theme.colors.text.primary};
    font-size:14px;margin-bottom:${theme.spacing(1)};
    &:hover{background:${theme.colors.background.canvas};}`,
  list: css`flex:1;overflow-y:auto;`,
  item: css`
    position:relative;padding:${theme.spacing(1, 1.25)};border-radius:8px;cursor:pointer;
    &:hover{background:${theme.colors.background.secondary};}
    &:hover button{opacity:1;}`,
  itemOn: css`
    position:relative;padding:${theme.spacing(1, 1.25)};border-radius:8px;cursor:pointer;
    background:${theme.colors.background.secondary};
    &:hover button{opacity:1;}`,
  itemTitle: css`font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:20px;`,
  itemAgo: css`font-size:11px;color:${theme.colors.text.disabled};margin-top:2px;`,
  del: css`
    position:absolute;right:6px;top:8px;opacity:0;border:none;background:none;cursor:pointer;
    color:${theme.colors.text.secondary};
    &:hover{color:${theme.colors.error.text};}`,
  empty: css`font-size:12px;color:${theme.colors.text.disabled};padding:${theme.spacing(2, 1)};`,
  wrap: css`flex:1;display:flex;flex-direction:column;min-width:0;`,
  wrapCompact: css`flex:1;display:flex;flex-direction:column;min-width:0;`,
  stream: css`flex:1;overflow-y:auto;padding:${theme.spacing(2)};font-size:15px;line-height:1.65;`,
  hint: css`text-align:center;color:${theme.colors.text.secondary};margin-top:${theme.spacing(6)};`,
  hintLogo: css`width:72px;height:72px;object-fit:contain;opacity:.9;margin-bottom:${theme.spacing(2)};`,
  hintTitle: css`font-size:17px;margin-bottom:${theme.spacing(1)};`,
  dim: css`color:${theme.colors.text.disabled};font-size:13px;margin:2px 0;`,
  avatar: css`width:28px;height:28px;object-fit:contain;flex:0 0 auto;margin-top:2px;`,
  userRow: css`display:flex;justify-content:flex-end;margin-bottom:${theme.spacing(2)};`,
  botRow: css`display:flex;justify-content:flex-start;gap:${theme.spacing(1.5)};margin-bottom:${theme.spacing(2)};`,
  userBubble: css`
    max-width:78%;background:${theme.colors.background.canvas};
    border:1px solid ${theme.colors.border.medium};color:${theme.colors.text.primary};
    padding:${theme.spacing(1.25, 1.75)};border-radius:14px 14px 4px 14px;font-size:15px;`,
  botBubble: css`
    max-width:82%;background:${theme.colors.background.secondary};
    border:1px solid ${theme.colors.border.weak};
    padding:${theme.spacing(1.25, 1.75)};border-radius:14px 14px 14px 4px;font-size:15px;`,
  plain: css`white-space:pre-wrap;word-break:break-word;`,
  md: css`
    word-break:break-word;
    p{margin:0 0 ${theme.spacing(1)} 0;} p:last-child{margin-bottom:0;}
    ul,ol{margin:0 0 ${theme.spacing(1)} ${theme.spacing(2.5)};} li{margin:2px 0;}
    code{background:${theme.colors.background.canvas};padding:1px 5px;border-radius:4px;font-size:13px;}
    pre{background:${theme.colors.background.canvas};padding:${theme.spacing(1)};border-radius:6px;overflow-x:auto;}
    pre code{background:none;padding:0;}
    strong{color:${theme.colors.text.maxContrast};}
    table{border-collapse:collapse;margin:${theme.spacing(1)} 0;}
    th,td{border:1px solid ${theme.colors.border.weak};padding:4px 8px;}
    h1,h2,h3,h4{font-size:16px;margin:${theme.spacing(1.5)} 0 ${theme.spacing(0.5)};}`,
  shots: css`margin-top:${theme.spacing(1.5)};display:flex;flex-direction:column;gap:${theme.spacing(1)};`,
  shot: css`margin:0;border:1px solid ${theme.colors.border.weak};border-radius:8px;overflow:hidden;background:${theme.colors.background.canvas};`,
  shotImg: css`display:block;width:100%;height:auto;`,
  shotWait: css`display:flex;align-items:center;gap:8px;min-height:120px;justify-content:center;color:${theme.colors.text.secondary};font-size:12px;padding:24px;`,
  shotCap: css`display:flex;align-items:center;gap:6px;padding:6px 10px;font-size:12px;color:${theme.colors.text.secondary};border-top:1px solid ${theme.colors.border.weak};`,
  shotLink: css`margin-left:auto;color:${theme.colors.text.link};`,
  trace: css`margin-top:${theme.spacing(1.5)};display:flex;flex-wrap:wrap;gap:5px;`,
  chip: css`font-size:12px;padding:2px 8px;border-radius:10px;background:${theme.colors.background.canvas};border:1px solid ${theme.colors.border.weak};color:${theme.colors.text.secondary};`,
  composer: css`padding:${theme.spacing(1.5)};border-top:1px solid ${theme.colors.border.weak};`,
  inputBox: css`
    position:relative;border:1px solid ${theme.colors.border.medium};border-radius:12px;
    background:${theme.colors.background.primary};
    &:focus-within{border-color:${theme.colors.border.strong};}`,
  input: css`
    font-size:15px;line-height:1.6;border:none;background:transparent;resize:none;
    padding:${theme.spacing(1.25, 6, 1.25, 1.75)};
    &:focus{box-shadow:none;outline:none;}`,
  sendBtn: css`
    position:absolute;right:8px;bottom:8px;width:34px;height:34px;
    display:flex;align-items:center;justify-content:center;
    border:1px solid ${theme.colors.border.medium};border-radius:9px;cursor:pointer;
    background:${theme.colors.background.secondary};color:${theme.colors.text.primary};
    &:hover:not(:disabled){background:${theme.colors.background.canvas};}
    &:disabled{opacity:.45;cursor:default;}`,
});
