import React, { Suspense, lazy } from 'react';
import { AppPlugin, dateMath, dateTime } from '@grafana/data';
import { LoadingPlaceholder } from '@grafana/ui';
import { getTemplateSrv } from '@grafana/runtime';
import type { AppConfigProps } from './components/AppConfig/AppConfig';

const App = lazy(() => import('./components/App/App'));
const LazyAppConfig = lazy(() => import('./components/AppConfig/AppConfig'));

const AppConfig = (props: AppConfigProps) => (
  <Suspense fallback={<LoadingPlaceholder text="" />}>
    <LazyAppConfig {...props} />
  </Suspense>
);

const PAGE = '/a/kinxidc-ask-app/one';

export const plugin = new AppPlugin<{}>()
  .setRootPage(App)
  .addConfigPage({
    title: 'Configuration',
    icon: 'cog',
    body: AppConfig,
    id: 'configuration',
  })
  // 패널 메뉴에서 그 패널의 맥락을 싣고 질의 화면을 연다. 확장점 문자열이 문서와
  // 실행 코드에서 다르게 나와(하나는 /v1 이 붙는다) 양쪽을 모두 건다.
  .addLink({
    title: '봇에게 묻기',
    description: '이 패널을 보고 관제 질의 창구를 연다',
    targets: ['grafana/dashboard/panel/menu', 'grafana/dashboard/panel/menu/v1'],
    path: PAGE,
    configure: (context: any) => {
      if (!context) {
        return {};
      }
      // 패널 제목에는 $host 같은 변수가 그대로 들어 있다. 대시보드의 현재 값으로
      // 풀어서 넘긴다 — 안 풀면 프롬프트에 "$host" 라는 글자가 그대로 실린다.
      const srv = getTemplateSrv();
      const q = new URLSearchParams();
      q.set('panel', String(srv.replace(String(context.title ?? context.id ?? ''))));
      // **식별자를 그대로 넘긴다.** 제목만 넘기면 게이트웨이가 대시보드를 뒤져 이름이
      // 비슷한 옆 패널을 집는다(2026-08-18 실측: "인증 활동" 을 보고 물었는데
      // "보안 이벤트" 가 그려졌다). 번호가 있는데 이름으로 찾을 이유가 없다.
      if (context.id !== undefined && context.id !== null) {
        q.set('panelId', String(context.id));
      }
      if (context.dashboard && context.dashboard.uid) {
        q.set('uid', String(context.dashboard.uid));
      }
      const host = srv.replace('$host');
      if (host && host !== '$host') {
        q.set('host', host);
      }
      if (context.dashboard && context.dashboard.title) {
        q.set('dash', String(context.dashboard.title));
      }
      // **절대 시각으로 바꿔서 넘긴다.** 대시보드 시간 범위는 두 모양으로 온다.
      // 사람이 그래프를 끌어 확대하면 절대 구간이지만, 그냥 열면 기본값이라 `now-6h`
      // 같은 글자다. 그 글자를 그대로 넘기면 게이트웨이가 못 읽고 조용히 최근 1시간을
      // 본다. 질문 글에는 "(구간 now-6h ~ now)" 가 남아 사람 눈에는 전달된 것처럼
      // 보인다(2026-08-19 점검).
      const at = (v: any, roundUp: boolean): string => {
        if (v === undefined || v === null || v === '') {
          return '';
        }
        const parsed = typeof v === 'string' ? dateMath.parse(v, roundUp) : dateTime(v);
        return parsed && parsed.isValid() ? parsed.toISOString() : '';
      };
      if (context.timeRange) {
        const from = at(context.timeRange.from, false);
        const to = at(context.timeRange.to, true);
        if (from && to) {
          q.set('from', from);
          q.set('to', to);
        }
      }
      return { path: PAGE + '?' + q.toString() };
    },
  });
