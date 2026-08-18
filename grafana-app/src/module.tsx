import React, { Suspense, lazy } from 'react';
import { AppPlugin } from '@grafana/data';
import { LoadingPlaceholder } from '@grafana/ui';
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
      const q = new URLSearchParams();
      q.set('panel', String(context.title ?? context.id ?? ''));
      if (context.dashboard && context.dashboard.title) {
        q.set('dash', String(context.dashboard.title));
      }
      if (context.timeRange && context.timeRange.from) {
        q.set('from', String(context.timeRange.from));
        q.set('to', String(context.timeRange.to));
      }
      return { path: PAGE + '?' + q.toString() };
    },
  });
