import React, { Suspense, lazy } from 'react';
import { AppPlugin, PluginExtensionPoints } from '@grafana/data';
import { LoadingPlaceholder } from '@grafana/ui';
import type { AppConfigProps } from './components/AppConfig/AppConfig';
import { AskBody } from './components/AskPanel';

const App = lazy(() => import('./components/App/App'));
const LazyAppConfig = lazy(() => import('./components/AppConfig/AppConfig'));

const AppConfig = (props: AppConfigProps) => (
  <Suspense fallback={<LoadingPlaceholder text="" />}>
    <LazyAppConfig {...props} />
  </Suspense>
);

export const plugin = new AppPlugin<{}>()
  .setRootPage(App)
  .addConfigPage({
    title: 'Configuration',
    icon: 'cog',
    body: AppConfig,
    id: 'configuration',
  })
  // 대시보드 패널 메뉴에서 바로 연다. 패널 번호와 시간 범위가 맥락으로 넘어온다.
  .addLink({
    title: '봇에게 묻기',
    description: '이 패널을 보고 관제 질의 창구를 연다',
    targets: [PluginExtensionPoints.DashboardPanelMenu],
    onClick: (event, { openModal, context }: any) =>
      openModal({
        title: '관제 질의',
        body: ({ onDismiss }: any) => <AskBody onDismiss={onDismiss} context={context} />,
      }),
  });
