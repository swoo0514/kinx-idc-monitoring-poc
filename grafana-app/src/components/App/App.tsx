import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';
const PageOne = React.lazy(() => import('../../pages/PageOne'));

function App(props: AppRootProps) {
  // 화면은 관제 질의 하나다. 만들어질 때 딸려 온 자리표시 페이지 셋은 지웠다 —
  // 왼쪽 메뉴에 "Page Two" 같은 항목이 그대로 보이고 있었다(2026-08-19 점검).
  return (
    <Routes>
      <Route path="*" element={<PageOne />} />
    </Routes>
  );
}

export default App;
