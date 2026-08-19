import { test, expect } from './fixtures';
import { ROUTES } from '../src/constants';

// 화면은 관제 질의 하나다. 만들어질 때 딸려 온 자리표시 페이지와 그 검사는 지웠다.
// 예전 검사는 "This is page one." 을 기대했는데 그 자리는 이미 챗봇이었다(2026-08-19).
test.describe('관제 질의 화면', () => {
  test('질의 화면이 뜬다', async ({ gotoPage, page }) => {
    await gotoPage(`/${ROUTES.One}`);
    await expect(page.getByPlaceholder('질문을 입력하고 Enter')).toBeVisible();
  });

  test('대화 목록과 새 대화 단추가 있다', async ({ gotoPage, page }) => {
    await gotoPage(`/${ROUTES.One}`);
    await expect(page.getByText('새 대화')).toBeVisible();
  });
});
