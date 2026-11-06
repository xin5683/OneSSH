import { expect, test } from '@playwright/test'

test('created token exposes a ready-to-copy Agent MCP setup prompt', async ({ page }) => {
  const plainToken = 'osh_test-token'
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.route((url) => url.pathname.startsWith('/api/'), async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/me' && request.method() === 'GET') {
      return route.fulfill({
        json: {
          id: 1,
          name: 'admin',
          email: '',
          avatar_url: '',
          role: 'admin',
          source: 'local',
          is_admin: true,
        },
      })
    }
    if (path === '/api/v1/hosts' && request.method() === 'GET') {
      return route.fulfill({ json: [] })
    }
    if (path === '/api/v1/tokens' && request.method() === 'GET') {
      return route.fulfill({ json: [] })
    }
    if (path === '/api/v1/tool-groups' && request.method() === 'GET') {
      return route.fulfill({ json: [] })
    }
    if (path === '/api/v1/tokens' && request.method() === 'POST') {
      const payload = request.postDataJSON()
      return route.fulfill({
        status: 201,
        json: {
          id: 7,
          ...payload,
          disabled_tools: payload.disabled_tools ?? [],
          created_at: 1,
          token: plainToken,
        },
      })
    }
    await route.abort()
    throw new Error(`Unexpected fixture API: ${request.method()} ${path}`)
  })

  await page.goto('/tokens')
  await page.getByRole('button', { name: '创建令牌', exact: true }).first().click()
  const createDialog = page.getByRole('dialog', { name: '创建令牌', exact: true })
  await createDialog.getByLabel('名称').fill('agent')
  await createDialog.getByRole('button', { name: '创建', exact: true }).click()

  const resultDialog = page.getByRole('dialog', { name: '令牌已创建', exact: true })
  await expect(resultDialog).toContainText('Streamable HTTP')
  await expect(resultDialog).toContainText('http://127.0.0.1:4173/mcp')
  await expect(resultDialog).toContainText(`Authorization: Bearer ${plainToken}`)

  await resultDialog.getByRole('button', { name: '复制接入提示词', exact: true }).click()
  const copied = await page.evaluate(() => navigator.clipboard.readText())
  expect(copied).toContain('请通过 Streamable HTTP 添加名为 onessh 的 MCP 服务')
  expect(copied).toContain('http://127.0.0.1:4173/mcp')
  expect(copied).toContain(`Authorization: Bearer ${plainToken}`)
  expect(copied).toContain('hosts_list')
})
