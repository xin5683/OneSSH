import { expect, test } from '@playwright/test'
import type { Host } from '../src/api/types'

test('clearing an existing jump host stays direct and omits jump_host when saved', async ({ page }) => {
  const defaults = {
    port: 22,
    username: 'root',
    auth_type: 'password' as const,
    has_password: false,
    monitor_enabled: false,
    archived: false,
    tags: [],
    created_at: 1,
  }
  let hosts: Host[] = [
    { ...defaults, id: 1, name: 'bastion', addr: '192.0.2.1' },
    { ...defaults, id: 2, name: 'target', addr: '192.0.2.2', jump_host_id: 1 },
  ]

  // All API traffic stays in this browser fixture; no real gateway is needed.
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
      return route.fulfill({ json: hosts })
    }
    if (path === '/api/v1/keys' && request.method() === 'GET') {
      return route.fulfill({ json: [] })
    }
    if (path === '/api/v1/hosts/2' && request.method() === 'PUT') {
      const payload = request.postDataJSON()
      hosts = hosts.map((host) => host.id === 2
        ? { ...host, ...payload, jump_host_id: hosts.find((item) => item.name === payload.jump_host)?.id }
        : host)
      return route.fulfill({ json: hosts[1] })
    }
    await route.abort()
    throw new Error(`Unexpected fixture API: ${request.method()} ${path}`)
  })

  await page.goto('/hosts')
  await page.getByRole('button', { name: 'target 操作', exact: true }).click()
  await page.getByRole('menuitem', { name: '编辑', exact: true }).click()

  const dialog = page.getByRole('dialog', { name: '编辑主机', exact: true })
  const jumpHost = dialog.getByRole('combobox', { name: '跳板主机', exact: true })
  await expect(jumpHost).toHaveText('bastion')
  await jumpHost.click()
  await page.getByRole('option', { name: '直连（不使用跳板）', exact: true }).click()
  // This fails with the old Controller.onChange(undefined) fallback to bastion.
  await expect(jumpHost).toHaveText('直连（不使用跳板）')

  const savedRequest = page.waitForRequest((request) =>
    new URL(request.url()).pathname === '/api/v1/hosts/2' && request.method() === 'PUT')
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  const payload = (await savedRequest).postDataJSON()
  expect(payload).toMatchObject({ name: 'target', addr: '192.0.2.2', username: 'root' })
  expect(payload).not.toHaveProperty('jump_host')
  expect(payload).not.toHaveProperty('password')
  await expect(dialog).not.toBeVisible()

  await page.reload()
  await page.getByRole('button', { name: 'target 操作', exact: true }).click()
  await page.getByRole('menuitem', { name: '编辑', exact: true }).click()
  await expect(jumpHost).toHaveText('直连（不使用跳板）')
})

test('key authentication submits an optional password fallback', async ({ page }) => {
  const me = {
    id: 1,
    name: 'admin',
    email: '',
    avatar_url: '',
    role: 'admin',
    source: 'local',
    is_admin: true,
  }
  await page.route((url) => url.pathname.startsWith('/api/'), async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/me' && request.method() === 'GET') {
      return route.fulfill({ json: me })
    }
    if (path === '/api/v1/hosts' && request.method() === 'GET') {
      return route.fulfill({ json: [] })
    }
    if (path === '/api/v1/keys' && request.method() === 'GET') {
      return route.fulfill({
        json: [{ id: 7, name: 'rk-fleet', public_key: 'ssh-ed25519 test', created_at: 1 }],
      })
    }
    if (path === '/api/v1/hosts' && request.method() === 'POST') {
      const payload = request.postDataJSON()
      expect(payload).toMatchObject({
        name: 'host-01',
        username: 'tester',
        addr: 'ssh.example.com',
        port: 2222,
        auth_type: 'key',
        key_id: 7,
        password: 'fallback-password',
      })
      return route.fulfill({
        status: 201,
        json: {
          id: 1,
          ...payload,
          has_password: true,
          monitor_enabled: true,
          archived: false,
          tags: [],
          created_at: 1,
        },
      })
    }
    await route.abort()
    throw new Error(`Unexpected fixture API: ${request.method()} ${path}`)
  })

  await page.goto('/hosts')
  await page.getByRole('button', { name: '添加主机', exact: true }).first().click()
  const dialog = page.getByRole('dialog', { name: '添加主机', exact: true })
  await dialog.getByLabel('名称').fill('host-01')
  await dialog.getByLabel('用户名').fill('tester')
  await dialog.getByLabel('地址').fill('ssh.example.com')
  await dialog.getByLabel('端口').fill('2222')
  await dialog.getByRole('combobox', { name: '认证方式' }).click()
  await page.getByRole('option', { name: 'SSH 密钥', exact: true }).click()
  await dialog.getByRole('combobox', { name: '密钥' }).click()
  await page.getByRole('option', { name: 'rk-fleet', exact: true }).click()
  await dialog.getByLabel('密码兜底（可选）').fill('fallback-password')

  const savedRequest = page.waitForRequest((request) =>
    new URL(request.url()).pathname === '/api/v1/hosts' && request.method() === 'POST')
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  const payload = (await savedRequest).postDataJSON()
  expect(payload).toMatchObject({ auth_type: 'key', key_id: 7, password: 'fallback-password' })
})
