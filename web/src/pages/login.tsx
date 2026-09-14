import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { motion } from 'motion/react'
import { WarningCircle } from '@phosphor-icons/react'
import { post, type ApiError } from '@/api/client'
import { useFeishuEnabled } from '@/api/queries'
import { FeishuLogo } from '@/components/brand/feishu-logo'
import { LogoTile } from '@/components/brand/logo'
import { Button } from '@/components/ui/button'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'

/** sso_error=xxx 是飞书回调失败落回来的短码，翻译成人话 */
const ssoErrorText: Record<string, string> = {
  denied: '你取消了飞书授权',
  invalid: '飞书回调参数无效，请重试',
  state: '登录状态已过期或被重复使用，请重新发起登录',
  scope: '飞书侧配置有误（可用范围/权限/回调地址），请联系应用管理员',
  secret: 'App Secret 校验失败，请检查 ONESSH_FEISHU_APP_SECRET 配置',
  disabled: '该账号已被管理员禁用',
  feishu: '飞书登录失败，请稍后重试',
  server: '服务器开小差了，请稍后重试',
}

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const [error, setError] = useState('')
  const [params, setParams] = useSearchParams()
  const { data: feishu } = useFeishuEnabled()

  // 回调失败带回的 sso_error 只展示一次：读完即从 URL 摘掉，刷新后不残留
  useEffect(() => {
    const code = params.get('sso_error')
    if (code) {
      setError(ssoErrorText[code] ?? '飞书登录失败，请重试')
      params.delete('sso_error')
      setParams(params, { replace: true })
    }
  }, [params, setParams])

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<{ password: string }>()

  const submit = handleSubmit(async ({ password }) => {
    setError('')
    try {
      await post('/login', { password })
      // 换会话必须丢弃旧缓存，否则上一个身份的数据会闪现
      queryClient.clear()
      navigateBack()
    } catch (e) {
      // 后端 401 只会回 "Unauthorized"，直接透出对中文界面既突兀也没信息量
      const err = e as ApiError
      setError(err.status === 401 ? '密码不正确，请重新输入' : err.message)
    }
  })

  const feishuLogin = () => {
    setError('')
    // from 已带查询串（OAuth 授权链接全靠它）；只认站内相对路径，浏览器端再挡一次
    const from = (location.state as { from?: string } | null)?.from
    const safe = from && from.startsWith('/') && !from.startsWith('//') ? from : '/'
    window.location.href = `/api/v1/auth/feishu/start?from=${encodeURIComponent(safe)}`
  }

  const navigateBack = () => {
    const from = (location.state as { from?: string } | null)?.from
    const back = from && from.startsWith('/') && !from.startsWith('//') ? from : '/'
    navigate(back, { replace: true })
  }

  return (
    <div className="relative flex min-h-dvh items-center justify-center overflow-hidden bg-bg px-4 py-10">
      {/* 单一冷光源：只用来把视线压到卡片上，浅色下靠 accent 混合出可感知但不脏的青灰 */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-1/2 size-[720px] -translate-x-1/2 -translate-y-[62%] rounded-full blur-[100px]"
        style={{
          background:
            'radial-gradient(circle, color-mix(in oklab, var(--accent) 30%, transparent) 0%, transparent 68%)',
          opacity: 0.35,
        }}
      />
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.28, ease: 'easeOut' }}
        className="relative w-full max-w-[380px] rounded-[12px] border border-border bg-surface p-7 shadow-card sm:p-8"
      >
        <LogoTile className="size-10" />
        <h1 className="mt-5 text-[22px] leading-none font-semibold tracking-tight text-text">OneSSH</h1>
        <p className="mt-2 text-[13px] text-muted">集中式 SSH 网关控制台</p>

        <form onSubmit={submit} className="mt-7 space-y-4">
          <Field label="管理员密码" required error={errors.password?.message}>
            {(id) => (
              <Input
                id={id}
                type="password"
                autoFocus
                autoComplete="current-password"
                placeholder="••••••••"
                invalid={!!errors.password || !!error}
                {...register('password', { required: '请输入管理员密码' })}
              />
            )}
          </Field>

          {/* 登录失败是提交结果而不是字段校验，贴在按钮上方比 toast 更容易被看到 */}
          {error && (
            <p className="flex items-start gap-2 rounded-[8px] border border-danger/25 bg-danger/8 px-3 py-2 text-[12px] leading-5 text-danger">
              <WarningCircle size={15} weight="fill" className="mt-px shrink-0" />
              {error}
            </p>
          )}

          <Button type="submit" variant="primary" size="lg" className="w-full" loading={isSubmitting}>
            进入控制台
          </Button>
        </form>

        {feishu?.enabled && (
          <>
            <div className="my-5 flex items-center gap-3 text-[12px] text-muted">
              <span className="h-px flex-1 bg-border" />
              或
              <span className="h-px flex-1 bg-border" />
            </div>
            <Button variant="outline" size="lg" className="w-full" onClick={feishuLogin}>
              <FeishuLogo className="size-[18px]" />
              使用飞书登录
            </Button>
          </>
        )}
      </motion.div>
    </div>
  )
}
