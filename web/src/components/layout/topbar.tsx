import { Check, Desktop, HardDrives, List, Moon, SignOut, Sun, UserCircle } from '@phosphor-icons/react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { post } from '@/api/client'
import { useMe } from '@/api/queries'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTheme, type ThemeMode } from '@/lib/theme'
import { titleForPath } from './nav-items'

const modes: { value: ThemeMode; label: string; icon: React.ReactNode }[] = [
  { value: 'light', label: '浅色', icon: <Sun size={15} /> },
  { value: 'dark', label: '深色', icon: <Moon size={15} /> },
  { value: 'system', label: '跟随系统', icon: <Desktop size={15} /> },
]

export function Topbar({ hostCount, onOpenNav }: { hostCount: number; onOpenNav: () => void }) {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { mode, resolved, setMode } = useTheme()
  const { data: me } = useMe()
  const current =
    mode === 'system' ? <Desktop size={16} /> : resolved === 'dark' ? <Moon size={16} /> : <Sun size={16} />

  const signOut = async () => {
    try {
      await post('/logout', {})
    } catch {
      // 会话已失效时登出仍要继续走本地清理
    }
    queryClient.clear()
    navigate('/login', { replace: true })
    toast.success('已退出登录')
  }

  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-bg px-4 md:px-8">
      <div className="flex min-w-0 items-center gap-1.5">
        <Button
          variant="ghost"
          size="icon"
          className="-ml-2 lg:hidden"
          onClick={onOpenNav}
          aria-label="打开导航"
        >
          <List size={18} />
        </Button>
        {/* 只是位置指示：页面里紧接着就是 h1，标题权重必须让给 h1，否则两行标题互相打架 */}
        <span className="truncate text-[13px] text-muted">{titleForPath(pathname)}</span>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Link
          to="/hosts"
          className="inline-flex items-center gap-1.5 rounded-[8px] px-2 py-1.5 text-[12px] text-muted transition-colors hover:bg-surface-2 hover:text-text"
        >
          <HardDrives size={14} />
          <span className="tabular-nums">{hostCount}</span>
          <span className="hidden sm:inline">台主机</span>
        </Link>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="切换主题">
              {current}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {modes.map((m) => (
              <DropdownMenuItem key={m.value} onSelect={() => setMode(m.value)}>
                {m.icon}
                <span className="flex-1">{m.label}</span>
                {mode === m.value && <Check size={14} className="text-accent" />}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
        {me && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                className="ml-1 flex items-center gap-2 rounded-full py-0.5 pr-2 pl-0.5 transition-colors hover:bg-surface-2"
                aria-label="用户菜单"
              >
                {me.avatar_url ? (
                  <img src={me.avatar_url} alt="" className="size-7 rounded-full object-cover" />
                ) : (
                  <UserCircle size={28} weight="fill" className="text-muted" />
                )}
                <span className="hidden max-w-32 truncate text-[12px] text-text sm:inline">{me.name}</span>
                <Badge variant={me.role === 'admin' ? 'accent' : 'default'}>
                  {me.role === 'admin' ? '管理员' : '成员'}
                </Badge>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <div className="px-2 py-1.5">
                <p className="text-[13px] font-medium text-text">{me.name}</p>
                <p className="text-[12px] text-muted">
                  {me.source === 'feishu' ? '飞书账号' : '本地账号'}
                  {me.email ? ` · ${me.email}` : ''}
                </p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={signOut}>
                <SignOut size={15} />
                退出登录
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </header>
  )
}
