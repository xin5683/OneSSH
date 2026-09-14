import { useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { Prohibit, ShieldCheck, Trash, UserCircle, Users } from '@phosphor-icons/react'
import {
  useDeleteUser,
  useHosts,
  useSetUserHosts,
  useUpdateUser,
  useUsers,
} from '@/api/queries'
import type { Host, UserRow } from '@/api/types'
import { ConfirmDialog } from '@/components/ui/alert-dialog'
import { FeishuLogo } from '@/components/brand/feishu-logo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataTable, type Column } from '@/components/ui/data-table'
import { Dialog } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Field } from '@/components/ui/field'
import { MultiSelect } from '@/components/ui/multi-select'
import { PageHeader } from '@/components/ui/page-header'
import { PageTransition } from '@/components/ui/page-transition'
import { Skeleton } from '@/components/ui/skeleton'
import { formatTime } from '@/lib/format'

/** 角色与来源展示：本地账号是兜底通道，标注出来避免管理员困惑它从哪来 */
function UserSourceBadge({ user }: { user: UserRow }) {
  if (user.source === 'local') return <Badge variant="outline">本地</Badge>
  return (
    <Badge>
      <FeishuLogo className="size-3" />
      飞书
    </Badge>
  )
}

/**
 * 主机授权弹窗：member 的可用主机集合。admin 无需授权（全量可见），
 * 表单里明确说明这一点，避免管理员误以为 admin 也要勾。
 */
function HostsDialog({
  user,
  hosts,
  onClose,
  onSave,
}: {
  user: UserRow | null
  hosts: Host[] | undefined
  onClose: () => void
  onSave: (hostIDs: number[]) => Promise<unknown>
}) {
  const {
    control,
    handleSubmit,
    reset,
    formState: { isSubmitting },
  } = useForm<{ host_ids: number[] }>()

  const open = user != null
  // 每次打开重置为当前授权集合
  const prevUser = useState<UserRow | null>(null)
  if (user !== prevUser[0]) {
    prevUser[1](user)
    reset({ host_ids: user?.host_ids ?? [] })
  }

  const submit = handleSubmit(async ({ host_ids }) => {
    if (!user) return
    await onSave(host_ids)
    onClose()
  })

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose()
      }}
      title={`主机授权 · ${user?.name ?? ''}`}
      description={
        user?.role === 'admin'
          ? '该用户是管理员，默认可见全部主机，无需单独授权。'
          : '勾选该成员可以使用的主机（终端 / 文件 / 任务 / 指标 / 记忆）。'
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button variant="primary" loading={isSubmitting} onClick={submit} disabled={user?.role === 'admin'}>
            保存授权
          </Button>
        </>
      }
    >
      <form onSubmit={submit}>
        {user?.role === 'admin' ? (
          <p className="rounded-[8px] border border-border bg-surface-2 px-3 py-2.5 text-[13px] text-muted">
            管理员默认可见并操作全部主机，无需单独授权。
          </p>
        ) : (
          <Field label="授权主机">
            {(id) => (
              <Controller
                control={control}
                name="host_ids"
                render={({ field }) => (
                  <MultiSelect
                    id={id}
                    value={field.value}
                    onChange={field.onChange}
                    options={(hosts ?? []).map((host) => ({ value: host.id, label: host.name }))}
                  />
                )}
              />
            )}
          </Field>
        )}
      </form>
    </Dialog>
  )
}

export function UsersPage() {
  const users = useUsers()
  const hosts = useHosts()
  const updateUser = useUpdateUser()
  const deleteUser = useDeleteUser()
  const setUserHosts = useSetUserHosts()
  const [grantTarget, setGrantTarget] = useState<UserRow | null>(null)
  const [deleting, setDeleting] = useState<UserRow | null>(null)

  const toggleStatus = (user: UserRow) => {
    updateUser.mutate({
      id: user.id,
      status: user.status === 'active' ? 'disabled' : 'active',
    })
  }

  const columns: Column<UserRow>[] = [
    {
      key: 'name',
      title: '用户',
      className: 'min-w-[180px]',
      render: (user) => (
        <div className="flex items-center gap-2.5">
          {user.avatar_url ? (
            <img src={user.avatar_url} alt="" className="size-7 shrink-0 rounded-full object-cover" />
          ) : (
            <UserCircle size={26} weight="fill" className="shrink-0 text-muted" />
          )}
          <div className="min-w-0">
            <p className="truncate text-[13px] font-medium text-text">{user.name}</p>
            <p className="truncate text-[12px] text-muted">{user.email || '—'}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      title: '角色',
      className: 'w-24',
      render: (user) =>
        user.role === 'admin' ? (
          <Badge variant="accent">管理员</Badge>
        ) : (
          <Badge>成员</Badge>
        ),
    },
    {
      key: 'status',
      title: '状态',
      className: 'w-24',
      render: (user) =>
        user.status === 'active' ? (
          <Badge variant="success">启用</Badge>
        ) : (
          <Badge variant="danger">已禁用</Badge>
        ),
    },
    {
      key: 'source',
      title: '来源',
      className: 'w-20',
      render: (user) => <UserSourceBadge user={user} />,
    },
    {
      key: 'last_login',
      title: '最近登录',
      className: 'hidden w-[1%] whitespace-nowrap tabular-nums text-muted md:table-cell',
      render: (user) =>
        user.last_login_at?.Valid ? formatTime(user.last_login_at.Int64) : '从未登录',
    },
    {
      key: 'actions',
      title: '操作',
      className: 'w-[1%] whitespace-nowrap text-right',
      render: (user) => (
        <div className="flex justify-end gap-1">
          <Button
            variant="ghost"
            size="icon"
            aria-label="设置主机授权"
            title="设置主机授权"
            onClick={() => setGrantTarget(user)}
          >
            <ShieldCheck size={16} />
          </Button>
          {user.source === 'local' ? (
            // 内置本地管理员不可操作；留个禁用按钮占位解释行为，比彻底消失更不困惑
            <Button variant="ghost" size="icon" disabled aria-label="本地账号不可禁用" title="内置账号不可禁用">
              <Prohibit size={16} />
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="icon"
              aria-label={user.status === 'active' ? '禁用用户' : '启用用户'}
              title={user.status === 'active' ? '禁用用户' : '启用用户'}
              onClick={() => toggleStatus(user)}
            >
              <Prohibit size={16} />
            </Button>
          )}
          {user.source === 'local' ? (
            <Button variant="ghost" size="icon" disabled aria-label="本地账号不可删除" title="内置账号不可删除">
              <Trash size={16} />
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="icon"
              aria-label="删除用户"
              title="删除用户"
              className="text-danger"
              onClick={() => setDeleting(user)}
            >
              <Trash size={16} />
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <PageTransition>
      <PageHeader
        title="用户"
        subtitle="飞书登录的成员在此管理角色与主机授权；第一个登录的飞书用户自动成为管理员。"
      />
      <div className="rounded-[12px] border border-border bg-surface">
        {users.isLoading ? (
          <div className="space-y-3 p-4">
            {Array.from({ length: 3 }, (_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : users.data && users.data.length > 0 ? (
          <DataTable columns={columns} rows={users.data} rowKey={(user) => user.id} />
        ) : (
          <EmptyState
            icon={<Users size={24} />}
            title="暂无飞书用户"
            description="配置飞书登录后，企业内成员首次登录会自动出现在这里。"
          />
        )}
      </div>

      <HostsDialog
        user={grantTarget}
        hosts={hosts.data}
        onClose={() => setGrantTarget(null)}
        onSave={async (hostIDs) => {
          if (grantTarget) await setUserHosts.mutateAsync({ id: grantTarget.id, host_ids: hostIDs })
        }}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(next) => {
          if (!next) setDeleting(null)
        }}
        title={`删除用户 ${deleting?.name ?? ''}？`}
        description="将移除其所有会话与主机授权。飞书侧再次登录会重新建号。"
        confirmText="删除"
        danger
        onConfirm={async () => {
          if (deleting) await deleteUser.mutateAsync(deleting.id)
          setDeleting(null)
        }}
      />
    </PageTransition>
  )
}
