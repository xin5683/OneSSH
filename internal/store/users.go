package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const LocalUserSource = "local"
const FeishuUserSource = "feishu"

// SSOStateLifetime 是飞书 OAuth state 的有效期：授权码本身 5 分钟，
// 覆盖跳转与用户在飞书侧停留的余量后 10 分钟足够，也限制了重放窗口。
const SSOStateLifetime = 10 * time.Minute

var ErrLocalUserProtected = errors.New("内置本地管理员不可修改或删除")

// 查询统一给 users 取别名 u，让直接查询与 web_sessions 联查共用同一份列清单。
const userColumns = `u.id,u.name,u.email,u.avatar_url,u.feishu_open_id,u.feishu_union_id,u.role,u.status,u.source,u.created_at,u.last_login_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.AvatarURL, &u.FeishuOpenID, &u.FeishuUnionID, &u.Role, &u.Status, &u.Source, &u.CreatedAt, &u.LastLoginAt)
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userColumns+` FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id=?`, id))
}

// GetLocalUser 返回密码登录映射的内置管理员。
func (s *Store) GetLocalUser(ctx context.Context) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE u.source='local'`))
}

func (s *Store) FindUserByFeishuOpenID(ctx context.Context, openID string) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE u.feishu_open_id=?`, openID))
}

// FeishuProfile 是飞书侧拉到的身份资料，登录时落到库。
type FeishuProfile struct {
	OpenID  string
	UnionID string
	Name    string
	Email   string
	Avatar  string
}

// UpsertFeishuUser 按飞书登录结果建号或更新资料。第一个飞书用户自动成为 admin；
// 判定放在写事务内（连接统一 immediate 写锁），并发首登也只会产生一个 admin。
// 返回是否为本次新建的账号。
func (s *Store) UpsertFeishuUser(ctx context.Context, profile FeishuProfile) (User, bool, error) {
	now := time.Now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, false, err
	}
	defer tx.Rollback()
	created := false
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE u.feishu_open_id=?`, profile.OpenID))
	switch {
	case err == nil:
		// union_id 以首个非空值落库，避免旧空值覆盖新值
		if profile.UnionID != "" && !u.FeishuUnionID.Valid {
			if _, err = tx.ExecContext(ctx, `UPDATE users SET feishu_union_id=? WHERE id=?`, profile.UnionID, u.ID); err != nil {
				return User{}, false, err
			}
			u.FeishuUnionID = sql.NullString{String: profile.UnionID, Valid: true}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET name=?,email=?,avatar_url=?,last_login_at=? WHERE id=?`,
			profile.Name, profile.Email, profile.Avatar, now, u.ID); err != nil {
			return User{}, false, err
		}
		u.Name, u.Email, u.AvatarURL = profile.Name, profile.Email, profile.Avatar
		u.LastLoginAt = sql.NullInt64{Int64: now, Valid: true}
	case errors.Is(err, sql.ErrNoRows):
		var feishuCount int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE source='feishu'`).Scan(&feishuCount); err != nil {
			return User{}, false, err
		}
		role := "member"
		if feishuCount == 0 {
			role = "admin"
		}
		var unionID any
		if profile.UnionID != "" {
			unionID = profile.UnionID
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO users(name,email,avatar_url,feishu_open_id,feishu_union_id,role,status,source,created_at,last_login_at)
			VALUES(?,?,?,?,?,?, 'active','feishu',?,?)`,
			profile.Name, profile.Email, profile.Avatar, profile.OpenID, unionID, role, now, now)
		if err != nil {
			return User{}, false, err
		}
		id, _ := res.LastInsertId()
		created = true
		u = User{
			ID: id, Name: profile.Name, Email: profile.Email, AvatarURL: profile.Avatar,
			FeishuOpenID:  sql.NullString{String: profile.OpenID, Valid: true},
			FeishuUnionID: sql.NullString{String: profile.UnionID, Valid: profile.UnionID != ""},
			Role:          role, Status: "active", Source: FeishuUserSource,
			CreatedAt: now, LastLoginAt: sql.NullInt64{Int64: now, Valid: true},
		}
	default:
		return User{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, false, err
	}
	return u, created, nil
}

// UpdateUserRoleStatus 修改角色与状态；role/status 传空串表示不改。
// 内置本地管理员受保护；降级或禁用最后一个活跃 admin 会被拒绝，防止自锁。
func (s *Store) UpdateUserRoleStatus(ctx context.Context, id int64, role, status string) (User, error) {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return User{}, err
	}
	if u.Source == LocalUserSource {
		return User{}, ErrLocalUserProtected
	}
	if role == "" {
		role = u.Role
	}
	if status == "" {
		status = u.Status
	}
	if role == u.Role && status == u.Status {
		return u, nil
	}
	if u.Role == "admin" && u.Status == "active" && (role != "admin" || status != "active") {
		var activeAdmins int
		if err = s.DB.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role='admin' AND status='active' AND id<>?`, id).Scan(&activeAdmins); err != nil {
			return User{}, err
		}
		if activeAdmins == 0 {
			return User{}, errors.New("至少保留一名可用的管理员")
		}
	}
	if _, err = s.DB.ExecContext(ctx, `UPDATE users SET role=?,status=? WHERE id=?`, role, status, id); err != nil {
		return User{}, err
	}
	u.Role, u.Status = role, status
	// 禁用即踢下线：会话校验 join status 已可即时生效，这里显式删行只是兜底与清理
	if status == "disabled" {
		if _, err = s.DeleteWebSessionsByUser(ctx, id); err != nil {
			return User{}, err
		}
	}
	return u, nil
}

// DeleteUser 删除飞书用户；web_sessions/user_hosts 由外键级联清理。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if u.Source == LocalUserSource {
		return ErrLocalUserProtected
	}
	if u.Role == "admin" && u.Status == "active" {
		var activeAdmins int
		if err = s.DB.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role='admin' AND status='active' AND id<>?`, id).Scan(&activeAdmins); err != nil {
			return err
		}
		if activeAdmins == 0 {
			return errors.New("至少保留一名可用的管理员")
		}
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

/* ── Web 会话 ────────────────────────────────────────────────────── */

// CreateWebSession 登记一条会话；hash 为 cookie 随机值的 TokenHash。
func (s *Store) CreateWebSession(ctx context.Context, hash string, userID int64, expiresAt int64) error {
	// 顺手清理过期会话与 SSO 残留：都是主键/索引删除，代价可忽略
	now := time.Now().Unix()
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at<?`, now); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM sso_states WHERE created_at<?`, now-int64(SSOStateLifetime.Seconds())); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO web_sessions(id_hash,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)`, hash, userID, now, expiresAt, now)
	return err
}

// FindWebSession 用会话哈希换用户；过期、被禁用、不存在都算未登录。
func (s *Store) FindWebSession(ctx context.Context, hash string) (User, error) {
	u, err := scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM web_sessions ws JOIN users u ON u.id=ws.user_id
		WHERE ws.id_hash=? AND ws.expires_at>? AND u.status='active'`, hash, time.Now().Unix()))
	if err != nil {
		return User{}, err
	}
	// last_seen 只作展示，失败不影响请求
	_, _ = s.DB.ExecContext(ctx, `UPDATE web_sessions SET last_seen_at=? WHERE id_hash=?`, time.Now().Unix(), hash)
	return u, nil
}

func (s *Store) DeleteWebSession(ctx context.Context, hash string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash=?`, hash)
	return err
}

func (s *Store) DeleteWebSessionsByUser(ctx context.Context, userID int64) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id=?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

/* ── member 主机授权 ─────────────────────────────────────────────── */

func (s *Store) UserHostIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT host_id FROM user_hosts WHERE user_id=? ORDER BY host_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// UserAuthorizedHost 检查用户是否被授权访问主机。
func (s *Store) UserAuthorizedHost(ctx context.Context, userID, hostID int64) (bool, error) {
	var one int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM user_hosts WHERE user_id=? AND host_id=?`, userID, hostID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetUserHosts 整体替换用户的主机授权集合；hostIDs 需先经 ValidateHostIDs。
func (s *Store) SetUserHosts(ctx context.Context, userID int64, hostIDs []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_hosts WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hostID := range hostIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO user_hosts(user_id,host_id) VALUES(?,?)`, userID, hostID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

/* ── 飞书 SSO 中间状态 ───────────────────────────────────────────── */

// SaveSSOState 记录发起登录时的 state 与回跳地址；state 单次消费、10 分钟过期。
func (s *Store) SaveSSOState(ctx context.Context, state, returnTo string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sso_states(state,return_to,created_at) VALUES(?,?,?)`,
		state, returnTo, time.Now().Unix())
	return err
}

// ConsumeSSOState 原子消费一条 state：DELETE RETURNING 保证单次使用，过期即失败。
func (s *Store) ConsumeSSOState(ctx context.Context, state string) (string, error) {
	var returnTo string
	err := s.DB.QueryRowContext(ctx, `DELETE FROM sso_states WHERE state=? AND created_at>? RETURNING return_to`,
		state, time.Now().Unix()-int64(SSOStateLifetime.Seconds())).Scan(&returnTo)
	return returnTo, err
}
