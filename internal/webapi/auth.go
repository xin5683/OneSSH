package webapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"onessh/internal/store"
)

// Principal 是通过 Web 会话认证后的身份，后续所有 handler 从这里取用户。
type Principal struct {
	store.User
}

type principalKey struct{}

// PrincipalFromContext 取当前登录用户；不存在时 ok=false。
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func (p Principal) IsAdmin() bool { return p.Role == "admin" }

// AdminAuth 负责 Web 会话：登录（密码或 SSO 回调）换 cookie，Require 校验并注入身份。
// 会话本体存 SQLite（web_sessions），cookie 只放随机值；禁用用户即时失效。
type AdminAuth struct {
	password string
	Store    *store.Store
}

func NewAdminAuth(password string, st *store.Store) *AdminAuth {
	return &AdminAuth{password: password, Store: st}
}

const sessionCookie = "onessh_session"

// issueSession 为用户签发一条新会话并写 cookie。
func (a *AdminAuth) issueSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	value := hex.EncodeToString(raw)
	expires := time.Now().Add(24 * time.Hour)
	if err := a.Store.CreateWebSession(r.Context(), store.TokenHash(value), userID, expires.Unix()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsHTTPS(r), MaxAge: 86400})
	return nil
}

func (a *AdminAuth) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || subtle.ConstantTimeCompare([]byte(in.Password), []byte(a.password)) != 1 {
		http.Error(w, "密码错误", http.StatusUnauthorized)
		return
	}
	user, err := a.Store.GetLocalUser(r.Context())
	if err != nil {
		http.Error(w, "本地管理员账号异常", http.StatusInternalServerError)
		return
	}
	if err = a.issueSession(w, r, user.ID); err != nil {
		http.Error(w, "创建会话失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// Logout 删除当前会话行并清 cookie；幂等，未登录也回 200。
func (a *AdminAuth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = a.Store.DeleteWebSession(r.Context(), store.TokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsHTTPS(r), MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(forwardedProto, "https")
}

// principal 校验 cookie 并换出身份；无效返回 nil。
func (a *AdminAuth) principal(r *http.Request) *Principal {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	user, err := a.Store.FindWebSession(r.Context(), store.TokenHash(c.Value))
	if err != nil {
		return nil
	}
	p := Principal{User: user}
	return &p
}

// Require 要求已登录；身份注入 context，供 handler 与角色化中间件使用。
func (a *AdminAuth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := a.principal(r)
		if p == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, *p)))
	})
}

// RequireAdmin 在 Require 基础上进一步要求 admin 角色。
func (a *AdminAuth) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := a.principal(r)
		if p == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !p.IsAdmin() {
			http.Error(w, "需要管理员权限", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, *p)))
	})
}
