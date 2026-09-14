package webapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"onessh/internal/feishu"
	"onessh/internal/store"
)

// SSOService 承载飞书登录的三个公开端点。回调是跨站落地页：只写 cookie 不读会话，
// SameSite=Strict 的现有会话 cookie 不受影响。
type SSOService struct {
	adminAuth *AdminAuth
	feishu    *feishu.Client
	baseURL   string
}

func NewSSOService(adminAuth *AdminAuth, client *feishu.Client, publicURL string) *SSOService {
	return &SSOService{adminAuth: adminAuth, feishu: client, baseURL: strings.TrimRight(publicURL, "/")}
}

func (s *SSOService) callbackURL() string {
	return s.baseURL + "/api/v1/auth/feishu/callback"
}

// Enabled 供登录页决定是否展示飞书登录入口。
func (s *SSOService) Enabled(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, http.StatusOK, map[string]bool{"enabled": s.feishu != nil})
}

// safeReturnTo 只接受站内相对路径：from 参数来自登录页跳转前的地址，伪造的
// "//host" 会被浏览器当协议相对 URL 跳走，绝对 URL 则是明确的开放重定向。
func safeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	return raw
}

// ssoRedirect 统一落回登录页并带上错误标识；登录页把它翻译成中文提示。
func ssoRedirect(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(code), http.StatusFound)
}

// randomToken 生成 n 字节随机值的 base64url 编码，用作 OAuth state。
func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Start 发起飞书授权：生成 state 落库（防 CSRF），302 到飞书授权页。
// PKCE 不使用：飞书 v1 authorize 与 v3 token 的配对暂未开放，机密客户端
// 以 client_secret 鉴权（见 internal/feishu 包注释）。
func (s *SSOService) Start(w http.ResponseWriter, r *http.Request) {
	if s.feishu == nil {
		http.Error(w, "飞书登录未启用", http.StatusNotFound)
		return
	}
	state, err := randomToken(24)
	if err != nil {
		http.Error(w, "生成 state 失败", http.StatusInternalServerError)
		return
	}
	if err = s.adminAuth.Store.SaveSSOState(r.Context(), state, safeReturnTo(r.URL.Query().Get("from"))); err != nil {
		http.Error(w, "保存登录状态失败", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.feishu.AuthorizeURL(state), http.StatusFound)
}

// Callback 处理飞书回调：消费 state → 换 token → 拉身份 → 建号/更新 → 发会话 → 回跳。
func (s *SSOService) Callback(w http.ResponseWriter, r *http.Request) {
	if s.feishu == nil {
		http.Error(w, "飞书登录未启用", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		ssoRedirect(w, r, "denied")
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		ssoRedirect(w, r, "invalid")
		return
	}
	returnTo, err := s.adminAuth.Store.ConsumeSSOState(r.Context(), state)
	if err != nil {
		// state 不存在/已用/过期：多半是回调重放或超时
		ssoRedirect(w, r, "state")
		return
	}
	accessToken, err := s.feishu.ExchangeCode(r.Context(), code)
	if err != nil {
		// 带上业务码与详情：HTTP 状态码（如 400）本身不足以排障
		log.Printf("飞书登录换 token 失败: %s（详情: %v）", feishu.DescribeError(err), err)
		ssoRedirect(w, r, feishuError(err))
		return
	}
	profile, err := s.feishu.UserInfo(r.Context(), accessToken)
	if err != nil {
		log.Printf("飞书登录取用户信息失败: %s（详情: %v）", feishu.DescribeError(err), err)
		ssoRedirect(w, r, feishuError(err))
		return
	}
	user, _, err := s.adminAuth.Store.UpsertFeishuUser(r.Context(), store.FeishuProfile{
		OpenID:  profile.OpenID,
		UnionID: profile.UnionID,
		Name:    profile.Name,
		Email:   profile.Email,
		Avatar:  profile.Avatar,
	})
	if err != nil {
		log.Printf("飞书登录落库失败: %v", err)
		ssoRedirect(w, r, "server")
		return
	}
	if user.Status != "active" {
		ssoRedirect(w, r, "disabled")
		return
	}
	if err = s.adminAuth.issueSession(w, r, user.ID); err != nil {
		log.Printf("飞书登录创建会话失败: %v", err)
		ssoRedirect(w, r, "server")
		return
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// feishuError 把飞书侧错误折叠成登录页可显示的短码：常见码有专属文案，
// 其余统一成 feishu，详情已在服务端日志里。
func feishuError(err error) string {
	var apiErr *feishu.APIError
	if !errors.As(err, &apiErr) {
		return "feishu"
	}
	switch apiErr.Code {
	case 20010, 20027, 20071:
		// 控制台配置类：可用范围 / 权限 / 回调地址
		return "scope"
	case 20003, 20004, 20065, 20049:
		// 授权码或 PKCE 失效：重新发起登录即可恢复
		return "state"
	case 20012:
		// App Secret 配错：提示查配置而不是干等
		return "secret"
	}
	return "feishu"
}

// Me 返回当前登录身份，前端据此做角色化 UI。
func (a *AdminAuth) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{
		"id": p.ID, "name": p.Name, "email": p.Email, "avatar_url": p.AvatarURL,
		"role": p.Role, "source": p.Source, "is_admin": p.IsAdmin(),
	})
}
