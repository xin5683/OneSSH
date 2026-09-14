package webapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"onessh/internal/feishu"
	"onessh/internal/store"
)

// newFeishuMock 起一个本地服务器扮演飞书三个端点，返回指向它的客户端。
func newFeishuMock(t *testing.T) *feishu.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = w.Write([]byte(`{"code":0,"access_token":"u-at","expires_in":7200}`))
		case strings.HasSuffix(r.URL.Path, "/user_info"):
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"open_id":"ou_9","name":"王五","email":"w@e.com","avatar_url":"https://a/9.png"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := feishu.New("cli_test", "secret", "https://onessh.example/api/v1/auth/feishu/callback")
	client.SetEndpoints(server.URL+"/token", server.URL+"/user_info")
	return client
}

func newTestSSO(t *testing.T, withFeishu bool) (*SSOService, *AdminAuth, *store.Store) {
	t.Helper()
	a, st := newTestAuth(t)
	var client *feishu.Client
	if withFeishu {
		client = newFeishuMock(t)
	}
	return NewSSOService(a, client, "https://onessh.example"), a, st
}

// 完整回调流程：start 302 飞书 → mock 回调 → 落库 + 发会话 → 回跳 return_to
func TestSSOCallbackFullFlow(t *testing.T) {
	sso, auth, st := newTestSSO(t, true)

	rr := httptest.NewRecorder()
	sso.Start(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/start?from=/terminal", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("start 状态码 %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "https://accounts.feishu.cn/open-apis/authen/v1/authorize?") {
		t.Fatalf("start 跳转 %s", location)
	}
	// 从授权 URL 提取 state 模拟飞书回调
	state := location[strings.Index(location, "state=")+6:]
	if amp := strings.Index(state, "&"); amp >= 0 {
		state = state[:amp]
	}

	cb := httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/callback?code=code-1&state="+state, nil)
	cbrr := httptest.NewRecorder()
	sso.Callback(cbrr, cb)
	if cbrr.Code != http.StatusFound {
		t.Fatalf("callback 状态码 %d: %s", cbrr.Code, cbrr.Body.String())
	}
	if got := cbrr.Header().Get("Location"); got != "/terminal" {
		t.Fatalf("回跳 %s, want /terminal", got)
	}

	// cookie 已签发且会话可换出身份
	cookies := cbrr.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "onessh_session" {
		t.Fatalf("回调未发会话 cookie: %v", cookies)
	}
	user, err := st.FindUserByFeishuOpenID(context.Background(), "ou_9")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != "admin" || user.Source != "feishu" || user.Name != "王五" {
		t.Fatalf("首登用户 = %+v", user)
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(cookies[0])
	merr := httptest.NewRecorder()
	auth.Require(http.HandlerFunc(auth.Me)).ServeHTTP(merr, req)
	if merr.Code != http.StatusOK || !strings.Contains(merr.Body.String(), `"role":"admin"`) {
		t.Fatalf("me 状态码 %d, body %s", merr.Code, merr.Body.String())
	}
}

// state 单次使用：重放同一回调必须被拒
func TestSSOCallbackStateSingleUse(t *testing.T) {
	sso, _, _ := newTestSSO(t, true)
	rr := httptest.NewRecorder()
	sso.Start(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/start", nil))
	state := extractState(t, rr.Header().Get("Location"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/callback?code=code-1&state="+state, nil)
	first := httptest.NewRecorder()
	sso.Callback(first, req)
	if first.Code != http.StatusFound || first.Header().Get("Location") != "/" {
		t.Fatalf("首次回调异常: %d %s", first.Code, first.Header().Get("Location"))
	}
	second := httptest.NewRecorder()
	sso.Callback(second, req)
	if second.Header().Get("Location") != "/login?sso_error=state" {
		t.Fatalf("重放回调未被拒绝: %s", second.Header().Get("Location"))
	}
}

// 伪造 state（从未发起过登录）直接拒绝
func TestSSOCallbackUnknownState(t *testing.T) {
	sso, _, _ := newTestSSO(t, true)
	rr := httptest.NewRecorder()
	sso.Callback(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/callback?code=c&state=forged", nil))
	if rr.Header().Get("Location") != "/login?sso_error=state" {
		t.Fatalf("伪造 state 未被拒绝: %s", rr.Header().Get("Location"))
	}
}

// 用户被禁用后回调直接落到 disabled 提示
func TestSSOCallbackDisabledUser(t *testing.T) {
	sso, _, st := newTestSSO(t, true)
	user, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_9", Name: "王五"})
	if err != nil {
		t.Fatal(err)
	}
	// 另建一个 admin 保证禁用不被"最后管理员"规则挡下
	if _, _, err = st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_10", Name: "赵六"}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateUserRoleStatus(context.Background(), user.ID, "", "disabled"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	sso.Start(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/start", nil))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/callback?code=code-1&state="+extractState(t, rr.Header().Get("Location")), nil)
	cbrr := httptest.NewRecorder()
	sso.Callback(cbrr, req)
	if cbrr.Header().Get("Location") != "/login?sso_error=disabled" {
		t.Fatalf("禁用用户回调 = %s", cbrr.Header().Get("Location"))
	}
}

// 拒绝授权（error=access_denied）直接回登录页
func TestSSOCallbackDenied(t *testing.T) {
	sso, _, _ := newTestSSO(t, true)
	rr := httptest.NewRecorder()
	sso.Callback(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/callback?error=access_denied&state=x", nil))
	if rr.Header().Get("Location") != "/login?sso_error=denied" {
		t.Fatalf("拒绝授权回调 = %s", rr.Header().Get("Location"))
	}
}

// 未配置飞书时 enabled=false，start 404
func TestSSODisabled(t *testing.T) {
	sso, _, _ := newTestSSO(t, false)
	rr := httptest.NewRecorder()
	sso.Enabled(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/enabled", nil))
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("enabled 响应 %s", rr.Body.String())
	}
	start := httptest.NewRecorder()
	sso.Start(start, httptest.NewRequest(http.MethodGet, "/api/v1/auth/feishu/start", nil))
	if start.Code != http.StatusNotFound {
		t.Fatalf("未启用时 start 状态码 %d", start.Code)
	}
}

// return_to 白名单：站内路径放行，协议相对与绝对地址回退首页
func TestSafeReturnTo(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{raw: "", want: "/"},
		{raw: "/terminal", want: "/terminal"},
		{raw: "/oauth/authorize?x=1", want: "/oauth/authorize?x=1"},
		{raw: "//evil.com", want: "/"},
		{raw: "/\\evil.com", want: "/"},
		{raw: "https://evil.com", want: "/"},
		{raw: "javascript:alert(1)", want: "/"},
	} {
		if got := safeReturnTo(test.raw); got != test.want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func extractState(t *testing.T, authorizeURL string) string {
	t.Helper()
	state := authorizeURL[strings.Index(authorizeURL, "state=")+6:]
	if amp := strings.Index(state, "&"); amp >= 0 {
		state = state[:amp]
	}
	return state
}
