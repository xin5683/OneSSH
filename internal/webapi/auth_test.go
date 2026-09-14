package webapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"onessh/internal/store"
)

func newTestAuth(t *testing.T) (*AdminAuth, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewAdminAuth("pw", st), st
}

func TestAdminLoginCookie(t *testing.T) {
	a, _ := newTestAuth(t)
	rr := httptest.NewRecorder()
	a.Login(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"password":"pw"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("登录状态码 %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("未设置 cookie")
	}
	if cookies[0].Secure {
		t.Fatal("HTTP 登录不应设置 Secure cookie")
	}
	protected := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.Role != "admin" {
			t.Errorf("身份注入失败: %+v", p)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	ok := httptest.NewRecorder()
	protected.ServeHTTP(ok, req)
	if ok.Code != http.StatusNoContent {
		t.Fatalf("鉴权状态码 %d", ok.Code)
	}
}

func TestAdminLoginCookieSecureForHTTPS(t *testing.T) {
	a, _ := newTestAuth(t)
	for _, test := range []struct {
		name           string
		target         string
		forwardedProto string
		wantSecure     bool
	}{
		{name: "direct HTTPS", target: "https://onessh.example/api/v1/login", wantSecure: true},
		{name: "trusted HTTPS proxy", target: "http://onessh.internal/api/v1/login", forwardedProto: "https", wantSecure: true},
		{name: "plain HTTP proxy", target: "http://onessh.internal/api/v1/login", forwardedProto: "http", wantSecure: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.target, bytes.NewBufferString(`{"password":"pw"}`))
			if test.forwardedProto != "" {
				request.Header.Set("X-Forwarded-Proto", test.forwardedProto)
			}
			response := httptest.NewRecorder()
			a.Login(response, request)
			cookies := response.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookie 数量 = %d", len(cookies))
			}
			if cookies[0].Secure != test.wantSecure {
				t.Fatalf("Secure = %t, want %t", cookies[0].Secure, test.wantSecure)
			}
		})
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a, _ := newTestAuth(t)
	rr := httptest.NewRecorder()
	a.Login(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"password":"bad"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码状态码 %d", rr.Code)
	}
}

// 登出后旧 cookie 立即失效
func TestLogoutInvalidatesSession(t *testing.T) {
	a, _ := newTestAuth(t)
	rr := httptest.NewRecorder()
	a.Login(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"password":"pw"}`)))
	cookie := rr.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	a.Logout(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	ok := httptest.NewRecorder()
	a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(ok, req)
	if ok.Code != http.StatusUnauthorized {
		t.Fatalf("登出后仍能访问: %d", ok.Code)
	}
}

// 禁用用户即时踢下线（本地管理员禁不了，用飞书用户模拟）
func TestDisabledUserKickedImmediately(t *testing.T) {
	a, st := newTestAuth(t)
	user, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_1", Name: "张三"})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	if err = a.issueSession(rr, httptest.NewRequest(http.MethodGet, "/", nil), user.ID); err != nil {
		t.Fatal(err)
	}
	cookie := rr.Result().Cookies()[0]

	if _, err = st.UpdateUserRoleStatus(context.Background(), user.ID, "", "disabled"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	ok := httptest.NewRecorder()
	a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(ok, req)
	if ok.Code != http.StatusUnauthorized {
		t.Fatalf("禁用用户仍能访问: %d", ok.Code)
	}
}

// member 登录后过 Require 但被 RequireAdmin 拒绝
func TestRequireAdminBlocksMember(t *testing.T) {
	a, st := newTestAuth(t)
	// 首个飞书用户自动成为 admin，第二个才是 member
	if _, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_0", Name: "管理员"}); err != nil {
		t.Fatal(err)
	}
	user, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_2", Name: "李四"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != "member" {
		t.Fatalf("新用户角色 = %s", user.Role)
	}
	rr := httptest.NewRecorder()
	if err = a.issueSession(rr, httptest.NewRequest(http.MethodGet, "/", nil), user.ID); err != nil {
		t.Fatal(err)
	}
	cookie := rr.Result().Cookies()[0]

	for _, test := range []struct {
		middleware func(http.Handler) http.Handler
		want       int
	}{
		{middleware: a.Require, want: 204},
		{middleware: a.RequireAdmin, want: http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)
		ok := httptest.NewRecorder()
		test.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(ok, req)
		if ok.Code != test.want {
			t.Fatalf("状态码 %d, want %d", ok.Code, test.want)
		}
	}
}
