package feishu

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newTestClient 把 token/user_info 端点指向本地 mock；authorize 保持飞书默认地址，
// 测试只断言生成的授权 URL 参数。
func newTestClient(t *testing.T, tokenStatus int, tokenBody, userInfoBody string) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			if tokenStatus != 0 {
				w.WriteHeader(tokenStatus)
			}
			_, _ = w.Write([]byte(tokenBody))
		case strings.HasSuffix(r.URL.Path, "/user_info"):
			if r.Header.Get("Authorization") != "Bearer u-at" {
				_, _ = w.Write([]byte(`{"code":20005,"msg":"token 无效"}`))
				return
			}
			_, _ = w.Write([]byte(userInfoBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := New("cli_test", "secret", "https://onessh.example/api/v1/auth/feishu/callback")
	client.SetEndpoints(server.URL+"/token", server.URL+"/user_info")
	return client, server
}

// 授权 URL：标准 OAuth2 参数齐全；机密客户端不使用 PKCE（v1 authorize 与 v3
// token 的 PKCE 配对暂未开放），断言不携带 code_challenge。
func TestAuthorizeURL(t *testing.T) {
	client := New("cli_test", "secret", "https://onessh.example/api/v1/auth/feishu/callback")
	raw := client.AuthorizeURL("state-abc")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "accounts.feishu.cn" || u.Path != "/open-apis/authen/v1/authorize" {
		t.Fatalf("授权地址 = %s", raw)
	}
	q := u.Query()
	if q.Get("client_id") != "cli_test" || q.Get("response_type") != "code" || q.Get("state") != "state-abc" {
		t.Fatalf("授权参数 = %v", q)
	}
	if q.Get("redirect_uri") != "https://onessh.example/api/v1/auth/feishu/callback" {
		t.Fatalf("redirect_uri = %s", q.Get("redirect_uri"))
	}
	for _, key := range []string{"code_challenge", "code_challenge_method"} {
		if q.Get(key) != "" {
			t.Errorf("不应携带 %s = %q", key, q.Get(key))
		}
	}
}

func TestExchangeCodeSuccess(t *testing.T) {
	client, _ := newTestClient(t, 0,
		`{"code":0,"access_token":"u-at","token_type":"Bearer","expires_in":7200}`,
		`{"code":0,"msg":"success","data":{"open_id":"ou_1","name":"张三"}}`)
	token, err := client.ExchangeCode(context.Background(), "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if token != "u-at" {
		t.Fatalf("token = %s", token)
	}
}

// 交换请求体必须是 RFC 6749 form 编码且凭据放请求体（不能 Basic）；
// 不发送 code_verifier（PKCE 不适用，见包注释）。
func TestExchangeCodeSendsStandardForm(t *testing.T) {
	var gotForm url.Values
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		gotContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"access_token":"u-at","token_type":"Bearer","expires_in":7200}`))
	}))
	t.Cleanup(server.Close)
	client := New("cli_test", "secret", "https://onessh.example/api/v1/auth/feishu/callback")
	client.SetEndpoints(server.URL+"/token", server.URL+"/user_info")
	if _, err := client.ExchangeCode(context.Background(), "code-1"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("Content-Type = %s", gotContentType)
	}
	for _, test := range []struct{ key, want string }{
		{"grant_type", "authorization_code"},
		{"code", "code-1"},
		{"client_id", "cli_test"},
		{"client_secret", "secret"},
		{"redirect_uri", "https://onessh.example/api/v1/auth/feishu/callback"},
	} {
		if gotForm.Get(test.key) != test.want {
			t.Errorf("%s = %q, want %q", test.key, gotForm.Get(test.key), test.want)
		}
	}
	for _, absent := range []string{"code_verifier", "Authorization"} {
		if gotForm.Get(absent) != "" {
			t.Errorf("不应发送 %s: %q", absent, gotForm.Get(absent))
		}
	}
}

// 业务错误（HTTP 400 + code/error/error_description）翻译回 APIError 并带业务码
func TestExchangeCodeAPIError(t *testing.T) {
	client, _ := newTestClient(t, http.StatusBadRequest,
		`{"code":20071,"error":"invalid_redirect_uri","error_description":"redirect mismatch"}`, `{}`)
	_, err := client.ExchangeCode(context.Background(), "code-1")
	if err == nil {
		t.Fatal("期望错误")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("错误类型 = %T: %v", err, err)
	}
	if apiErr.Code != 20071 {
		t.Fatalf("业务码 = %d", apiErr.Code)
	}
	if got := DescribeError(err); !strings.Contains(got, "回调地址") {
		t.Fatalf("20071 提示 = %q", got)
	}
}

// 20003（授权码失效）应给出「重新发起登录」提示
func TestExchangeCodeExpiredGrant(t *testing.T) {
	client, _ := newTestClient(t, http.StatusBadRequest,
		`{"code":20003,"error":"invalid_grant","error_description":"The authorization code is not found."}`, `{}`)
	_, err := client.ExchangeCode(context.Background(), "code-1")
	if err == nil {
		t.Fatal("期望错误")
	}
	if got := DescribeError(err); !strings.Contains(got, "重新发起登录") {
		t.Fatalf("20003 提示 = %q", got)
	}
}

func TestUserInfo(t *testing.T) {
	client, _ := newTestClient(t, 0, `{"code":0,"access_token":"u-at"}`,
		`{"code":0,"msg":"success","data":{"open_id":"ou_1","union_id":"un_1","name":"张三","email":"z@e.com","avatar_url":"https://a/e.png"}}`)
	profile, err := client.UserInfo(context.Background(), "u-at")
	if err != nil {
		t.Fatal(err)
	}
	if profile.OpenID != "ou_1" || profile.Name != "张三" || profile.Email != "z@e.com" || profile.Avatar != "https://a/e.png" || profile.UnionID != "un_1" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestUserInfoBadToken(t *testing.T) {
	client, _ := newTestClient(t, 0, `{"code":0,"access_token":"u-at"}`, `{"code":0,"msg":"x","data":{}}`)
	_, err := client.UserInfo(context.Background(), "bad-token")
	if err == nil {
		t.Fatal("期望错误")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("错误类型 = %T", err)
	}
	if apiErr.Code != 20005 {
		t.Fatalf("code = %d", apiErr.Code)
	}
}
