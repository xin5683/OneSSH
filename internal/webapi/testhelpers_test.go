package webapi

import (
	"context"
	"net/http"
	"testing"

	"onessh/internal/store"
)

// serveAsAdmin 把 handler 包一层本地管理员身份：老测试直连 API handler，
// 会话中间件不在链上，这里手动注入 Principal 模拟已登录的 admin。
func serveAsAdmin(t *testing.T, st *store.Store, handler http.Handler) http.HandlerFunc {
	t.Helper()
	user, err := st.GetLocalUser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{User: user}
	return func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
	}
}

// newMemberPrincipal 构造 member 身份请求上下文，用于权限过滤测试。
func newMemberPrincipal(t *testing.T, st *store.Store, r *http.Request) *http.Request {
	t.Helper()
	if _, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_admin", Name: "首管"}); err != nil {
		t.Fatal(err)
	}
	user, _, err := st.UpsertFeishuUser(context.Background(), store.FeishuProfile{OpenID: "ou_member", Name: "成员"})
	if err != nil {
		t.Fatal(err)
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{User: user}))
}
