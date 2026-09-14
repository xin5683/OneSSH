package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"onessh/internal/store"
)

// member 只见授权主机：GET /hosts 过滤 + 未授权端点 403
func TestMemberHostFilterAndForbidden(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	h1, err := st.CreateHost(ctx, store.Host{Name: "h1", Addr: "127.0.0.1", Port: 22, Username: "u", AuthType: "password"})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := st.CreateHost(ctx, store.Host{Name: "h2", Addr: "127.0.0.2", Port: 22, Username: "u", AuthType: "password"})
	if err != nil {
		t.Fatal(err)
	}
	// 首个飞书用户 admin，第二个 member；member 只授权 h1
	admin, _, err := st.UpsertFeishuUser(ctx, store.FeishuProfile{OpenID: "ou_admin", Name: "首管"})
	if err != nil {
		t.Fatal(err)
	}
	member, _, err := st.UpsertFeishuUser(ctx, store.FeishuProfile{OpenID: "ou_member", Name: "成员"})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetUserHosts(ctx, member.ID, []int64{h1.ID}); err != nil {
		t.Fatal(err)
	}

	api := NewAPI(st, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	as := func(u store.User) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			handler := api
			handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{User: u})))
		}
	}
	adminHandler, memberHandler := as(admin), as(member)

	// member 列表只有 h1
	req := httptest.NewRequest(http.MethodGet, "/hosts", nil)
	rr := httptest.NewRecorder()
	memberHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("member 列主机 %d %s", rr.Code, rr.Body.String())
	}
	var listed []struct{ Name string }
	if json.Unmarshal(rr.Body.Bytes(), &listed) != nil || len(listed) != 1 || listed[0].Name != "h1" {
		t.Fatalf("member 主机列表 = %s", rr.Body.String())
	}

	// admin 列表全量
	rr = httptest.NewRecorder()
	adminHandler(rr, httptest.NewRequest(http.MethodGet, "/hosts", nil))
	var adminListed []struct{ Name string }
	if json.Unmarshal(rr.Body.Bytes(), &adminListed) != nil || len(adminListed) != 2 {
		t.Fatalf("admin 主机列表 = %s", rr.Body.String())
	}

	// member 访问未授权主机的 metrics 403
	rr = httptest.NewRecorder()
	memberHandler(rr, httptest.NewRequest(http.MethodGet, "/metrics/"+fmt.Sprint(h2.ID), nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("未授权 metrics = %d %s", rr.Code, rr.Body.String())
	}
	// 授权主机放行（无指标数据但不是 403）
	rr = httptest.NewRecorder()
	memberHandler(rr, httptest.NewRequest(http.MethodGet, "/metrics/"+fmt.Sprint(h1.ID)+"?hours=1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("授权 metrics = %d %s", rr.Code, rr.Body.String())
	}
}

// 用户管理 API：列表/角色/禁用/删除/授权集合
func TestUsersAdminAPI(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	local, err := st.GetLocalUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = st.UpsertFeishuUser(ctx, store.FeishuProfile{OpenID: "ou_admin", Name: "首管"})
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := st.UpsertFeishuUser(ctx, store.FeishuProfile{OpenID: "ou_member", Name: "成员"})
	if err != nil {
		t.Fatal(err)
	}
	h1, err := st.CreateHost(ctx, store.Host{Name: "h1", Addr: "127.0.0.1", Port: 22, Username: "u", AuthType: "password"})
	if err != nil {
		t.Fatal(err)
	}

	api := NewAPI(st, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req = req.WithContext(context.WithValue(req.Context(), principalKey{}, Principal{User: local}))
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)
		return rr
	}

	rr := call(http.MethodGet, "/users", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("用户列表 %d %s", rr.Code, rr.Body.String())
	}
	var users []userView
	if err = json.Unmarshal(rr.Body.Bytes(), &users); err != nil || len(users) != 3 {
		t.Fatalf("用户列表 = %s", rr.Body.String())
	}

	// 角色与状态校验
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(target.ID), `{"role":"admin"}`)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"role":"admin"`)) {
		t.Fatalf("改角色 %d %s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(target.ID), `{"status":"disabled"}`)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"status":"disabled"`)) {
		t.Fatalf("禁用 %d %s", rr.Code, rr.Body.String())
	}
	// 本地管理员受保护
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(local.ID), `{"status":"disabled"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("本地管理员禁用未拒绝: %d", rr.Code)
	}
	rr = call(http.MethodDelete, "/users/"+fmt.Sprint(local.ID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("本地管理员删除未拒绝: %d", rr.Code)
	}
	// 本地管理员永远是兜底 admin，因此"最后一个 admin"降级永远放行——
	// 这是有意设计：密码登录通道保证控制台不会锁死。这里验证降级成功即可。
	adminRow, err := st.FindUserByFeishuOpenID(ctx, "ou_admin")
	if err != nil {
		t.Fatal(err)
	}
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(adminRow.ID), `{"role":"member"}`)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"role":"member"`)) {
		t.Fatalf("降级最后一个飞书 admin = %d %s", rr.Code, rr.Body.String())
	}
	// 恢复成 admin 供后续步骤使用
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(adminRow.ID), `{"role":"admin"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("恢复 admin = %d %s", rr.Code, rr.Body.String())
	}

	// 授权集合整体替换
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(target.ID)+"/hosts", `{"host_ids":[`+fmt.Sprint(h1.ID)+`]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("设置授权 %d %s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodGet, "/users/"+fmt.Sprint(target.ID)+"/hosts", "")
	if !bytes.Contains(rr.Body.Bytes(), []byte(fmt.Sprint(h1.ID))) {
		t.Fatalf("读授权 = %s", rr.Body.String())
	}
	// 不存在的主机 ID 拒绝
	rr = call(http.MethodPut, "/users/"+fmt.Sprint(target.ID)+"/hosts", `{"host_ids":[999]}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("无效主机授权 = %d", rr.Code)
	}

	// 删除用户
	rr = call(http.MethodDelete, "/users/"+fmt.Sprint(target.ID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("删除用户 %d %s", rr.Code, rr.Body.String())
	}
}
