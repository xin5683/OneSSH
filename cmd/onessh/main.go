package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"onessh/internal/config"
	"onessh/internal/cryptox"
	"onessh/internal/events"
	"onessh/internal/feishu"
	"onessh/internal/hostmanager"
	"onessh/internal/mcpserver"
	"onessh/internal/memoryx"
	"onessh/internal/oauthserver"
	"onessh/internal/sshpool"
	"onessh/internal/store"
	"onessh/internal/webapi"
	"onessh/web"
)

var version = "dev"

func main() {
	loadDotEnv()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	memEngine := memoryx.New(st, memoryx.EmbeddingConfig{
		APIURL: cfg.EmbeddingAPIURL,
		APIKey: cfg.EmbeddingAPIKey,
		Model:  cfg.EmbeddingModel,
	})
	box, err := cryptox.New(cfg.MasterKey)
	if err != nil {
		log.Fatal(err)
	}
	pool := sshpool.New(st, box)
	defer pool.Close()
	hosts := hostmanager.New(st, box, pool)
	bus := events.New()
	// oauthService 先建：它会校验并规范化 ONESSH_PUBLIC_URL，MCP 的 serverInfo 图标直接复用该结果
	oauthService, err := oauthserver.New(st, cfg.PublicURL)
	if err != nil {
		log.Fatal(err)
	}
	mcpService := mcpserver.New(st, pool, bus, hosts, memEngine, mcpserver.Options{
		DataDir:       cfg.DataDir,
		PublicURL:     oauthService.PublicURL,
		PollInterval:  cfg.PollInterval,
		SearchHelper:  cfg.SearchHelper,
		MCPApps:       cfg.MCPApps,
		DisabledTools: cfg.DisabledTools,
	})
	defer mcpService.Close()
	adminAuth := webapi.NewAdminAuth(cfg.AdminPassword, st)
	adminAPI := webapi.NewAPI(st, box, pool, hosts, mcpService.Exec, mcpService.Files, mcpService.Jobs, mcpService.Monitor, memEngine, bus)
	// 飞书登录：未配置时端点不注册，登录页拿 enabled=false 后不显示入口
	var feishuClient *feishu.Client
	if cfg.FeishuAppID != "" {
		feishuClient = feishu.New(cfg.FeishuAppID, cfg.FeishuAppSecret, oauthService.PublicURL+"/api/v1/auth/feishu/callback")
		// 20029 类问题九成是控制台登记的重定向 URL 与此串不一致，启动即打印便于比对
		log.Printf("飞书登录已启用，回调地址: %s", oauthService.PublicURL+"/api/v1/auth/feishu/callback")
	}
	ssoService := webapi.NewSSOService(adminAuth, feishuClient, oauthService.PublicURL)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/login", http.HandlerFunc(adminAuth.Login))
	mux.HandleFunc("GET /api/v1/auth/feishu/enabled", ssoService.Enabled)
	if feishuClient != nil {
		mux.HandleFunc("GET /api/v1/auth/feishu/start", ssoService.Start)
		mux.HandleFunc("GET /api/v1/auth/feishu/callback", ssoService.Callback)
	}
	mux.Handle("GET /api/v1/me", adminAuth.Require(http.HandlerFunc(adminAuth.Me)))
	mux.Handle("POST /api/v1/logout", adminAuth.Require(http.HandlerFunc(adminAuth.Logout)))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", oauthService.ProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", oauthService.ProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauthService.AuthorizationServerMetadata)
	mux.HandleFunc("POST /oauth/register", oauthService.RegisterClient)
	mux.HandleFunc("POST /oauth/token", oauthService.Token)
	// OAuth 同意页涉及对 MCP 客户端放权，只允许 admin 操作
	mux.Handle("GET /api/v1/oauth/authorization", adminAuth.RequireAdmin(http.HandlerFunc(oauthService.AuthorizationInfo)))
	mux.Handle("POST /api/v1/oauth/authorization", adminAuth.RequireAdmin(http.HandlerFunc(oauthService.AuthorizationDecision)))
	mux.Handle("/mcp", mcpserver.Handler(st, mcpService, oauthService.ResourceURLs))
	// 资源管理类端点（主机/密钥/令牌/用户的增删改）仅 admin；其余 member 可用（按授权过滤）
	mux.Handle("POST /api/v1/hosts", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("PUT /api/v1/hosts/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("DELETE /api/v1/hosts/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("POST /api/v1/hosts/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("POST /api/v1/keys", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("DELETE /api/v1/keys/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("POST /api/v1/tokens", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("PUT /api/v1/tokens/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("DELETE /api/v1/tokens/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("/api/v1/users", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("/api/v1/users/", adminAuth.RequireAdmin(http.StripPrefix("/api/v1", adminAPI.Handler())))
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", adminAuth.Require(adminAPI.Handler())))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.Health(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": version})
	})
	mux.Handle("/", web.Handler())
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("OneSSH %s 监听 %s", version, cfg.Listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.New(os.Stderr, "", 0).Fatal(err)
	}
}
