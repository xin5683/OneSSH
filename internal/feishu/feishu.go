// Package feishu 实现飞书网页应用 SSO 登录的 OAuth 客户端侧。
// 授权链接与授权码交换复用 golang.org/x/oauth2 的标准实现（RFC 6749），
// token 端点用飞书推荐的 v3（accounts.feishu.cn/oauth/v3/token）；
// user_info 是飞书自有 API（code/msg/data 包裹），不属于 OAuth2 规范，保持手写。
//
// 不使用 PKCE：飞书「获取授权码」文档注明 v1 authorize 使用 PKCE 时暂时只能搭配
// v2 token 端点（v3 会以 20049 "PKCE code challenge failed" 拒绝 code_verifier）。
// 开放平台应用均为机密客户端，按 v3 文典的标准流程以 client_secret（请求体内）
// 鉴权，配合 state 防 CSRF，安全性等价。
package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	authorizeEndpoint = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	tokenEndpoint     = "https://accounts.feishu.cn/oauth/v3/token"
	userInfoEndpoint  = "https://open.feishu.cn/open-apis/authen/v1/user_info"

	requestTimeout = 15 * time.Second
)

// Profile 是从飞书侧取到的登录身份（user_info 响应 data 部分的子集）。
type Profile struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Avatar  string `json:"avatar_url"`
}

type Client struct {
	conf        *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func New(appID, appSecret, redirectURI string) *Client {
	return &Client{
		conf: &oauth2.Config{
			ClientID:     appID,
			ClientSecret: appSecret,
			RedirectURL:  redirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authorizeEndpoint,
				TokenURL: tokenEndpoint,
				// 飞书要求凭据放请求体；Basic 与 client_secret 混用会报 20070
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		userInfoURL: userInfoEndpoint,
		httpClient:  &http.Client{Timeout: requestTimeout},
	}
}

// SetEndpoints 仅供测试注入 mock 服务器地址。
func (c *Client) SetEndpoints(token, userInfo string) {
	c.conf.Endpoint.TokenURL = token
	c.userInfoURL = userInfo
}

// AuthorizeURL 构造跳转飞书授权页的地址；state 由调用方生成并落库校验（防 CSRF）。
func (c *Client) AuthorizeURL(state string) string {
	return c.conf.AuthCodeURL(state)
}

// APIError 保留飞书返回的业务错误码（响应 JSON 的 code 字段），
// 调用方据此给出可读中文提示与登录页短码。
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("飞书接口错误 %d: %s", e.Code, e.Message)
	}
	return "飞书接口错误: " + e.Message
}

func apiError(code int, msg string) error { return &APIError{Code: code, Message: msg} }

// 飞书业务错误码的可读提示，未覆盖的码原样透出。
func DescribeError(err error) string {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return "飞书登录失败，请稍后重试"
	}
	switch apiErr.Code {
	case 20010:
		return "你不在飞书应用的可用范围内，请联系管理员将你加入"
	case 20027:
		return "飞书应用未申请所需的用户信息权限，请联系应用管理员"
	case 20071:
		return "回调地址与飞书应用安全设置不匹配，请核对 ONESSH_PUBLIC_URL 与重定向 URL 配置"
	case 20003, 20004, 20065:
		return "登录凭证已失效或已被使用，请重新发起登录"
	case 20049:
		return "PKCE 校验失败，请重新发起登录"
	case 20012:
		return "App Secret 校验失败，请核对 ONESSH_FEISHU_APP_SECRET"
	case 20050, 20072, 99991400:
		return "飞书服务暂时不可用，请稍后重试"
	}
	return apiErr.Error()
}

// ExchangeCode 用授权码换取 user_access_token。token 只在本次登录内使用、不落库，
// 所以这里只返回 access token 一个值。
func (c *Client) ExchangeCode(ctx context.Context, code string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	token, err := c.conf.Exchange(ctx, code)
	if err != nil {
		return "", translateError(err)
	}
	return token.AccessToken, nil
}

// translateError 把 oauth2 库的错误翻译回 APIError。飞书把业务错误码放在响应
// JSON 的 code 字段（HTTP 400/500 + RFC 6749 的 error/error_description），
// oauth2.RetrieveError 保留了原始 Body，重新解析拿回业务码，供 DescribeError
// 与服务端日志使用——否则只剩一个 400 状态码，排障无从下手。
func translateError(err error) error {
	var rerr *oauth2.RetrieveError
	if !errors.As(err, &rerr) {
		return err
	}
	var body struct {
		Code             int    `json:"code"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(rerr.Body, &body) == nil && body.Code != 0 {
		message := body.ErrorDescription
		if message == "" {
			message = rerr.ErrorDescription
		}
		if message == "" {
			message = rerr.ErrorCode
		}
		return &APIError{Code: body.Code, Message: message}
	}
	return &APIError{Message: firstNonEmpty(rerr.ErrorDescription, rerr.ErrorCode)}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type userInfoResponse struct {
	Code int     `json:"code"`
	Msg  string  `json:"msg"`
	Data Profile `json:"data"`
}

// UserInfo 用 user_access_token 拉取登录者身份资料。
func (c *Client) UserInfo(ctx context.Context, userAccessToken string) (Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoURL, nil)
	if err != nil {
		return Profile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+userAccessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("请求飞书用户信息接口: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Profile{}, fmt.Errorf("读取飞书用户信息响应: %w", err)
	}
	var out userInfoResponse
	if err = json.Unmarshal(body, &out); err != nil {
		return Profile{}, fmt.Errorf("解析飞书用户信息响应（状态码 %d）: %w", resp.StatusCode, err)
	}
	if out.Code != 0 {
		return Profile{}, apiError(out.Code, out.Msg)
	}
	if out.Data.OpenID == "" {
		return Profile{}, errors.New("飞书用户信息缺少 open_id")
	}
	return out.Data, nil
}
