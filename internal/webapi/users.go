package webapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"onessh/internal/store"
)

// 用户管理端点全部只挂 RequireAdmin（见 main.go），这里不再重复判角色。
func (a *API) usersRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /users", a.users)
	mux.HandleFunc("PUT /users/{id}", a.userUpdate)
	mux.HandleFunc("DELETE /users/{id}", a.userDelete)
	mux.HandleFunc("GET /users/{id}/hosts", a.userHosts)
	mux.HandleFunc("PUT /users/{id}/hosts", a.userHostsSet)
}

type userView struct {
	store.User
	HostIDs []int64 `json:"host_ids"`
}

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListUsers(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]userView, 0, len(list))
	for _, u := range list {
		ids, err := a.Store.UserHostIDs(r.Context(), u.ID)
		if err != nil {
			apiError(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, userView{User: u, HostIDs: ids})
	}
	jsonOut(w, http.StatusOK, out)
}

type userUpdateInput struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}

func (a *API) userUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r, "id")
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	var in userUpdateInput
	if err = json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if in.Role != "" && in.Role != "admin" && in.Role != "member" {
		apiError(w, http.StatusBadRequest, errors.New("role 只能是 admin 或 member"))
		return
	}
	if in.Status != "" && in.Status != "active" && in.Status != "disabled" {
		apiError(w, http.StatusBadRequest, errors.New("status 只能是 active 或 disabled"))
		return
	}
	u, err := a.Store.UpdateUserRoleStatus(r.Context(), id, in.Role, in.Status)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			apiError(w, http.StatusNotFound, err)
		case errors.Is(err, store.ErrLocalUserProtected):
			apiError(w, http.StatusForbidden, err)
		default:
			apiError(w, http.StatusConflict, err)
		}
		return
	}
	jsonOut(w, http.StatusOK, u)
}

func (a *API) userDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r, "id")
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if err = a.Store.DeleteUser(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			apiError(w, http.StatusNotFound, err)
		case errors.Is(err, store.ErrLocalUserProtected):
			apiError(w, http.StatusForbidden, err)
		default:
			apiError(w, http.StatusConflict, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) userHosts(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r, "id")
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	ids, err := a.Store.UserHostIDs(r.Context(), id)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"host_ids": ids})
}

type userHostsInput struct {
	HostIDs []int64 `json:"host_ids"`
}

func (a *API) userHostsSet(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r, "id")
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	var in userHostsInput
	if err = json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	hostIDs, err := a.Store.ValidateHostIDs(r.Context(), in.HostIDs)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if err = a.Store.SetUserHosts(r.Context(), id, hostIDs); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"host_ids": hostIDs})
}
