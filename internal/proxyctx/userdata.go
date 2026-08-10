package proxyctx

import (
	"bytes"

	"github.com/elazarl/goproxy"
)

type userData map[string]any

// GetValue retrieves a value from the user data store
func GetValue(proxyCtx *goproxy.ProxyCtx, key string) (any, bool) {
	ud, ok := proxyCtx.UserData.(userData)
	if !ok {
		return nil, false
	}

	val, ok := ud[key]
	return val, ok
}

// GetBool retrieves a boolean value from the user data store
func GetBool(proxyCtx *goproxy.ProxyCtx, key string) (bool, bool) {
	val, ok := GetValue(proxyCtx, key)
	if !ok {
		return false, false
	}

	boolVal, ok := val.(bool)
	return boolVal, ok
}

// GetBuffer retrieves a bytes.Buffer value from the user data store
func GetBuffer(proxyCtx *goproxy.ProxyCtx, key string) (*bytes.Buffer, bool) {
	val, ok := GetValue(proxyCtx, key)
	if !ok {
		return nil, false
	}

	bufVal, ok := val.(*bytes.Buffer)
	return bufVal, ok
}

// SetValue sets a value in the user data store
func SetValue(proxyCtx *goproxy.ProxyCtx, key string, value any) {
	var ud userData
	ud, ok := proxyCtx.UserData.(userData)
	if !ok {
		ud = userData{}
		proxyCtx.UserData = ud
	}

	ud[key] = value
}
