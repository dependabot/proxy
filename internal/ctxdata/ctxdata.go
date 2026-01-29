package ctxdata

import (
	"bytes"

	"github.com/elazarl/goproxy"
)

type userData map[string]interface{}

// GetValue retrieves a value from the user data store
func GetValue(ctx *goproxy.ProxyCtx, key string) (interface{}, bool) {
	ud, ok := ctx.UserData.(userData)
	if !ok {
		return nil, false
	}

	val, ok := ud[key]
	return val, ok
}

// GetBool retrieves a boolean value from the user data store
func GetBool(ctx *goproxy.ProxyCtx, key string) (bool, bool) {
	val, ok := GetValue(ctx, key)
	if !ok {
		return false, false
	}

	boolVal, ok := val.(bool)
	return boolVal, ok
}

// GetBuffer retrieves a bytes.Buffer value from the user data store
func GetBuffer(ctx *goproxy.ProxyCtx, key string) (*bytes.Buffer, bool) {
	val, ok := GetValue(ctx, key)
	if !ok {
		return nil, false
	}

	bufVal, ok := val.(*bytes.Buffer)
	return bufVal, ok
}

// SetValue sets a value in the user data store
func SetValue(ctx *goproxy.ProxyCtx, key string, value interface{}) {
	var ud userData
	ud, ok := ctx.UserData.(userData)
	if !ok {
		ud = userData{}
		ctx.UserData = ud
	}

	ud[key] = value
}
