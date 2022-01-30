package auth

import (
	"coder.byzk.cn/golibs/common/logs"
	"encoding/json"
	"github.com/devloperPlatform/go-base-utils/commonvos"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type UserAuthFun func(user *commonvos.InsideUserInfo, ctx *gin.Context)

type GinAuthExtend struct {
	engine              *gin.Engine
	userTokenHeaderName string
	tokenGetFn          func(ctx *gin.Context) string
	authService         *Service
	ignoreUrl           map[string]bool
	ignoreFn            func(context *gin.Context) bool
}

func NewGinAuthExtend(engine *gin.Engine, userTokenHeaderName string, authService *Service) *GinAuthExtend {
	authExtend := &GinAuthExtend{
		engine:              engine,
		userTokenHeaderName: userTokenHeaderName,
		authService:         authService,
		ignoreUrl:           make(map[string]bool),
	}
	authExtend.init()
	return authExtend
}

func (this *GinAuthExtend) IgnoreUrl(url string) *GinAuthExtend {
	this.ignoreUrl[url] = true
	return this
}

func (this *GinAuthExtend) IgnoreFn(fn func(context *gin.Context) bool) *GinAuthExtend {
	this.ignoreFn = fn
	return this
}

func (this *GinAuthExtend) TokenGetFn(fn func(ctx *gin.Context) string) *GinAuthExtend {
	this.tokenGetFn = fn
	return this
}

func (this *GinAuthExtend) init() {
	this.engine.Use(this.middle())
}

func (this *GinAuthExtend) middle() gin.HandlerFunc {
	return func(context *gin.Context) {
		logs.Debugln("进入鉴权拦截器, 将要被鉴权的路径: ", context.Request.RequestURI)
		if this.ignoreFn != nil {
			if this.ignoreFn(context) {
				goto IgnoreOK
			} else {
				goto BreakIgnore
			}
		}
		if _, ok := this.ignoreUrl[context.Request.URL.Path]; !ok {
			goto BreakIgnore
		}
	IgnoreOK:
		logs.Debugln("检测到该路径为忽略权限路径, 跳过权限认证")
		context.Set("ignore", true)
		context.Next()
		return
	BreakIgnore:
		var userToken string
		if this.tokenGetFn != nil {
			userToken = this.tokenGetFn(context)
		} else {
			userToken = context.GetHeader(this.userTokenHeaderName)
		}
		if userToken == "" {
			logs.Debugln("获取客户端用户Token失败")
			context.JSON(401, &gin.H{
				"message": "未识别的用户令牌",
			})
			context.Abort()
			return
		}

		logs.Debugln("客户端Token: ", userToken)
		auth, err := this.authService.AuthAndResToUserInfo(userToken)
		if err != nil {
			logs.Debugln("从认证中心获取客户端Token失败")
			context.JSON(401, &gin.H{
				"message": err.Error(),
			})
			context.Abort()
			return
		}

		if logs.CurrentLevel() == logrus.DebugLevel {
			marshal, _ := json.Marshal(auth)
			logs.Debugf("从认证中心获取到的用户信息: ", string(marshal))
		}
		context.Set("nowUser", auth)
		context.Next()
	}
}

func (this *GinAuthExtend) Wrapper(fn UserAuthFun) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		if _, exists := ctx.Get("ignore"); exists {
			fn(nil, ctx)
			return
		}
		nowUserInfo, exists := ctx.Get("nowUser")
		if !exists {
			ctx.JSON(401, "获取用户信息失败")
			return
		}

		if info, ok := nowUserInfo.(commonvos.InsideUserInfo); ok {
			fn(&info, ctx)
			return
		}

		if info, ok := nowUserInfo.(*commonvos.InsideUserInfo); ok {
			fn(info, ctx)
			return
		}

	}
}

func (this *GinAuthExtend) GET(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.GET(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) POST(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.POST(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) DELETE(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.DELETE(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) PATCH(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.PATCH(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) PUT(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.PUT(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) OPTIONS(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.OPTIONS(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) HEAD(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.HEAD(realPath, this.Wrapper(fn))
	return this
}

func (this *GinAuthExtend) Any(realPath string, fn UserAuthFun) *GinAuthExtend {
	this.engine.Any(realPath, this.Wrapper(fn))
	return this
}
