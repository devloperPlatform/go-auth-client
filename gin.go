package auth

import (
	"github.com/devloperPlatform/go-base-utils/commonvos"
	"github.com/gin-gonic/gin"
)

type UserAuthFun func(user *commonvos.InsideUserInfo, ctx *gin.Context)

type GinAuthExtend struct {
	engine              *gin.Engine
	userTokenHeaderName string
	authService         *Service
	ignoreUrl           map[string]bool
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

func (this *GinAuthExtend) init() {
	this.engine.Use(this.middle())
}

func (this *GinAuthExtend) middle() gin.HandlerFunc {
	return func(context *gin.Context) {
		if _, ok := this.ignoreUrl[context.Request.RequestURI]; ok {
			context.Next()
			return
		}
		userToken := context.GetHeader(this.userTokenHeaderName)
		if userToken == "" {
			context.JSON(401, &gin.H{
				"message": "未识别的用户令牌",
			})
			context.Abort()
			return
		}

		auth, err := this.authService.AuthAndResToUserInfo(userToken)
		if err != nil {
			context.JSON(401, &gin.H{
				"message": err.Error(),
			})
			context.Abort()
			return
		}

		context.Set("nowUser", auth)
		context.Next()
	}
}

func (this *GinAuthExtend) Wrapper(fn UserAuthFun) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		nowUserInfo, exists := ctx.Get("nowUser")
		if !exists {
			ctx.JSON(401, "获取用户信息失败")
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
