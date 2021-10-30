package auth

import (
	"coder.byzk.cn/golibs/common/logs"
	"fmt"
	"testing"
)

func TestService_AuthAndResToUserInfo(t *testing.T) {
	authService := New("127.0.0.1:8080", "67538f92d1475f13b1994a29f62da33d", `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQglYYt+3XPO+FwZXiG
UyX+nFkF3OgkXeYoWGtuTyjw/36gCgYIKoEcz1UBgi2hRANCAARqy2fdrDz3J2lN
m3fgrevryYyUdnotSHqikpIaRWn58Bh5aND3HlzxujqDlW/dj8bWgxu3uTH+GaS7
wlz+hjcL
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEIpps11gY9bA3pfgSfgzX2Vitg7QP
TShCb33gZKWIY5f0QIBSzJf+b4gH3BTIyrOPx7NIvONGrrq5MENzyngKjQ==
-----END PUBLIC KEY-----`)

	userInfo, err := authService.AuthAndResToUserInfo("1234567890987654")
	if err != nil {
		logs.Errorln(err.Error())
		return
	}

	fmt.Println(userInfo.Name)
}
