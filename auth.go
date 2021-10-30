package auth

import (
	"bytes"
	"coder.byzk.cn/golibs/common/logs"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/devloperPlatform/go-auth-client/pb"
	"github.com/devloperPlatform/go-base-utils/commonvos"
	"github.com/devloperPlatform/go-coder-utils/coder"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Service struct {
	ServerHost string
	SysToken   string
	PriKeyPem  string
	PubKeyPem  string
}

func New(serverHost, sysToken, priKeyPem, pubKeyPem string) *Service {
	return &Service{
		ServerHost: serverHost,
		SysToken:   sysToken,
		PriKeyPem:  priKeyPem,
		PubKeyPem:  pubKeyPem,
	}
}

func (this *Service) Auth(userToken string) ([]byte, error) {
	if this.SysToken == "" {
		return nil, errors.New("缺失应用token")
	}

	if userToken == "" {
		return nil, errors.New("缺失用户token")
	}

	sm4Key := coder.Sm4RandomKey()
	userTokenEncrypt, err := coder.Sm4Encrypt(sm4Key, []byte(userToken))
	if err != nil {
		logs.Errorf("用户token[%s]加密失败, 错误信息: %s", userToken, err.Error())
		return nil, errors.New("转换用户Token内容格式失败")
	}

	sm4EncKey, err := coder.Sm2Encrypt(this.PubKeyPem, sm4Key)
	if err != nil {
		logs.Errorf("加密SM4秘钥失败, 错误信息: %s", err.Error())
		return nil, errors.New("数据格式转换失败")
	}

	sm4Md5Sum := md5.Sum(sm4EncKey)
	sysTokenEncrypt, err := coder.Sm4Encrypt(sm4Md5Sum[:], []byte(this.SysToken))
	if err != nil {
		logs.Errorf("加密应用token[%s]失败, 错误信息: %s", this.SysToken, err.Error())
		return nil, errors.New("转换数据格式失败")
	}

	sendDataBytes := bytes.Join([][]byte{
		sm4EncKey,
		userTokenEncrypt,
		sysTokenEncrypt,
	}, nil)

	sendData := base64.StdEncoding.EncodeToString(sendDataBytes)

	dial, err := grpc.Dial(this.ServerHost, grpc.WithInsecure())
	if err != nil {
		return nil, errors.New("认证服务连接失败")
	}
	defer dial.Close()

	client := pb.NewAuthServiceClient(dial)
	res, err := client.Auth(context.Background(), wrapperspb.String(sendData))
	if err != nil {
		return nil, convertGrpcErr2Err(err)
	}

	resBytes, err := base64.StdEncoding.DecodeString(res.Value)
	if err != nil {
		logs.Errorf("认证结果[%s], base64解码失败, 错误信息: %s", res.Value, err.Error())
		return nil, errors.New("转换认证结果数据格式失败")
	}

	resEncSm4Key := resBytes[:113]
	resEncData := resBytes[113:]

	resSm4Key, err := coder.Sm2Decrypt(this.PriKeyPem, resEncSm4Key)
	if err != nil {
		logs.Errorf("认证结果SM4秘钥解密失败, 错误信息: %s", err.Error())
		return nil, errors.New("认证结果数据转换失败")
	}

	resDataBytes, err := coder.Sm4Decrypt(resSm4Key, resEncData)
	if err != nil {
		return nil, errors.New("认证结果格式转换失败")
	}

	return resDataBytes, nil
}

func (this *Service) AuthAndResToUserInfo(userToken string) (*commonvos.InsideUserInfo, error) {
	res, err := this.Auth(userToken)
	if err != nil {
		return nil, err
	}

	userInfo := &commonvos.InsideUserInfo{}
	if err = json.Unmarshal(res, &userInfo); err != nil {
		return nil, errors.New("转换用户信息失败: " + err.Error())
	}
	return userInfo, nil
}

func convertGrpcErr2Err(err error) error {
	if err == nil {
		return err
	}
	s := status.Convert(err)
	if s == nil {
		return err
	}

	return errors.New(s.Message())
}
