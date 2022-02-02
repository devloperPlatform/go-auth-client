package utils

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/devloperPlatform/go-coder-utils/coder"
)

func DataEncrypt(publicKeyPem string, data []byte) (string, error) {
	sm4Key := coder.Sm4RandomKey()
	encryptData, err := coder.Sm4Encrypt(sm4Key, data)
	if err != nil {
		return "", errors.New("加密数据失败: " + err.Error())
	}

	encryptKey, err := coder.Sm2Encrypt(publicKeyPem, sm4Key)
	if err != nil {
		return "", errors.New("传输秘钥加密失败: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(bytes.Join([][]byte{encryptKey, encryptData}, nil)), nil
}

func DataDecrypt(privateKeyPem, encryptB64Data string) ([]byte, error) {
	encryptDataBytes, err := base64.StdEncoding.DecodeString(encryptB64Data)
	if err != nil {
		return nil, errors.New("数据格式转换错误")
	}

	encryptSm4Key := encryptDataBytes[:113]
	encryptData := encryptDataBytes[113:]

	sm4Key, err := coder.Sm2Decrypt(privateKeyPem, encryptSm4Key)
	if err != nil {
		return nil, errors.New("解析传输秘钥失败: " + err.Error())
	}

	srcData, err := coder.Sm4Decrypt(sm4Key, encryptData)
	if err != nil {
		return nil, errors.New("数据解密失败: " + err.Error())
	}

	return srcData, nil
}
