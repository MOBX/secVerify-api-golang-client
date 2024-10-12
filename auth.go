package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"time"
)

var (
	url       = "http://identify-auth.zztfly.com/auth/auth/sdkClientFreeLogin"
	appkey    = ""
	appSecret = ""
	token     = "59616292321333248"
	opToken   = "opToken"
	operator  = "CUCC"
	md5str    = ""
)

type Login struct {
	Status int         `json:"status"`
	Error  string      `json:"error"`
	Res    interface{} `json:"res"`
}

type ResData struct {
	Phone string `json:"phone"`
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, []byte("00000000"))
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte("00000000"))
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

var Base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func Base64Encode(src []byte) []byte {
	var coder *base64.Encoding
	coder = base64.NewEncoding(Base)
	return []byte(coder.EncodeToString(src))
}

func Base64Decode(src []byte) ([]byte, error) {
	var coder *base64.Encoding
	coder = base64.NewEncoding(Base)
	return coder.DecodeString(string(src))
}

func generateSign(request map[string]interface{}, secret string) string {
	ret := ""
	var keys []string
	for k := range request {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ret = ret + fmt.Sprintf("%v=%v&", k, request[k])
	}
	ret = ret[:len(ret)-1] + secret

	md5Ctx := md5.New()
	md5Ctx.Write([]byte(ret))
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func HttpPostBody(url string, msg []byte) ([]byte, error) {
	resp, err := http.Post(url, "application/json;charset=utf-8", bytes.NewBuffer(msg))
	if err != nil {
		return []byte(""), err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}

func main() {
	//encrypt, _ := DesEncrypt([]byte("123456"), []byte("b89d2427a3bc7ad1aea1e1e8c1d36bf3")[0:8])
	//encode := Base64Encode(encrypt)
	//fmt.Println(string(encode))
	//s := "ne5MoL97ZW2kbWVSApn900JeOgjhg3TPGG4hMacY0uVMV/su4HFnvg=="
	//decode, _ := Base64Decode([]byte(s))
	//decr, _ := DesDecrypt(decode, []byte("b89d2427a3bc7ad1aea1e1e8c1d36bf3")[0:8])
	//fmt.Println(string(decr))
	//fmt.Println(string(Base64Encode([]byte("123456"))))

	data := map[string]interface{}{
		"appkey":    appkey,
		"token":     token,
		"opToken":   opToken,
		"operator":  operator,
		"timestamp": time.Now().Unix(),
	}
	data["sign"] = generateSign(data, appSecret)
	b, _ := json.Marshal(data)
	postBody, _ := HttpPostBody(url, b)

	ret := new(Login)
	res := new(ResData)
	json.Unmarshal(postBody, &ret)

	if ret.Status == 200 {
		decode, _ := Base64Decode([]byte(ret.Res.(string)))
		decr, _ := DesDecrypt(decode, []byte(appSecret)[0:8])
		json.Unmarshal(decr, &res)
		ret.Res = res
	}
	fmt.Printf("%v\n", ret)
}
