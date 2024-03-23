package controller

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fabric-did/did"
	"fabric-did/tools"
	"fmt"
	"github.com/gin-gonic/gin"
	qrcode "github.com/skip2/go-qrcode"
	"math/rand"
	"time"
)

var strStorage map[string]string
var latestVcId = "b629f8e3492d1ed2c4a95c348774ed72"
var latestDid string
var latestName string

func init() {
	strStorage = make(map[string]string)
}

func GenQrcode(c *gin.Context) {
	//random string
	random := RandStr(32)

	encode, err := qrcode.Encode(random, qrcode.Medium, 256)
	fmt.Printf("qrcode: %s \n", random)
	strStorage[random] = ""
	if err != nil {
		return
	}
	_, err = c.Writer.Write(encode)
	if err != nil {
		return
	}
}

func GenQrcodeBase64(c *gin.Context) {
	//random string
	random := RandStr(32)

	encode, _ := qrcode.Encode(random, qrcode.Medium, 256)
	fmt.Printf("qrcode: %s \n", random)
	strStorage[random] = ""
	imageBase64 := base64.StdEncoding.EncodeToString(encode)
	result := make(map[string]string)
	result["imageBase64"] = imageBase64
	result["random"] = random
	SuccessResult(c, result)
}

func Login(c *gin.Context) {
	sign := c.PostForm("sign")
	vcId := c.PostForm("vcId")
	didUri := c.PostForm("did")
	random := c.PostForm("random")
	_, ok := strStorage[random]
	if !ok {
		FailResult(c, "二维码不存在")
		return
	}

	//delete(strStorage, random)
	fmt.Printf("signature: %s \n", sign)
	fmt.Printf("didUri: %s \n", didUri)
	fmt.Printf("vcId: %s \n", vcId)
	fmt.Printf("random: %s \n", random)
	signature := tools.Base58Decode([]byte(sign))
	result, err := tools.QueryChaincode("did", "SearchDID", didUri)
	if err != nil {
		FailResult(c, "DID不存在")
		return
	}
	var d did.DID
	err = json.Unmarshal(result, &d)
	if err != nil {
		FailResult(c, err.Error())
		return
	}
	publicKey := tools.Base58Decode([]byte(d.Authentication.PublicKeyMultibase))
	fmt.Printf("PublicKey: %s \n", d.Authentication.PublicKeyMultibase)
	// 使用公钥进行验签
	verify := ed25519.Verify(publicKey, []byte(random), signature)
	if verify {
		strStorage[random] = vcId
		latestDid = didUri
		latestVcId = vcId
	}
	SuccessResult(c, verify)
}

func Sign(c *gin.Context) {
	//由于golang和java的ed25519的签名方法无法互通
	//共钥传输过程中，无论是base64还是base58，都无法正常恢复
	//先采用接口签名测试，之后互通了会删除此方法
	sk := c.PostForm("sk")
	msg := c.PostForm("msg")
	privateKey := tools.Base58Decode([]byte(sk))
	msgByte := []byte(msg)
	// 进行ed25519签名
	signature := ed25519.Sign(privateKey, msgByte)
	fmt.Printf("signature: %s \n", string(tools.Base58Encode(signature)))
	_, err := c.Writer.Write(tools.Base58Encode(signature))
	if err != nil {
		return
	}
}

func LoginCheck(c *gin.Context) {
	random := c.PostForm("random")
	_, ok := strStorage[random]
	if !ok {
		FailResult(c, "二维码不存在")
		return
	}
	vcId := strStorage[random]
	if vcId == "" {
		FailResult(c, "用户还未登录")
		return
	}
	if vcId == "0" {
		res := make(map[string]interface{})
		res["did"] = latestDid
		res["hasVc"] = false
		SuccessResult(c, res)
		return
	}
	result, err := tools.QueryChaincode("did", "SearchVC", vcId)
	if err != nil {
		FailResult(c, "vc不存在")
		return
	}
	var vc did.VerifiableCredential
	err = json.Unmarshal(result, &vc)
	if err != nil {
		FailResult(c, err.Error())
		return
	}
	userProof := USER_PROOF_STATIC[vc.ID]
	res := make(map[string]interface{})
	res["vc"] = vc
	res["hasVc"] = true
	res["did"] = latestDid
	res["userProof"] = userProof
	SuccessResult(c, res)
}

func RandStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}
