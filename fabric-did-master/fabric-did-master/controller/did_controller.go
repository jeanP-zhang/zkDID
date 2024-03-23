package controller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fabric-did/did"
	"fabric-did/tools"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"time"
)

var USER_PROOF_STATIC = make(map[string]interface{})

func GenKeys(c *gin.Context) {
	//ed25519椭圆曲线生成公私钥
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publicKeyBase58 := tools.Base58Encode(publicKey)
	//私钥链下存储
	privateKeyBase58 := tools.Base58Encode(privateKey)
	result := make(map[string]string)
	result["publicKey"] = string(publicKeyBase58)
	result["privateKey"] = string(privateKeyBase58)
	SuccessResult(c, result)
}

func RegisterDID(c *gin.Context) {
	publicKey := c.Request.PostFormValue("publicKey")
	//address由公钥生成
	id := "did:example:" + tools.GetAddress([]byte(publicKey))
	authentication := did.Authentication{
		ID:                 id + "#keys-1",
		Type:               did.KeyType,
		Controller:         id,
		PublicKeyMultibase: publicKey,
	}
	userDID := did.DID{
		ID:             id,
		Authentication: authentication,
	}
	didBytes, _ := json.Marshal(userDID)
	_, _, err := tools.ExecuteChaincode("did", "CreateDID", string(didBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("id: %s \n", userDID.ID)
	fmt.Printf("DID: %s \n", string(didBytes))
	SuccessResult(c, userDID.ID)
}

func SearchVC(c *gin.Context) {
	vcId := c.Query("vcId")
	fmt.Printf("vcId: %s \n", vcId)
	result, _ := tools.QueryChaincode("did", "SearchVC", vcId)
	var out bytes.Buffer
	_ = json.Indent(&out, result, "", "\t")
	SuccessResult(c, out.Bytes())
}

func SearchLatestVC(c *gin.Context) {
	vcId := latestVcId
	fmt.Printf("vcId: %s \n", vcId)
	vcBytes, _ := tools.QueryChaincode("did", "SearchVC", vcId)
	var vc did.VerifiableCredential
	json.Unmarshal(vcBytes, &vc)
	result := make(map[string]interface{})
	result["vcId"] = vcId
	userProof := make(map[string]interface{})
	userProof["name"] = "equal " + latestName
	userProof["age"] = "above 18"
	userProof["points"] = "above 1000"
	result["proof"] = userProof
	res, _ := json.Marshal(result)
	var out bytes.Buffer
	_ = json.Indent(&out, res, "", "\t")
	USER_PROOF_STATIC[vc.ID] = userProof
	SuccessResult(c, out.Bytes())
}

const ZkServerUrl = "http://localhost:8081/birth/"

func CreatePersonCommit(c *gin.Context) {
	commitUrl := ZkServerUrl + "commit"
	name := c.Request.PostFormValue("name")
	age := c.Request.PostFormValue("age")
	jifen := c.Request.PostFormValue("jifen")
	i, _ := strconv.Atoi(age)
	date := 2023 - i
	paras := make(map[string]interface{})
	paras["name"] = name
	paras["date"] = date
	paras["points"] = jifen
	personCom := tools.HTTPPostJson(commitUrl, paras)
	fmt.Printf("personCom: %s \n", personCom)
	SuccessResult(c, personCom)
}

func Issue(c *gin.Context) {
	personCommit := c.Request.PostFormValue("personCommit")
	userId := c.Request.PostFormValue("userId")
	issuerId := c.Request.PostFormValue("issuerId")
	age := c.Request.PostFormValue("age")
	jifen := c.Request.PostFormValue("jifen")
	name := c.Request.PostFormValue("name")
	i, _ := strconv.Atoi(age)
	date := 2023 - i
	if i < 18 {
		FailResult(c, "person proof failed")
		return
	}
	jifenInt, _ := strconv.Atoi(jifen)
	if jifenInt < 1000 {
		FailResult(c, "person proof failed")
		return
	}
	//issue ZK的凭证
	issueUrl := ZkServerUrl + "issue"
	resBody := tools.HTTPPost(issueUrl, personCommit)
	var issueResult did.IssueResult
	_ = json.Unmarshal([]byte(resBody), &issueResult)

	//get VK
	vksUrl := ZkServerUrl + "vks"
	resBody = tools.HTTPGet(vksUrl)
	var verifyingKeys did.VerifyingKeys
	_ = json.Unmarshal([]byte(resBody), &verifyingKeys)

	//get checker
	ageCheckerUrl := ZkServerUrl + "ageChecker"
	ageChecker := tools.HTTPGet(ageCheckerUrl)

	//saveVC
	credentialSubject := did.CredentialSubject{
		ID:           userId,
		PersonCommit: personCommit,
	}
	now := time.Now().UnixMilli()

	authPath := issueResult.AuthPath
	userProofUrl := ZkServerUrl + "userProof"
	paras := make(map[string]interface{})
	birth := make(map[string]interface{})
	birth["name"] = name
	birth["date"] = date
	paras["birth"] = birth
	paras["authPath"] = authPath
	personProof := tools.HTTPPostJson(userProofUrl, paras)

	//create issuer
	proof := did.ZKProof{
		Creator:      issuerId,
		Type:         did.KeyType,
		Created:      now,
		ForestRoots:  issueResult.ForestRoots,
		ForestProof:  issueResult.ForestProof,
		TreeProof:    issueResult.TreeProof,
		MerkleRoot:   issueResult.MerkleRoot,
		AgeChecker:   ageChecker,
		PersonCommit: personCommit,
		PersonProof:  personProof,
	}
	vc := did.VerifiableCredential{
		ID:                tools.GetUUID(),
		Type:              []string{did.VCType, did.VCTypeAge},
		Issuer:            issuerId,
		IssuanceDate:      now,
		ExpirationDate:    now + 1000*60*60*24*365,
		CredentialSubject: credentialSubject,
		Proof:             proof,
		VerifyingKeys:     verifyingKeys,
	}
	fmt.Printf("Create VC success:%#v \n", vc)
	vcBytes, _ := json.Marshal(vc)
	_, _, _ = tools.ExecuteChaincode("did", "CreateVC", userId, issuerId, string(vcBytes))

	result := make(map[string]interface{})
	result["vc"] = vc
	userProof := make(map[string]interface{})
	userProof["name"] = "equal " + name
	userProof["age"] = "above 18"
	userProof["points"] = "above 1000"
	result["userProof"] = userProof

	latestVcId = vc.ID
	latestName = name
	USER_PROOF_STATIC[vc.ID] = userProof
	SuccessResult(c, result)
}

func CreateVC(c *gin.Context) {
	commitUrl := ZkServerUrl + "commit"
	userId := c.Request.PostFormValue("userId")
	name := c.Request.PostFormValue("name")
	age := c.Request.PostFormValue("age")
	i, _ := strconv.Atoi(age)
	if i < 18 {
		FailResult(c, "person proof failed")
		return
	}
	date := 2023 - i
	jifen := c.Request.PostFormValue("jifen")
	jifenInt, _ := strconv.Atoi(jifen)
	if jifenInt < 1000 {
		FailResult(c, "person proof failed")
		return
	}
	paras := make(map[string]interface{})
	paras["name"] = name
	paras["date"] = date
	paras["points"] = jifen
	personCom := tools.HTTPPostJson(commitUrl, paras)
	fmt.Printf("personCom: %s \n", personCom)

	personCommit := personCom
	issuerId := "did:example:0000000000000000000000000000000000"
	//issue ZK的凭证
	issueUrl := ZkServerUrl + "issue"
	resBody := tools.HTTPPost(issueUrl, personCommit)
	var issueResult did.IssueResult
	_ = json.Unmarshal([]byte(resBody), &issueResult)

	//get VK
	vksUrl := ZkServerUrl + "vks"
	resBody = tools.HTTPGet(vksUrl)
	var verifyingKeys did.VerifyingKeys
	_ = json.Unmarshal([]byte(resBody), &verifyingKeys)

	//get checker
	ageCheckerUrl := ZkServerUrl + "ageChecker"
	ageChecker := tools.HTTPGet(ageCheckerUrl)

	//saveVC
	credentialSubject := did.CredentialSubject{
		ID:           userId,
		PersonCommit: personCommit,
	}
	now := time.Now().UnixMilli()
	//create issuer
	proof := did.ZKProof{
		Creator:     issuerId,
		Type:        did.KeyType,
		Created:     now,
		ForestRoots: issueResult.ForestRoots,
		ForestProof: issueResult.ForestProof,
		TreeProof:   issueResult.TreeProof,
		MerkleRoot:  issueResult.MerkleRoot,
		AgeChecker:  ageChecker,
	}
	vc := did.VerifiableCredential{
		ID:                tools.GetUUID(),
		Type:              []string{did.VCType, did.VCTypeAge},
		Issuer:            issuerId,
		IssuanceDate:      now,
		ExpirationDate:    now + 1000*60*60*24*365,
		CredentialSubject: credentialSubject,
		Proof:             proof,
		VerifyingKeys:     verifyingKeys,
	}
	fmt.Printf("Create VC success:%#v \n", vc)
	vcBytes, _ := json.Marshal(vc)
	_, _, _ = tools.ExecuteChaincode("did", "CreateVC", userId, issuerId, string(vcBytes))

	authPath := issueResult.AuthPath
	userProofUrl := ZkServerUrl + "userProof"
	paras = make(map[string]interface{})
	birth := make(map[string]interface{})
	birth["name"] = name
	birth["date"] = date
	paras["birth"] = birth
	paras["authPath"] = authPath
	personProof := tools.HTTPPostJson(userProofUrl, paras)
	if personProof == "" {
		FailResult(c, "person proof failed")
		return
	}
	fmt.Printf("personProof: %s \n", personProof)
	result := make(map[string]interface{})
	result["vcId"] = vc.ID
	//result["vc"] = string(vcBytes)
	//result["personCommit"] = personCommit
	userProof := make(map[string]interface{})
	userProof["name"] = "equal " + name
	userProof["age"] = "above 18"
	userProof["points"] = "above 1000"
	result["proof"] = userProof
	res, _ := json.Marshal(result)
	var out bytes.Buffer
	_ = json.Indent(&out, res, "", "\t")
	USER_PROOF_STATIC[vc.ID] = userProof
	SuccessResult(c, out.Bytes())
}

//返回数据结构体
type Result struct {
	Success bool        `json:"success"` //成功true，失败false
	Message string      `json:"message"` //消息
	Data    interface{} `json:"data"`    //数据
}

//接口调用成功统一调用
func SuccessResult(c *gin.Context, data interface{}) {
	result := Result{
		Success: true,
		Message: "",
		Data:    data,
	}
	//如果是byte类型，转string
	value, ok := data.([]byte)
	if ok {
		result.Data = string(value)
	}
	c.JSON(http.StatusOK, result)
}

func FailResult(c *gin.Context, msg string) {
	result := Result{
		Success: false,
		Message: msg,
	}
	c.JSON(http.StatusOK, result)
}
