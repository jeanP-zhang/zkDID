package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fabric-did/did"
	"fabric-did/tools"
	"fmt"
	"testing"
	"time"
)

const ZkServerUrl = "http://localhost:8081/birth/"

var Issuer = make([]string, 0)

func TestCreatDid(t *testing.T) {
	d := did.CreateDid()
	marshal, _ := json.Marshal(d)
	fmt.Printf("%s", marshal)
}

func TestIssuerAdd(t *testing.T) {
	Issuer = append(Issuer, "did:example:061dce1b6e87f6ff110d50cf2ce5bd98")
	fmt.Printf("Issuer:%#v \n", Issuer)
}

func TestVC(t *testing.T) {
	//user commit
	commitUrl := ZkServerUrl + "commit"
	paras := make(map[string]interface{})
	paras["name"] = "zhangsan"
	paras["date"] = 2000
	personCom := tools.HTTPPostJson(commitUrl, paras)

	//issue
	issueUrl := ZkServerUrl + "issue"
	resBody := tools.HTTPPost(issueUrl, personCom)
	var issueResult did.IssueResult
	_ = json.Unmarshal([]byte(resBody), &issueResult)

	//user proof
	userProofUrl := ZkServerUrl + "userProof"
	paras = make(map[string]interface{})
	birth := make(map[string]interface{})
	birth["name"] = "zhangsan"
	birth["date"] = 2020
	paras["birth"] = birth
	paras["authPath"] = issueResult.AuthPath
	personProof := tools.HTTPPostJson(userProofUrl, paras)

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
		ID:           "did:example:123",
		PersonCommit: personCom,
	}
	now := time.Now().UnixMilli()
	//create issuer
	issuer := did.CreateDid()
	proof := did.ZKProof{
		Creator:     issuer.ID,
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
		Issuer:            issuer.ID,
		IssuanceDate:      now,
		ExpirationDate:    now + 60000,
		CredentialSubject: credentialSubject,
		Proof:             proof,
		VerifyingKeys:     verifyingKeys,
	}
	fmt.Printf("Create VC success:%#v \n", vc)

	//验证
	verifyUrl := ZkServerUrl + "verify"
	paras = make(map[string]interface{})
	paras["personCom"] = credentialSubject.PersonCommit
	paras["forestRoots"] = proof.ForestRoots
	paras["forestProof"] = proof.ForestProof
	paras["treeProof"] = proof.TreeProof
	paras["merkleRoot"] = proof.MerkleRoot
	paras["personProof"] = personProof
	paras["vks"] = verifyingKeys
	resBody = tools.HTTPPostJson(verifyUrl, paras)
	var verifyResult did.VerifyResult
	_ = json.Unmarshal([]byte(resBody), &verifyResult)
	fmt.Println("验证结果：", verifyResult.Result)
}

func TestEd25519(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	msg := "abc123"

	msgByte := []byte(msg)

	// 进行ed25519签名
	signature := ed25519.Sign(privateKey, msgByte)

	// 使用公钥进行验签
	verify := ed25519.Verify(publicKey, msgByte, signature)

	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
	privateKeyStr := base64.StdEncoding.EncodeToString(privateKey)
	id := tools.Base58Encode(publicKey)
	fmt.Println("公钥：", publicKeyStr)
	fmt.Println("id：", string(id))
	fmt.Println("私钥", privateKeyStr)
	fmt.Println("签名", signature)
	fmt.Println("验签结果：", verify)

}

//5yd8aSTtsrxcDesuqt99D1eVe4kXyAN9poniGBbvw2MmUjGED1yNeiAAiAMx84DVLPhFRpoaHBhEXWAH2d39AH5z
func TestSign(t *testing.T) {
	sk := "3kVUswJ29uHo6L6mqBjw5kKhrATzbLcvibTCr95NLXQhWwhDzDTdWNczgLH9Y71Ga58oQP89GRzVAK3DwRdr71Ae"
	privateKey := tools.Base58Decode([]byte(sk))
	fmt.Printf("privateKey: %v\n", privateKey)
	msg := "XfMUg5lQkI55WRI2hWZZYHyu0pl3n6cG"

	msgByte := []byte(msg)

	// 进行ed25519签名
	signature := ed25519.Sign(privateKey, msgByte)
	sign := tools.Base58Encode(signature)
	fmt.Printf("签名: %s\n", string(sign))

}

func TestSign2(t *testing.T) {
	//ed25519椭圆曲线生成公私钥
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Printf("privateKey: %v\n", privateKey)
	res := base64.StdEncoding.EncodeToString(privateKey)
	fmt.Println(res)
}

func TestVerify(t *testing.T) {
	random := "F8HPrnq5UA3YDQBJa26MKXtIaq71WWa1"
	signature := tools.Base58Decode([]byte("2xbn2NbdzckNPhoGioXxrxbz8Zu7h1F2Ky9bCmbVzKd7A3ZyVP1co8bcwGQaum6tFgoQKtFpmAiVXBdyYU5UHd9z"))
	result, err := tools.QueryChaincode("did", "SearchDID", "did:example:1LziBpYtTf6Ay15fCDHLgiSRpEH4sATafj")
	if err != nil {
		fmt.Printf("DID不存在")
		return
	}
	var d did.DID
	err = json.Unmarshal(result, &d)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}
	publicKey := tools.Base58Decode([]byte(d.Authentication.PublicKeyMultibase))
	// 使用公钥进行验签
	verify := ed25519.Verify(publicKey, []byte(random), signature)
	fmt.Printf("verify: %v\n", verify)

}

func TestVerify2(t *testing.T) {
	// 生成公私钥
	var publicKey []byte

	var msg = "This is the fourth demo"

	msgByte := []byte(msg)

	// 进行ed25519签名
	//signature := ed25519.Sign(privateKey, msgByte)
	signature, _ := base64.RawURLEncoding.DecodeString("aqLhgTTxKXTmBS/nBXhNKPh6mlo5BMzxhRuhVL+jsIQ66T3oXuWxnywXwX1eZ7cvBNxW2T7R9MNPSWpDV5/7AA==")
	publicKey, _ = base64.RawURLEncoding.DecodeString("MCowBQYDK2VwAyEA84kvLGBxlUSKa2hLlBM7ZuSt/+F/gc0lomfN9WjULuM=")
	// 使用公钥进行验签
	verify := ed25519.Verify(publicKey, msgByte, signature)

	fmt.Println("公钥：", publicKey)
	fmt.Println("签名", signature)
	fmt.Println("验签结果：", verify)

}
