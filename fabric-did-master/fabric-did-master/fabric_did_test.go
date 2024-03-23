package main

import (
	"encoding/json"
	"fabric-did/did"
	"fabric-did/tools"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

const chaincode = "did"

func TestInitLedger(t *testing.T) {
	_, _, err := tools.ExecuteChaincode(chaincode, "InitLedger")
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %v \n", true)
}

//user:    did:example:1PhVLNviqBf4WrxRSmupnpdhfe5LvTrWtu
//issuer:  did:example:1LiuAUm1BQWJ3AyasBrBYFou6RZ4AhDDTU
func TestCreateDID(t *testing.T) {
	DID := did.CreateDid()
	didBytes, _ := json.Marshal(DID)
	_, _, err := tools.ExecuteChaincode(chaincode, "CreateDID", string(didBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("id: %s \n", DID.ID)
	fmt.Printf("DID: %s \n", string(didBytes))
	//for {
	//	DID := did.CreateDid()
	//	didBytes, _ := json.Marshal(DID)
	//	_, _, err := tools.ExecuteChaincode("did", "CreateDID", string(didBytes))
	//	if err != nil {
	//		panic(err)
	//	}
	//	time.Sleep(time.Second * 15)
	//}
}

func TestCreateDID2(t *testing.T) {
	for {
		DID := did.CreateDid()
		didBytes, _ := json.Marshal(DID)
		_, _, err := tools.ExecuteChaincode("did", "CreateDID", string(didBytes))
		if err != nil {
			panic(err)
		}
		min := int32(5)  //设置随机数下限
		max := int32(10) //设置随机数上限
		num := rand.Int31n(max-min-1) + min + 1
		time.Sleep(time.Second * time.Duration(num))
	}
}

func TestSearchDID(t *testing.T) {
	result, err := tools.QueryChaincode(chaincode, "SearchDID", "did:example:1LiuAUm1BQWJ3AyasBrBYFou6RZ4AhDDTU")
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %s \n", result)
}

//
//func TestBecomeCandidate(t *testing.T) {
//	DID := "did:example:1A16uzkxSJMDCgx8KBRGxswqs7osmXRZzm"
//	didBytes, err := tools.QueryChaincode(chaincode, "SearchDID", DID)
//	if err != nil {
//		panic("DID doesn't exist")
//	}
//	var d did.DID
//	_ = json.Unmarshal(didBytes, &d)
//
//	issuerListBytes, _ := tools.QueryChaincode(chaincode, "SearchIssuer")
//	var issuerList []string
//	_ = json.Unmarshal(issuerListBytes, &issuerList)
//
//	candidate := did.Candidate{
//		ID:            tools.GetUUID(),
//		DID:           DID,
//		ApproveList:   make([]string, 0),
//		TotalVoterNum: len(issuerList),
//		Result:        false,
//		CreateTime:    time.Now().UnixMilli(),
//		UpdateTime:    time.Now().UnixMilli(),
//	}
//	candidateBytes, _ := json.Marshal(candidate)
//	_, _, err = tools.ExecuteChaincode(chaincode, "BecomeCandidate", string(candidateBytes))
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("candidateId: %s \n", candidate.ID)
//	fmt.Printf("candidate: %s \n", string(candidateBytes))
//}
//
//func TestSearchCandidate(t *testing.T) {
//	result, err := tools.QueryChaincode(chaincode, "SearchCandidate", "d96b3e8f1c45d75b1ebb56a0de2f166d")
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("result: %s \n", result)
//}
//
//func TestVoteCandidate(t *testing.T) {
//	candidateId := "d96b3e8f1c45d75b1ebb56a0de2f166d"
//	issuerId := "did:example:0000000000000000000000000000000000"
//	_, _, err := tools.ExecuteChaincode(chaincode, "VoteCandidate", candidateId, issuerId)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("result: %v \n", true)
//}
//
//func TestSearchIssuer(t *testing.T) {
//	result, err := tools.QueryChaincode(chaincode, "SearchIssuer")
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("result: %s \n", result)
//}

//////////////////////////////////////////////VC

func TestUserCommit(t *testing.T) {
	//user commit
	commitUrl := ZkServerUrl + "commit"
	paras := make(map[string]interface{})
	paras["name"] = "zhangsan"
	paras["date"] = 1999
	personCom := tools.HTTPPostJson(commitUrl, paras)
	fmt.Printf("personCom: %s \n", personCom)
}

func TestCreateVC(t *testing.T) {
	personCommit := "WzIxNSwxMDAsNyw0MiwxOTIsNjEsNTgsMjE2LDIwMCw5LDE3MSwyMjEsMCwxMTYsMjIxLDIxMCwzMSw0MiwyMDIsMjI5LDEzOCwxNjMsNjIsMTE2LDIzOSwxOTEsMTY2LDMyLDIyNCwyMTMsMTUyLDEwM10="
	issuerId := "did:example:0000000000000000000000000000000000"
	userId := "did:example:1LziBpYtTf6Ay15fCDHLgiSRpEH4sATafj"
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
		ExpirationDate:    now + 60000,
		CredentialSubject: credentialSubject,
		Proof:             proof,
		VerifyingKeys:     verifyingKeys,
	}
	fmt.Printf("Create VC success:%#v \n", vc)
	vcBytes, _ := json.Marshal(vc)
	_, _, err := tools.ExecuteChaincode(chaincode, "CreateVC", userId, issuerId, string(vcBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("vc: %s \n", string(vcBytes))
	fmt.Printf("vcId: %#v \n", vc.ID)
	fmt.Printf("result: %v \n", true)
	fmt.Printf("AuthPath: %v \n", issueResult.AuthPath)
	//return authPath
}

//74387c183669bddbf81f902d37da7da9

func TestSearchVC(t *testing.T) {
	result, err := tools.QueryChaincode(chaincode, "SearchVC", "3f9ede1761676037e341300bf638b734")
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %s \n", result)
}

//链下
func TestUserProof(t *testing.T) {
	authPath := "WzMyLDAsMCwwLDAsMCwwLDAsMjE1LDEwMCw3LDQyLDE5Miw2MSw1OCwyMTYsMjAwLDksMTcxLDIyMSwwLDExNiwyMjEsMjEwLDMxLDQyLDIwMiwyMjksMTM4LDE2Myw2MiwxMTYsMjM5LDE5MSwxNjYsMzIsMjI0LDIxMywxNTIsMTAzLDMyLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDEsMCwwLDAsMCwwLDAsMCwxMjcsMjI1LDM1LDk1LDgxLDIwMyw4NSwxMjAsMjE2LDIzNSwxMDMsMjIyLDE3NywxMDAsODgsMTA0LDI1NSwxNjEsMjM3LDIyLDE3OCwxNzUsOTEsOTgsMjYsMjUzLDc3LDExMiwxNSwxMTgsMTkzLDIsMjQ1LDEzMyw5OSwzNSwzOSw3MCwyMTgsMTMyLDQwLDQ3LDUzLDEsMTkxLDI0MiwxMTUsNywxNzAsMTgwLDE1NiwxODksNjcsMTkxLDg0LDU1LDIwNCwxOTMsMTA1LDI1NCwxMjEsMjIsMTY2LDI4LDE2LDE4NCwxNTYsMjAwLDE3MCwxMzksNzUsMTA1LDE5NSwyNCw4OCwxNzcsMTkwLDEzOCw2MywyNDMsMTg5LDE1OCwxNzcsMjAwLDUyLDE4NywyNiw0NiwxMzAsMzAsMTY4LDEwNiw5NiwyMSwyMjcsMjRd"
	userProofUrl := ZkServerUrl + "userProof"
	paras := make(map[string]interface{})
	birth := make(map[string]interface{})
	birth["name"] = "zhangsan"
	birth["date"] = 1999
	paras["birth"] = birth
	paras["authPath"] = authPath
	personProof := tools.HTTPPostJson(userProofUrl, paras)
	fmt.Printf("personProof: %s \n", personProof)
}

func TestCheckVC(t *testing.T) {
	verifyUrl := ZkServerUrl + "verify"
	personProof := "WzE2MywxMTEsNjIsMywxMCw5MCw1MywxMzgsNDgsNjYsMjMzLDE1Miw2Niw5MiwxODcsMjQ1LDQzLDIxOSw2MCwxLDEyLDc5LDE4Miw5NSwyMDMsNDQsMjI0LDQ0LDMyLDE4LDE0MCwyNSwxMjEsMTM5LDIwMSwxNTEsMjAzLDE0MiwzNSw2MywyNDUsMzIsOTEsOTgsMjE5LDI1LDIxMywyMSwxMjIsMjEwLDE2NSwxODUsNTcsMTAsMTQxLDQyLDE1NywzLDExMCw5NywyNTUsMjA2LDExMSwxMTUsMTExLDE4LDEwMSwxMTQsNjcsMjQ0LDE0OCw5NywxMDAsMjA4LDk4LDE5LDEyMSwxOCwyMjQsMTUzLDE5OSwxMDcsMTM2LDEwNiwyNTQsNjQsMjIzLDE2MCw4NiwyMzAsMzksMTEzLDg3LDEyMywxMTgsMTIsOTgsMTY4LDE3NiwxNTksMTgwLDIyNSwyMjksOTYsMTg4LDI0MywyNDIsMSwxOTcsNzIsMTk0LDE5MCw2Niw5OCwxNTYsMjQyLDU4LDEzMiwxODAsMSwxMDYsMTIwLDIxOSwxNywyMDIsMTE1LDE0MCwxNjUsNDQsMjQ1LDY5LDE4MywyMTksNjksMTY4LDE1NCwyMjEsMTk2LDE0OSwxOTksNCwxNjYsMjUwLDMsMjMwLDE1Miw2OCw4NCwxMjYsOTksOTIsMTUyLDI1NSwyMDMsMTQwLDE4NSwxMiwxNTAsNiw2NCwxNjMsNywxNDIsNzksMTE4LDIyNSw1MywxMDcsMTY1LDEzOCwxNDcsMTkxLDEzMSw4LDgwLDM5LDM2LDE1NiwyNDUsMTI4LDYwLDEwNSwxODQsMTAyLDQ0LDE2NCwyMiwxOTAsMTEyLDIwNSwyMzksMTQ1XQ=="
	vcId := "d3edb91eff74538bcd099b02f6b6e798"
	vcBytes, err := tools.QueryChaincode(chaincode, "SearchVC", vcId)
	if err != nil {
		panic(err)
	}
	var vc did.VerifiableCredential
	_ = json.Unmarshal(vcBytes, &vc)
	paras := make(map[string]interface{})
	paras["personCom"] = vc.CredentialSubject.PersonCommit
	paras["forestRoots"] = vc.Proof.ForestRoots
	paras["forestProof"] = vc.Proof.ForestProof
	paras["treeProof"] = vc.Proof.TreeProof
	paras["merkleRoot"] = vc.Proof.MerkleRoot
	paras["personProof"] = personProof
	paras["vks"] = vc.VerifyingKeys
	resBody := tools.HTTPPostJson(verifyUrl, paras)
	var verifyResult did.VerifyResult
	_ = json.Unmarshal([]byte(resBody), &verifyResult)
	fmt.Println("验证结果：", verifyResult.Result)
}

func TestCreateFakeVC(t *testing.T) {
	fakeVCJson := "{\"id\":\"d19f13f0ed4766fe4d86983c5c80c7e0\",\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:f39c3520830161c10fb4b8337d29adb1\",\"issuanceDate\":1695694864713,\"expirationDate\":1695694924713,\"credentialSubject\":{\"id\":\"did:example:f932f6d52109dbc70e5d62de4f8c2969\",\"claim\":{\"age\":\"1300\",\"name\":\"李白\",\"poiet\":\"桃花潭水深千尺，不及汪伦送我情\"}},\"proof\":{\"creator\":\"did:example:f39c3520830161c10fb4b8337d29adb1\",\"signature\":\"4uFgxrnvskaxg1akWEpHBCf1D59LCHvtXeyBASebnDt6isenGqoE53fStPSQShpkPVuLESvXtJNPnjJv6edWuYeK\",\"created\":1695694864713,\"type\":\"Ed25519VerificationKey2018\"}} "
	var vc did.VerifiableCredential
	_ = json.Unmarshal([]byte(fakeVCJson), &vc)
	//vc.CredentialSubject.Claim["name"] = "杜甫"
	bytes, _ := json.Marshal(vc)
	_, _, err := tools.ExecuteChaincode(chaincode, "PutValue", "d19f13f0ed4766fe4d86983c5c80c7e0", string(bytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %v \n", true)
}
