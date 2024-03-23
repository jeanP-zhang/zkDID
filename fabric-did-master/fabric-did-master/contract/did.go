package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
)

type SimpleChaincode struct {
	contractapi.Contract
}

const KeyType = "Ed25519VerificationKey2018"
const VCType = "VerifiableCredential"
const IssuerKey = "ISSUER_LIST"

type DID struct {
	ID             string         `json:"id"`
	Authentication Authentication `json:"authentication,omitempty"`
	PrivateKey     string         `json:"privateKey,omitempty"`
}

type Authentication struct {
	ID                 string `json:"id"`
	Type               string `json:"type,omitempty"`
	Controller         string `json:"controller,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

type Issuer struct {
	DID         string `json:"DID"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreateTime  int64  `json:"createTime"`
	PublicKey   int64  `json:"publicKey"`
}

type Candidate struct {
	ID            string   `json:"ID"`
	DID           string   `json:"DID"`
	ApproveList   []string `json:"approveList"`
	TotalVoterNum int      `json:"totalVoterNum"`
	Result        bool     `json:"result"`
	CreateTime    int64    `json:"createTime"`
	UpdateTime    int64    `json:"updateTime"`
}

type VerifiableCredential struct {
	ID                string            `json:"id,omitempty"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      int64             `json:"issuanceDate"`
	ExpirationDate    int64             `json:"expirationDate,omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             ZKProof           `json:"proof"`
	VerifyingKeys     VerifyingKeys     `json:"verifyingKeys"`
}

type CredentialSubject struct {
	ID           string `json:"id"`
	PersonCommit string `json:"personCommit"`
}

type ZKProof struct {
	Creator      string `json:"creator"`
	Type         string `json:"type"`
	Created      int64  `json:"created"`
	ForestRoots  string `json:"forestRoots"`
	ForestProof  string `json:"forestProof"`
	TreeProof    string `json:"treeProof"`
	MerkleRoot   string `json:"merkleRoot"`
	AgeChecker   string `json:"ageChecker"`
	PersonCommit string `json:"personCommit"`
	PersonProof  string `json:"personProof"`
}

type VerifyingKeys struct {
	ForestVk string `json:"forestVk"`
	TreeVk   string `json:"treeVk"`
	AgeVk    string `json:"ageVk"`
}

func (t *SimpleChaincode) InitLedger(ctx contractapi.TransactionContextInterface) error {
	fmt.Println("Init Ledger")

	fmt.Println("Init First DID")
	id := "did:example:0000000000000000000000000000000000"
	authentication := Authentication{
		ID:                 id + "#keys-1",
		Type:               KeyType,
		Controller:         id,
		PublicKeyMultibase: "G6hEJYCTzSxo4NS1oHnytyHxJ3hbD3kdrX3sT2u7kxNX",
	}
	did := DID{
		ID:             id,
		Authentication: authentication,
	}
	didBytes, _ := json.Marshal(did)
	_ = ctx.GetStub().PutState(did.ID, didBytes)

	fmt.Println("Init First issuer")
	var issuer = make([]string, 0)
	issuer = append(issuer, id)
	issuerBytes, err := json.Marshal(issuer)
	if err != nil {
		return err
	}
	//初始化issuerList列表
	err = ctx.GetStub().PutState(IssuerKey, issuerBytes)
	if err != nil {
		return err
	}
	return nil
}

// CreateDID 如果不提供公私钥，那么CreateDID应该是链下处理，数据上链
func (t *SimpleChaincode) CreateDID(ctx contractapi.TransactionContextInterface, DIDJson string) error {
	var did DID
	err := json.Unmarshal([]byte(DIDJson), &did)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(did.ID, []byte(DIDJson))
	if err != nil {
		return err
	}
	return nil
}

func (t *SimpleChaincode) SearchDID(ctx contractapi.TransactionContextInterface, ID string) (string, error) {
	didBytes, err := ctx.GetStub().GetState(ID)
	if didBytes == nil || err != nil {
		return "", fmt.Errorf("DID doesn't exist")
	}
	return string(didBytes), nil
}

func (t *SimpleChaincode) BecomeCandidate(ctx contractapi.TransactionContextInterface, candidateJson string) error {
	var candidate Candidate
	err := json.Unmarshal([]byte(candidateJson), &candidate)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(candidate.ID, []byte(candidateJson))
	if err != nil {
		return err
	}
	return nil
}

func (t *SimpleChaincode) SearchCandidate(ctx contractapi.TransactionContextInterface, candidateId string) (string, error) {
	candidateBytes, err := ctx.GetStub().GetState(candidateId)
	if candidateBytes == nil || err != nil {
		return "", fmt.Errorf("candidate doesn't exist")
	}
	return string(candidateBytes), nil
}

func (t *SimpleChaincode) VoteCandidate(ctx contractapi.TransactionContextInterface, candidateId string, IssuerId string) error {
	candidateBytes, err := ctx.GetStub().GetState(candidateId)
	if candidateBytes == nil || err != nil {
		return fmt.Errorf("candidate doesn't exist")
	}
	_, err = CheckIssuer(ctx, IssuerId)
	if err != nil {
		return fmt.Errorf("you are not issuer")
	}
	var candidate Candidate
	err = json.Unmarshal(candidateBytes, &candidate)
	if err != nil {
		return err
	}
	if InSlice(candidate.ApproveList, IssuerId) {
		return nil
	}
	if candidate.Result {
		return nil
	}
	candidate.ApproveList = append(candidate.ApproveList, IssuerId)
	if len(candidate.ApproveList) > candidate.TotalVoterNum/2 {
		//half passed, candidate become issuer
		err := AddIssuer(ctx, candidate.DID)
		if err != nil {
			return err
		}
		candidate.Result = true
	}
	candidateBytes, err = json.Marshal(candidate)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(candidate.ID, candidateBytes)
	if err != nil {
		return err
	}
	return nil
}

func (t *SimpleChaincode) SearchIssuer(ctx contractapi.TransactionContextInterface) (string, error) {
	issuerBytes, err := ctx.GetStub().GetState(IssuerKey)
	if err != nil {
		return "", fmt.Errorf("issuer doesn't exist")
	}
	return string(issuerBytes), nil
}

// CreateVC VC的创建需要链上和链下一起进行，链下进行issuer私钥的签名，链上判断issuer的权限
func (t *SimpleChaincode) CreateVC(ctx contractapi.TransactionContextInterface, ID string, issuerID string, vcJson string) error {
	//检查issuer是否存在
	_, err := CheckIssuer(ctx, issuerID)
	if err != nil {
		return err
	}
	//查询ID是否存在
	_, err = GetDID(ctx, ID)
	if err != nil {
		return err
	}
	var vc VerifiableCredential
	err = json.Unmarshal([]byte(vcJson), &vc)
	if err != nil {
		return fmt.Errorf("verifiableCredential format error")
	}
	if vc.Issuer != issuerID || issuerID != vc.Proof.Creator {
		return fmt.Errorf("issuerID error")
	}
	err = ctx.GetStub().PutState(vc.ID, []byte(vcJson))
	return nil
}

func (t *SimpleChaincode) SearchVC(ctx contractapi.TransactionContextInterface, vcID string) (string, error) {
	vcBytes, err := ctx.GetStub().GetState(vcID)
	if vcBytes == nil || err != nil {
		return "", fmt.Errorf("vc doesn't exist")
	}
	return string(vcBytes), nil
}

func CheckIssuer(ctx contractapi.TransactionContextInterface, issuerID string) (bool, error) {
	issuerList, err := GetIssuerList(ctx)
	if err != nil {
		return false, fmt.Errorf("issuer doesn't exist")
	}
	for _, eachItem := range issuerList {
		if eachItem == issuerID {
			return true, nil
		}
	}
	return false, fmt.Errorf("not issuer")
}

func GetIssuerList(ctx contractapi.TransactionContextInterface) ([]string, error) {
	issuerBytes, err := ctx.GetStub().GetState(IssuerKey)
	if issuerBytes == nil || err != nil {
		return nil, fmt.Errorf("issuer doesn't exist")
	}
	var issuerList = make([]string, 0)
	err = json.Unmarshal(issuerBytes, &issuerList)
	if err != nil {
		return nil, fmt.Errorf("unmarshal issuer error")
	}
	return issuerList, nil
}

func GetDID(ctx contractapi.TransactionContextInterface, ID string) (DID, error) {
	didBytes, err := ctx.GetStub().GetState(ID)
	if didBytes == nil || err != nil {
		return DID{}, fmt.Errorf("DID doesn't exist")
	}
	var did DID
	err = json.Unmarshal(didBytes, &did)
	if err != nil {
		return DID{}, err
	}
	return did, nil
}

func AddIssuer(ctx contractapi.TransactionContextInterface, ID string) error {
	b, err := ctx.GetStub().GetState(ID)
	if err != nil {
		return fmt.Errorf("DID doesn't exist")
	}
	var did DID
	err = json.Unmarshal(b, &did)
	if err != nil {
		return err
	}
	issuerList, err := GetIssuerList(ctx)
	issuerList = append(issuerList, ID)
	issuerBytes, err := json.Marshal(issuerList)
	if err != nil {
		return err
	}
	//更新issuer
	err = ctx.GetStub().PutState(IssuerKey, issuerBytes)
	if err != nil {
		return err
	}
	return nil
}

// ReverseBytes reverses a byte array
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

// InSlice 判断字符串是否在 slice 中。
func InSlice(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SimpleChaincode{})
	if err != nil {
		log.Panicf("Error creating asset chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting asset chaincode: %v", err)
	}
}
