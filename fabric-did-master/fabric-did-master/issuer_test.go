package main

import (
	"encoding/json"
	"fabric-did/did"
	"fabric-did/tools"
	"fmt"
	"testing"
	"time"
)

//Issuer1: did:example:1BjY5h7G6jQ7ZzGn2XkWFBDnqSP5H8YxHm
//Issuer2: did:example:1G9d1ESbMEmemmGj1XGjv9WbrQhgGYmYoS
//did:example:1NQGUDdJSS5tG3rSctCGRo3iyxmnMAgfgf
func TestCreateIssuerDID(t *testing.T) {
	DID := did.CreateDid()
	didBytes, _ := json.Marshal(DID)
	_, _, err := tools.ExecuteChaincode(chaincode, "CreateDID", string(didBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("id: %s \n", DID.ID)
	fmt.Printf("DID: %s \n", string(didBytes))
}

func TestBecomeCandidate(t *testing.T) {
	DID := "did:example:1NQGUDdJSS5tG3rSctCGRo3iyxmnMAgfgf"
	didBytes, err := tools.QueryChaincode(chaincode, "SearchDID", DID)
	if err != nil {
		panic("DID doesn't exist")
	}
	var d did.DID
	_ = json.Unmarshal(didBytes, &d)

	issuerListBytes, _ := tools.QueryChaincode(chaincode, "SearchIssuer")
	var issuerList []string
	_ = json.Unmarshal(issuerListBytes, &issuerList)

	candidate := did.Candidate{
		ID:            tools.GetUUID(),
		DID:           DID,
		ApproveList:   make([]string, 0),
		TotalVoterNum: len(issuerList),
		Result:        false,
		CreateTime:    time.Now().UnixMilli(),
		UpdateTime:    time.Now().UnixMilli(),
	}
	candidateBytes, _ := json.Marshal(candidate)
	_, _, err = tools.ExecuteChaincode(chaincode, "BecomeCandidate", string(candidateBytes))
	if err != nil {
		panic(err)
	}
	fmt.Printf("candidateId: %s \n", candidate.ID)
	fmt.Printf("candidate: %s \n", string(candidateBytes))
}

func TestSearchCandidate(t *testing.T) {
	result, err := tools.QueryChaincode(chaincode, "SearchCandidate", "16c0a71c5de56e9e3ad74a9cdc0c0045")
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %s \n", result)
}

func TestVoteCandidate(t *testing.T) {
	candidateId := "16c0a71c5de56e9e3ad74a9cdc0c0045"
	issuerId := "did:example:1G9d1ESbMEmemmGj1XGjv9WbrQhgGYmYoS"
	_, _, err := tools.ExecuteChaincode(chaincode, "VoteCandidate", candidateId, issuerId)
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %v \n", true)
}

func TestSearchIssuer(t *testing.T) {
	result, err := tools.QueryChaincode(chaincode, "SearchIssuer")
	if err != nil {
		panic(err)
	}
	fmt.Printf("result: %s \n", result)
}
