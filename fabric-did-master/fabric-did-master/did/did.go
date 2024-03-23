package did

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fabric-did/tools"
	"fmt"
	"os"
)

const KeyType = "Ed25519VerificationKey2018"
const KeyTypeZK = "zkcreds"
const VCType = "VerifiableCredential"
const VCTypeAge = "AgeCredential"

//type DID struct {
//	ID             string         `json:"id"`
//	Authentication Authentication `json:"authentication,omitempty"`
//	PrivateKey     string         `json:"privateKey,omitempty"`
//}

type DID struct {
	ID             string         `json:"id"`
	Authentication Authentication `json:"authentication,omitempty"`
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

type Proof struct {
	Creator   string `json:"creator,omitempty"`
	Signature string `json:"signature"`
	Created   int64  `json:"created,omitempty"`
	Type      string `json:"type,omitempty"`
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

type IssueResult struct {
	PersonCom   string `json:"personCom"`
	AuthPath    string `json:"authPath"`
	ForestRoots string `json:"forestRoots"`
	ForestProof string `json:"forestProof"`
	TreeProof   string `json:"treeProof"`
	MerkleRoot  string `json:"merkleRoot"`
}

type VerifyResult struct {
	Result bool `json:"result"`
}

type VerifyingKeys struct {
	ForestVk string `json:"forestVk"`
	TreeVk   string `json:"treeVk"`
	AgeVk    string `json:"ageVk"`
}

func CreateDid() DID {
	//ed25519椭圆曲线生成公私钥
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publicKeyBase58 := tools.Base58Encode(publicKey)
	//私钥链下存储
	privateKeyBase58 := tools.Base58Encode(privateKey)
	savePrivateKeyToFIle(privateKeyBase58)
	//address由公钥生成
	id := "did:example:" + tools.GetAddress(publicKey)
	authentication := Authentication{
		ID:                 id + "#keys-1",
		Type:               KeyType,
		Controller:         id,
		PublicKeyMultibase: string(publicKeyBase58),
	}
	did := DID{
		ID:             id,
		Authentication: authentication,
	}
	fmt.Printf("did:%#v \n", did)
	return did
}

func savePrivateKeyToFIle(privateKey []byte) {
	file, _ := os.OpenFile("private_key.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	writer := bufio.NewWriter(file)
	_, err := writer.WriteString(string(privateKey))
	if err != nil {
		return
	}
	_ = writer.Flush()
}
