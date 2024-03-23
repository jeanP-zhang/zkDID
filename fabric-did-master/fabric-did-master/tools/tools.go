package tools

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
)

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

const versionByte = byte(0x00)
const addressChecksumLen = 4

// Base58Encode encodes a byte array to Base58
func Base58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)

	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	if input[0] == 0x00 {
		result = append(result, b58Alphabet[0])
	}

	ReverseBytes(result)

	return result
}

// Base58Decode decodes Base58-encoded data
func Base58Decode(input []byte) []byte {
	result := big.NewInt(0)

	for _, b := range input {
		charIndex := bytes.IndexByte(b58Alphabet, b)
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	decoded := result.Bytes()

	if input[0] == b58Alphabet[0] {
		decoded = append([]byte{0x00}, decoded...)
	}

	return decoded
}

// ReverseBytes reverses a byte array
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func GetUUID() (uuid string) {
	b := make([]byte, 16)
	fmt.Println(b)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	uuid = fmt.Sprintf("%x%x%x%x%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return
}

// GetAddress -> address = base58(version + publickey hash + checksum)
func GetAddress(publicKey []byte) string {
	pubkeyhash := HashPubkey(publicKey)

	versionedPayload := append([]byte{versionByte}, pubkeyhash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)
	return string(address)
}

// HashPubkey
func HashPubkey(pubkey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubkey)
	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160
}

//checksum = hash(hash(publicKey))
func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:addressChecksumLen]
}

func HTTPPostJson(url string, paras map[string]interface{}) string {
	bytesData, _ := json.Marshal(paras)
	resp, _ := http.Post(url, "application/json", bytes.NewBuffer(bytesData))
	if resp == nil || resp.StatusCode != 200 {
		return ""
	}
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func HTTPPost(url string, postBody string) string {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte(postBody)))
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func HTTPGet(url string) string {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}
