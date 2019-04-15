/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/palletone/go-palletone/bccsp/utils"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
	"crypto/sha256"
	//"github.com/btcsuite/btcutil/base58"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]", err)
		os.Exit(-1)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ecdsaPrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ecdsaPublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&rsaPublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&rsaPrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&aesPrivateKey{nil, false})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&aesPrivateKey{nil, true})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestBigKeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	cspKey := &ecdsaPrivateKey{privKey}
	ski := cspKey.SKI()
	rawKey, err := utils.PrivateKeyToPEM(privKey, nil)
	assert.NoError(t, err)

	// Large padding array, of some values PEM parser will NOOP
	bigBuff := make([]byte, (1 << 17))
	for i := range bigBuff {
		bigBuff[i] = '\n'
	}
	copy(bigBuff, rawKey)

	//>64k, so that total file size will be too big
	ioutil.WriteFile(filepath.Join(ksPath, "bigfile.pem"), bigBuff, 0666)

	_, err = ks.GetKey(ski)
	assert.Error(t, err)

	expected := fmt.Sprintf("Key with SKI %s not found in %s", ski2Address(ski), ksPath)
	assert.EqualError(t, err, expected)

	// 1k, so that the key would be found
	ioutil.WriteFile(filepath.Join(ksPath, "smallerfile.pem"), bigBuff[0:1<<10], 0666)

	_, err = ks.GetKey(ski)
	assert.NoError(t, err)
}

func TestReInitKeyStore(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedKeyStore)
	assert.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	assert.EqualError(t, err, "KeyStore already initilized.")
} 

 
func TestKeyStore_Read(t *testing.T) {
        fmt.Println("----------writeKeyToFile---------") 
	privateKey, e := sm2.GenerateKey()
	if e != nil{
		fmt.Println("获取密钥对失败！")
	}
	fmt.Printf("--sm2.GenerateKey()-----%+v\n",privateKey)
	publicKey := &privateKey.PublicKey
	raw := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
    // Hash it
    hash := sha256.New()
    hash.Write(raw)
    ski:= hash.Sum(nil)
    addr:= ski2Address(ski)
    b, i := sm2.WritePrivateKeytoPem("/tmp/privateKey", privateKey, []byte(addr))
	pem, i2 := sm2.WritePublicKeytoPem("/tmp/publicKey", publicKey, []byte(addr))
 
	if b||pem {
		fmt.Println("密钥已成功写入文件！")
	}else {
		fmt.Println("密钥对写入文件失败！")
	}
	if i != nil||i2 !=nil {
		fmt.Println("密钥对写入文件错误！！！")
	}
	//writeKeyToFile("/tmp/privateKey", "/tmp/publicKey", []byte("i am  wek && The_Reader "))
	privateKey, publicKey, b = readKeyFromFile("/tmp/privateKey", "/tmp/publicKey",  []byte(addr))
	if b {
		fmt.Println("readKeyFromFile Is success ! ")
		fmt.Println("the privateKey is ",*privateKey," ")
		fmt.Println("the publicKey is ", *publicKey," ")
	}else {
		fmt.Println("readKeyFromFile Is Faild ! ")
	}
	raw1 := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
    // Hash it
    hash1 := sha256.New()
    hash1.Write(raw1)
    ski1:= hash.Sum(nil)
    addr1:= ski2Address(ski1)
    if addr1 == addr {
        fmt.Println("addr is addr1  ! ")
    }else{
    	fmt.Println("addr is not equal addr1 ! ")
    }
}



