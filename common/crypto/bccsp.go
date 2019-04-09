/*
 *
 *    This file is part of go-palletone.
 *    go-palletone is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *    go-palletone is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *    You should have received a copy of the GNU General Public License
 *    along with go-palletone.  If not, see <http://www.gnu.org/licenses/>.
 * /
 *
 *  * @author PalletOne core developer <dev@pallet.one>
 *  * @date 2018-2019
 *
 */

package crypto

import (
	"github.com/palletone/go-palletone/bccsp"
	"github.com/palletone/go-palletone/bccsp/factory"
	"github.com/palletone/go-palletone/common"
)

type HashType byte

const (
	HashType_SHA3_256 HashType = 0
	HashType_GM3      HashType = 1
)

type CryptoType byte

const (
	CryptoType_ECDSA_P256 CryptoType = 0
	CryptoType_GM2_256    CryptoType = 1
)

var csp bccsp.BCCSP
var hashOpt bccsp.HashOpts

func Init(hashType HashType, cryptoType CryptoType, keystorePath string) error {
	f := &factory.SWFactory{}

	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
		},
	}
	hashOpt, _ = bccsp.GetHashOpt("GMSM3")
	if hashType == HashType_GM3 {
		opts = &factory.FactoryOpts{
			SwOpts: &factory.SwOpts{
				SecLevel:     256,
				HashFamily:   "GMSM3",
				FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
			},
		}
		hashOpt, _ = bccsp.GetHashOpt("GMSM3")
	}
	var err error
	csp, err = f.Get(opts)
	if err != nil {
		return err
	}
	return nil
}
func Hash(data []byte) common.Hash {
	hashOpt, err := bccsp.GetHashOpt("GMSM3")
	if err != nil {
		return common.Hash{}
	}
	hf, err := csp.GetHash(hashOpt)
	hf.Write([]byte("Devin"))
	hash1 := hf.Sum(nil)
	hash2, err := csp.Hash([]byte("Devin"), hashOpt)
	hash1=hash1
	hash2=hash2
	return common.Hash{}
}
