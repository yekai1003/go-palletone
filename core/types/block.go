// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package types contains data types related to PalletOne consensus.
package types

import (
	"math/big"
	"time"

	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/crypto/sha3"
	"github.com/palletone/go-palletone/common/rlp"
)

type BlockNonce [8]byte

type Header struct {
	ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address `json:"miner"            gencodec:"required"`
	Root        common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	Bloom       Bloom          `json:"logsBloom"        gencodec:"required"`
	Difficulty  *big.Int       `json:"difficulty"       gencodec:"required"`
	Number      *big.Int       `json:"number"           gencodec:"required"`
	GasLimit    uint64         `json:"gasLimit"         gencodec:"required"`
	GasUsed     uint64         `json:"gasUsed"          gencodec:"required"`
	Time        *big.Int       `json:"timestamp"        gencodec:"required"`
	Extra       []byte         `json:"extraData"        gencodec:"required"`
	MixDigest   common.Hash    `json:"mixHash"          gencodec:"required"`
	Nonce       BlockNonce     `json:"nonce"            gencodec:"required"`
}

func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

// HashNoNonce returns the hash which is used as input for the proof-of-work search.
func (h *Header) HashNoNonce() common.Hash {
	return common.Hash{}
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	return common.StorageSize(0)
}

type Block struct {
	header       *Header
	ReceivedAt   time.Time
	transactions Transactions
}
type Blocks []*Block
type Body struct {
	Transactions []*Transaction
	Uncles       []*Header
}

func (b *Block) WithSeal(header *Header) *Block {
	return &Block{}
}

// WithBody returns a new block with the given transaction and uncle contents.
func (b *Block) WithBody(transactions []*Transaction, uncles []*Header) *Block {
	block := &Block{}
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	v := common.Hash{}
	return v
}

func (b *Block) Uncles() []*Header          { return []*Header{} }
func (b *Block) Transactions() Transactions { return Transactions{} }

func (b *Block) Number() *big.Int     { return &big.Int{} }
func (b *Block) GasLimit() uint64     { return uint64(0) }
func (b *Block) GasUsed() uint64      { return uint64(0) }
func (b *Block) Difficulty() *big.Int { return &big.Int{} }
func (b *Block) Time() *big.Int       { return &big.Int{} }

func (b *Block) NumberU64() uint64        { return uint64(0) }
func (b *Block) MixDigest() common.Hash   { return common.Hash{} }
func (b *Block) Nonce() uint64            { return uint64(0) }
func (b *Block) Bloom() Bloom             { return Bloom{} }
func (b *Block) Coinbase() common.Address { return common.Address{} }
func (b *Block) Root() common.Hash        { return common.Hash{} }
func (b *Block) ParentHash() common.Hash  { return common.Hash{} }
func (b *Block) TxHash() common.Hash      { return common.Hash{} }
func (b *Block) ReceiptHash() common.Hash { return common.Hash{} }
func (b *Block) UncleHash() common.Hash   { return common.Hash{} }
func (b *Block) Extra() []byte            { return []byte{} }

func (b *Block) Header() *Header { return &Header{} }

func (b *Block) Size() common.StorageSize { return common.StorageSize(0) }

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}
func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
func NewBlockWithHeader(header *Header) *Block {
	return &Block{}
}
