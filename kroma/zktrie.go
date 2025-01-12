// This is taken from https://github.com/scroll-tech/go-ethereum/blob/staging/trie/zk_trie.go

// Copyright 2015 The go-ethereum Authors
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

package kroma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/iden3/go-iden3-crypto/utils"
	zktrie "github.com/kroma-network/zktrie/trie"
	zkt "github.com/kroma-network/zktrie/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/kroma/poseidon"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

var magicHash []byte = []byte("THIS IS THE MAGIC INDEX FOR ZKTRIE")
var ErrInvalidLength = errors.New("StateAccount: invalid input length")

// ZkTrie wrap zktrie for trie interface
type ZkTrie struct {
	*zktrie.ZkTrie
	db zktrie.ZktrieDatabase
}

func init() {
	zkt.InitHashScheme(poseidon.HashFixed)
}

func sanityCheckByte32Key(b []byte) {
	if len(b) != 32 && len(b) != 20 {
		panic(fmt.Errorf("do not support length except for 120bit and 256bit now. data: %v len: %v", b, len(b)))
	}
}

// NOTE(chokobole): This part is different from scroll
func IsMagicHash(k []byte) bool {
	return bytes.Equal(k, magicHash)
}

// NewZkTrie creates a trie
// NewZkTrie bypasses all the buffer mechanism in *Database, it directly uses the
// underlying diskdb
func NewZkTrie(root common.Hash, db zktrie.ZktrieDatabase) (*ZkTrie, error) {
	tr, err := zktrie.NewZkTrie(*zkt.NewByte32FromBytes(root.Bytes()), db)
	if err != nil {
		return nil, err
	}
	return &ZkTrie{tr, db}, nil
}

func (t *ZkTrie) MustGet(key []byte) []byte {
	b, err := t.Get(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return b
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
func (t *ZkTrie) Get(key []byte) ([]byte, error) {
	sanityCheckByte32Key(key)
	return t.TryGet(key)
}

func (t *ZkTrie) GetStorage(_ common.Address, key []byte) ([]byte, error) {
	sanityCheckByte32Key(key)
	return t.TryGet(key)
}

// [Scroll: START]
// NOTE(chokobole): This part is different from scroll
// UpdateAccount will abstract the write of an account to the
// ZkTrie.
func (t *ZkTrie) UpdateAccount(address common.Address, acc *types.StateAccount) error {
	sanityCheckByte32Key(address.Bytes())

	fields := make([]zkt.Byte32, 4)
	binary.BigEndian.PutUint64(fields[0][24:], acc.Nonce)

	balance := acc.Balance.ToBig()
	if !utils.CheckBigIntInField(balance) {
		panic("balance overflow")
	}
	balance.FillBytes(fields[1][:])

	copy(fields[2][:], acc.CodeHash)
	copy(fields[3][:], acc.Root.Bytes())
	return t.ZkTrie.TryUpdate(address.Bytes(), 4, fields)
}

// [Scroll: END]

func (t *ZkTrie) UpdateContractCode(_ common.Address, _ common.Hash, _ []byte) error {
	return nil
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
func (t *ZkTrie) Update(key, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *ZkTrie) MustUpdate(k, v []byte) {
	if err := t.TryUpdate(k, v); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// NOTE: value is restricted to length of bytes32.
// we override the underlying zktrie's TryUpdate method
func (t *ZkTrie) TryUpdate(key, value []byte) error {
	sanityCheckByte32Key(key)
	return t.ZkTrie.TryUpdate(key, 1, []zkt.Byte32{*zkt.NewByte32FromBytes(value)})
}

func (t *ZkTrie) UpdateStorage(_ common.Address, key, value []byte) error {
	sanityCheckByte32Key(key)
	return t.ZkTrie.TryUpdate(key, 1, []zkt.Byte32{*zkt.NewByte32FromBytes(value)})
}

// Delete removes any existing value for key from the trie.
func (t *ZkTrie) Delete(key []byte) {
	sanityCheckByte32Key(key)
	if err := t.TryDelete(key); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

func (t *ZkTrie) MustDelete(key []byte) { t.Delete(key) }

// Delete removes any existing value for key from the trie.
func (t *ZkTrie) DeleteStorage(_ common.Address, key []byte) error {
	sanityCheckByte32Key(key)
	return t.TryDelete(key)
}

// GetKey returns the preimage of a hashed key that was
// previously used to store a value.
func (t *ZkTrie) GetKey(kHashBytes []byte) []byte {

	return nil
}

// Commit writes all nodes and the secure hash pre-images to the trie's database.
// Nodes are stored with their sha3 hash as the key.
//
// Committing flushes nodes from memory. Subsequent Get calls will load nodes
// from the database.
func (t *ZkTrie) Commit(bool) (common.Hash, *trienode.NodeSet, error) {
	// in current implementation, every update of trie already writes into database
	// so Commit does nothing
	return t.Hash(), nil, nil
}

// Hash returns the root hash of ZkTrie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *ZkTrie) Hash() common.Hash {
	var hash common.Hash
	hash.SetBytes(t.ZkTrie.Hash())
	return hash
}

// Copy returns a copy of ZkTrie.
func (t *ZkTrie) Copy() *ZkTrie {
	return &ZkTrie{t.ZkTrie.Copy(), t.db}
}

// NodeIterator returns an iterator that returns nodes of the underlying trie. Iteration
// starts at the key after the given start key.
func (t *ZkTrie) NodeIterator(start []byte) (trie.NodeIterator, error) {
	panic("not implemented")
}

func (t *ZkTrie) MustNodeIterator(start []byte) trie.NodeIterator {
	panic("not implemented")

}

// hashKey returns the hash of key as an ephemeral buffer.
// The caller must not hold onto the return value because it will become
// invalid on the next call to hashKey or secKey.
/*func (t *ZkTrie) hashKey(key []byte) []byte {
	if len(key) != 32 {
		panic("non byte32 input to hashKey")
	}
	low16 := new(big.Int).SetBytes(key[:16])
	high16 := new(big.Int).SetBytes(key[16:])
	hash, err := poseidon.Hash([]*big.Int{low16, high16})
	if err != nil {
		panic(err)
	}
	return hash.Bytes()
}
*/

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *ZkTrie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	err := t.ZkTrie.Prove(key, 0, func(n *zktrie.Node) error {
		nodeHash, err := n.NodeHash()
		if err != nil {
			return err
		}

		if n.Type == zktrie.NodeTypeLeaf {
			preImage := t.GetKey(n.NodeKey.Bytes())
			if len(preImage) > 0 {
				n.KeyPreimage = &zkt.Byte32{}
				copy(n.KeyPreimage[:], preImage)
				// return fmt.Errorf("key preimage not found for [%x] ref %x", n.NodeKey.Bytes(), k.Bytes())
			}
		}
		return proofDb.Put(nodeHash[:], n.Value())
	})
	if err != nil {
		return err
	}

	// we put this special kv pair in db so we can distinguish the type and
	// make suitable Proof
	return proofDb.Put(magicHash, zktrie.ProofMagicBytes())
}

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProofSMT(rootHash common.Hash, key []byte, proofDb ethdb.KeyValueReader) (value []byte, err error) {
	h := zkt.NewHashFromBytes(rootHash.Bytes())
	k, err := zkt.ToSecureKey(key)
	if err != nil {
		return nil, err
	}
	kHash := zkt.NewHashFromBigInt(k)
	proof, n, err := zktrie.BuildZkTrieProof(h, kHash, zktrie.GetPath(len(key)*8, kHash[:]), func(key *zkt.Hash) (*zktrie.Node, error) {
		buf, _ := proofDb.Get(key[:])
		if buf == nil {
			return nil, zktrie.ErrKeyNotFound
		}
		n, err := zktrie.NewNodeFromBytes(buf)
		return n, err
	})

	if err != nil {
		// do not contain the key
		return nil, err
	} else if !proof.Existence {
		return nil, nil
	}

	if zktrie.VerifyProofZkTrie(h, proof, n) {
		return n.Data(), nil
	} else {
		return nil, fmt.Errorf("bad proof node %v", proof)
	}
}

// [Scroll: START]
// NOTE(chokobole): This part is different from scroll
func (t *ZkTrie) DeleteAccount(address common.Address) error {
	return t.TryDelete(address.Bytes())
}

func (t *ZkTrie) GetAccount(address common.Address) (*types.StateAccount, error) {
	res, err := t.TryGet(address.Bytes())
	if res == nil || err != nil {
		return nil, err
	}

	if len(res) != 128 {
		return nil, ErrInvalidLength
	}
	acc := new(types.StateAccount)
	acc.Nonce = binary.BigEndian.Uint64(res[24:])
	acc.Balance = uint256.MustFromHex(common.Bytes2Hex(res[32:64]))
	acc.CodeHash = make([]byte, 32)
	copy(acc.CodeHash, res[64:96])
	acc.Root = common.Hash{}
	acc.Root.SetBytes(res[96:128])

	return acc, nil
}

// [Scroll: END]
