package core

import (
	"encoding/json"

	"github.com/holiman/uint256"
	zktrie "github.com/kroma-network/zktrie/trie"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/kroma"
	"github.com/ethereum/go-ethereum/triedb"
)

func HashAllocZk(ga *types.GenesisAlloc, _ bool) (common.Hash, error) {
	memdb := zktrie.NewZkTrieMemoryDb()
	tr, err := kroma.NewZkTrie(common.Hash{}, memdb)
	if err != nil {
		return common.Hash{}, nil
	}

	for addr, account := range *ga {
		zkAcc := &types.StateAccount{
			Nonce:    account.Nonce,
			CodeHash: crypto.Keccak256Hash(account.Code).Bytes(),
			Root:     common.Hash{},
		}
		if account.Balance != nil {
			zkAcc.Balance = uint256.MustFromBig(account.Balance)
		}
		storageTr, err := kroma.NewZkTrie(common.Hash{}, memdb)
		if err != nil {
			return common.Hash{}, err
		}
		for key, value := range account.Storage {
			if value != (common.Hash{}) {
				err := storageTr.UpdateStorage(addr, key[:], common.TrimLeftZeroes(value[:]))
				if err != nil {
					return common.Hash{}, err
				}
			}
		}
		zkAcc.Root = storageTr.Hash()
		err = tr.UpdateAccount(addr, zkAcc)
		if err != nil {
			return common.Hash{}, err
		}
	}
	return tr.Hash(), nil
}

func FlushAllocZk(ga *types.GenesisAlloc, db ethdb.Database, triedb *triedb.Database, blockhash common.Hash) error {
	root, err := HashAllocZk(ga, false)
	if err != nil {
		return err
	}
	// Commit newly generated states into disk if it's not empty.
	if root != (common.Hash{}) {
		if err := triedb.Commit(root, true); err != nil {
			return err
		}
	}
	// Marshal the genesis state specification and persist.
	blob, err := json.Marshal(ga)
	if err != nil {
		return err
	}
	rawdb.WriteGenesisStateSpec(db, blockhash, blob)
	return nil
}
