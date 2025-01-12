package core

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum-optimism/superchain-registry/superchain"
)

func LoadKromaGenesis(chainID uint64) (*Genesis, error) {
	chConfig, ok := params.KromaChains[chainID]
	if !ok {
		return nil, fmt.Errorf("unknown chain ID: %d", chainID)
	}

	cfg, err := params.LoadKromaChainConfig(chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to load params.ChainConfig for chain %d: %w", chainID, err)
	}

	gen := chConfig.Genesis

	genesis := &Genesis{
		Config:        cfg,
		Nonce:         0,
		Timestamp:     gen.Timestamp,
		ExtraData:     gen.ExtraData,
		GasLimit:      gen.GasLimit,
		Difficulty:    common.Big0,
		Mixhash:       common.Hash{},
		Coinbase:      gen.Coinbase,
		Alloc:         make(GenesisAlloc),
		Number:        0,
		GasUsed:       0,
		ParentHash:    common.Hash{},
		BaseFee:       gen.BaseFee,
		ExcessBlobGas: gen.ExcessBlobGas,
		BlobGasUsed:   gen.BlobGasUsed,
	}

	for addr, acc := range gen.Alloc {
		var code []byte
		if acc.CodeHash != ([32]byte{}) {
			dat, err := superchain.LoadContractBytecode(acc.CodeHash)
			if err != nil {
				return nil, fmt.Errorf("failed to load bytecode %s of address %s in chain %d: %w", acc.CodeHash, addr, chainID, err)
			}
			code = dat
		}
		var storage map[common.Hash]common.Hash
		if len(acc.Storage) > 0 {
			storage = make(map[common.Hash]common.Hash)
			for k, v := range acc.Storage {
				storage[common.Hash(k)] = common.Hash(v)
			}
		}
		bal := common.Big0
		if acc.Balance != nil {
			bal = (*big.Int)(acc.Balance)
		}
		genesis.Alloc[addr] = GenesisAccount{
			Code:    code,
			Storage: storage,
			Balance: bal,
			Nonce:   acc.Nonce,
		}
	}
	if gen.StateHash != (common.Hash{}) {
		if len(gen.Alloc) > 0 {
			return nil, fmt.Errorf("chain definition unexpectedly contains both allocation (%d) and state-hash %s", len(gen.Alloc), gen.StateHash)
		}
		genesis.StateHash = &gen.StateHash
	}
	return genesis, nil
}
