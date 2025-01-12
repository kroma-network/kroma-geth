package params

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum-optimism/superchain-registry/superchain"
)

const (
	KromaMainnetChainID = 255
	KromaSepoliaChainID = 2358
	KromaDevnetChainID  = 7791
)

type Genesis struct {
	Timestamp     uint64
	ExtraData     []byte
	GasLimit      uint64
	Coinbase      common.Address
	BaseFee       *big.Int
	ExcessBlobGas *uint64
	BlobGasUsed   *uint64
	Alloc         map[common.Address]superchain.GenesisAccount
	StateHash     common.Hash
	ZkTrie        bool
}

type KromaChainConfig struct {
	Name         string
	ChainID      uint64
	CanyonTime   *uint64
	DeltaTime    *uint64
	EcotoneTime  *uint64
	FjordTime    *uint64
	GraniteTime  *uint64
	HoloceneTime *uint64

	Genesis *Genesis
}

var KromaChains = map[uint64]*KromaChainConfig{
	KromaMainnetChainID: {
		Name:         "kroma-mainnet",
		ChainID:      KromaMainnetChainID,
		CanyonTime:   uint64ptr(1708502400),
		EcotoneTime:  uint64ptr(1714032001),
		FjordTime:    nil,
		GraniteTime:  nil,
		HoloceneTime: nil,
	},
	KromaSepoliaChainID: {
		Name:         "kroma-sepolia",
		ChainID:      KromaSepoliaChainID,
		CanyonTime:   uint64ptr(1707897600),
		EcotoneTime:  uint64ptr(1713340800),
		FjordTime:    nil,
		GraniteTime:  nil,
		HoloceneTime: nil,
	},
	KromaDevnetChainID: {
		Name:         "kroma-devnet",
		ChainID:      KromaDevnetChainID,
		CanyonTime:   uint64ptr(1707292800),
		EcotoneTime:  uint64ptr(1712908800),
		FjordTime:    nil,
		GraniteTime:  nil,
		HoloceneTime: nil,
		Genesis: &Genesis{
			Timestamp: 1711098072,
			ExtraData: common.Hex2Bytes("4c696d69746c657373205765623320556e6976657273653a204b726f6d61"),
			GasLimit:  30000000,
			Coinbase:  common.Address{},
			BaseFee:   new(big.Int).SetUint64(1000000000),
			StateHash: common.HexToHash("087c2e12caf484f153c313e018c2410b0e279af8fb021d0f87271a308dded88c"),
			ZkTrie:    true,
		},
	},
}

func init() {
	for id, ch := range KromaChains {
		NetworkNames[fmt.Sprintf("%d", id)] = ch.Name
	}
}

func KromaChainIDByName(name string) (uint64, error) {
	for id, ch := range KromaChains {
		if ch.Name == name {
			return id, nil
		}
	}
	return 0, fmt.Errorf("unknown chain %q", name)
}

func KromaChainNames() (out []string) {
	for _, ch := range KromaChains {
		out = append(out, ch.Name)
	}
	sort.Strings(out)
	return
}

func LoadKromaChainConfig(chainID uint64) (*ChainConfig, error) {
	chConfig, ok := KromaChains[chainID]
	if !ok {
		return nil, fmt.Errorf("unknown chain ID: %d", chainID)
	}

	genesisActivation := uint64(0)
	out := &ChainConfig{
		ChainID:                       new(big.Int).SetUint64(chainID),
		HomesteadBlock:                common.Big0,
		DAOForkBlock:                  nil,
		DAOForkSupport:                false,
		EIP150Block:                   common.Big0,
		EIP155Block:                   common.Big0,
		EIP158Block:                   common.Big0,
		ByzantiumBlock:                common.Big0,
		ConstantinopleBlock:           common.Big0,
		PetersburgBlock:               common.Big0,
		IstanbulBlock:                 common.Big0,
		MuirGlacierBlock:              common.Big0,
		BerlinBlock:                   common.Big0,
		LondonBlock:                   common.Big0,
		ArrowGlacierBlock:             common.Big0,
		GrayGlacierBlock:              common.Big0,
		MergeNetsplitBlock:            common.Big0,
		ShanghaiTime:                  chConfig.CanyonTime,  // Shanghai activates with Canyon
		CancunTime:                    chConfig.EcotoneTime, // Cancun activates with Ecotone
		PragueTime:                    nil,
		BedrockBlock:                  common.Big0,
		RegolithTime:                  &genesisActivation,
		CanyonTime:                    chConfig.CanyonTime,
		EcotoneTime:                   chConfig.EcotoneTime,
		FjordTime:                     chConfig.FjordTime,
		TerminalTotalDifficulty:       common.Big0,
		TerminalTotalDifficultyPassed: true,
		Ethash:                        nil,
		Clique:                        nil,
		Optimism: &OptimismConfig{
			EIP1559Elasticity:        6,
			EIP1559Denominator:       50,
			EIP1559DenominatorCanyon: 250,
		},
		Zktrie: chConfig.Genesis.ZkTrie,
	}

	// special overrides for Kroma chains
	switch chainID {
	case KromaMainnetChainID:
		out.BedrockBlock = big.NewInt(0)
	case KromaSepoliaChainID:
		out.BedrockBlock = big.NewInt(0)
		out.Optimism.EIP1559Elasticity = 10
	case KromaDevnetChainID:
		out.BedrockBlock = big.NewInt(12347964)
		out.Optimism.EIP1559Elasticity = 10
	}

	return out, nil
}

func uint64ptr(n uint64) *uint64 {
	return &n
}
