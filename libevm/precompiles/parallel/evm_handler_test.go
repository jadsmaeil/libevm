package parallel

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"
)

func makeEVMRequestTupleForTest(
	precompile common.Address,
	target common.Address,
	input []byte,
) types.AccessTuple {
	chunkCount := (len(input) + 31) / 32
	keys := make([]common.Hash, 2+chunkCount)

	// store the 20 byte target address in the last 20 bytes of keys[0]
	copy(keys[0][12:], target[:])

	// store the calldata length in the last 8 bytes
	binary.BigEndian.PutUint64(keys[1][24:], uint64(len(input)))

	// store the calldata in 32 byte chunk. the final key remain zero padded

	for i := 0; i < chunkCount; i++ {
		start := i * 32
		end := start + 32

		if end > len(input) {
			end = len(input)
		}
		copy(keys[2+i][:], input[start:end])
	}

	return types.AccessTuple{
		Address:     precompile,
		StorageKeys: keys,
	}
}

func IndexedTxWithAccessListForTest(accessList types.AccessList) IndexedTx {
	return IndexedTx{
		Transaction: types.NewTx(&types.AccessListTx{AccessList: accessList,
		}),
	}
}

func TestParseEVMRequests_DataChunkBoundaries(t *testing.T) {
	precompile := common.Address{0x10}
	target := common.Address{0x20}

	for _, length := range []int{0,1,31,32,33} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T){
			input := make([]byte, length)
			for i := range input {
				input[i] = byte(i + 1)
			}
			tuple := makeEVMRequestTupleForTest(precompile, target, input)
			tx := IndexedTxWithAccessListForTest(types.AccessList{tuple})

			got, ok := parseEVMRequests(tx, precompile, 4)
			require.True(t, ok)
			require.Len(t, got, 1)
			require.Equal(t, target, got[0].target)
			require.Equal(t, input, got[0].input)
		})
	}
}

func TestParseEVMRequests_MultipleRequestsAndUnrelatedTuple(t *testing.T){
	precompile := common.Address{0x10}
	otherAddress := common.Address{0x11}
	firstTarget := common.Address{0x20}
	secondTarget := common.Address{0x21}
	firstInput := []byte{0xaa, 0xbb}
	secondInput := []byte{0xcc}

	accessList := types.AccessList {
		makeEVMRequestTupleForTest(precompile, firstTarget, firstInput),
		makeEVMRequestTupleForTest(otherAddress, common.Address{0x30}, []byte{0xdd}),
		makeEVMRequestTupleForTest(precompile, secondTarget, secondInput),
	}

	tx := IndexedTxWithAccessListForTest(accessList)

	got, ok := parseEVMRequests(tx, precompile, 2)
	require.True(t, ok)
	require.Len(t, got, 2)
	require.Equal(t, firstTarget, got[0].target)
	require.Equal(t, firstInput, got[0].input)
	require.Equal(t, secondTarget, got[1].target)
	require.Equal(t, secondInput, got[1].input)
}

