package evmcall

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/core/vm"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/libevm"
	"github.com/ava-labs/libevm/params"

	parallel "github.com/ava-labs/libevm/libevm/precompiles/parallel"
)

type evmRequest struct {
	target   common.Address
	input    []byte
	gasLimit uint64
	reader   common.Address
}

type evmRequests []evmRequest

type EVMHandler struct {
	ChainConfig  *params.ChainConfig
	ChainContext core.ChainContext

	PrecompileAddress common.Address
	MaxRequests       int
	MaxGasPerRequest  uint64
	Priority          uint64
	requestsByTxHash  map[common.Hash]evmRequests
}

var _ parallel.Handler[
	vm.BlockContext,
	struct{},
	EVMResult,
	struct{},
] = (*EVMHandler)(nil)

type EVMCallResult struct {
	Ret              []byte
	RemainingGas     uint64
	authorizedReader common.Address
	Err              error
}

type EVMResult []EVMCallResult

var _ parallel.PrecompileResult = EVMResult{}

const targetCallRevertedSignature = "TargetCallReverted(uint64,bytes)"

var targetCallRevertedSelector = crypto.Keccak256([]byte(targetCallRevertedSignature))[:4]

const getResultSignature = "getResult(uint64)"

var getResultSelector = crypto.Keccak256([]byte(getResultSignature))[:4]

func encodeTargetCallReverted(index uint64, revertData []byte) []byte {
	paddedLength := len(revertData)

	if remainder := paddedLength % 32; remainder != 0 {
		paddedLength += 32 - remainder
	}

	// Selector + two API argument words + the dynamic bytes length and data
	out := make([]byte, 4+32+32+32+paddedLength)
	copy(out[:4], targetCallRevertedSelector)

	// uint64 request index, left padded to one 32-byte ABI word
	binary.BigEndian.PutUint64(out[4+24:4+32], index)

	// offset to the dynamic bytes data, measured from the start of the arguments.
	binary.BigEndian.PutUint64(out[4+32+24:4+64], 64)

	// dynamic bytes length, followed by the original revert data.
	binary.BigEndian.PutUint64(out[4+64+24:4+96], uint64(len(revertData)))
	copy(out[4+96:], revertData)

	return out
}

func parseGetResultInput(input []byte) (uint64, bool) {
	if len(input) != 4+32 {
		return 0, false
	}
	if !bytes.Equal(input[:4], getResultSelector) {
		return 0, false
	}

	argument := input[4:]

	for _, b := range argument[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(argument[24:]), true

}

func encodeABIBytes(value []byte) []byte {
	paddedLength := len(value)

	if remainder := paddedLength % 32; remainder != 0 {
		paddedLength += 32 - remainder
	}

	out := make([]byte, 64+paddedLength)

	// Offset to the bytes data, measured from the start of the return data.
	binary.BigEndian.PutUint64(out[24:32], 32)

	// Length of the bytes value.
	binary.BigEndian.PutUint64(out[56:64], uint64(len(value)))

	copy(out[64:], value)
	return out
}

func parseEVMRequests(tx parallel.IndexedTx, precompile common.Address, maxRequests int) (evmRequests, bool) {
	if maxRequests <= 0 {
		return nil, false
	}
	var requests evmRequests

	for _, tuple := range tx.AccessList() {
		if tuple.Address != precompile {
			continue
		}
		if len(requests) >= maxRequests {
			return nil, false
		}

		keys := tuple.StorageKeys
		if len(keys) < 2 {
			return nil, false
		}

		// key[0] is 32 bytes. 20 bytes target address, 8 bytes length of call data, and first 4 bytes of gas limit.
		header := keys[0]

		target := common.BytesToAddress(header[0:20])
		length := binary.BigEndian.Uint64(header[20:28])

		metadata := keys[1]

		// The gas limit is one big-endian uint64 split across the two keys.
		var gasLimitBytes [8]byte
		copy(gasLimitBytes[:4], header[28:32])
		copy(gasLimitBytes[4:], metadata[0:4])

		gasLimit := binary.BigEndian.Uint64(gasLimitBytes[:])

		reader := common.BytesToAddress(metadata[4:24])

		for _, b := range metadata[24:32] {
			if b != 0 {
				return nil, false
			}
		}

		if reader == (common.Address{}) || gasLimit == 0 {
			return nil, false
		}

		if length > uint64(math.MaxInt) {
			return nil, false
		}

		chunkCount := length / 32
		if length%32 != 0 {
			chunkCount++
		}
		if chunkCount != uint64(len(keys)-2) {
			return nil, false
		}
		input := make([]byte, int(length))

		// copy each 32-byte chunk into the input. the final chunk
		// is truncated to the declared length

		for offset := 0; offset < len(input); offset += 32 {
			n := len(input) - offset
			if n > 32 {
				n = 32
			}
			chunk := keys[2+offset/32]
			copy(input[offset:offset+n], chunk[:n])
		}
		// Bytes after the declared calldata length in the final chunk
		// must be zero
		if remainder := len(input) % 32; remainder != 0 {
			lastChunk := keys[len(keys)-1]
			for _, b := range lastChunk[remainder:] {
				if b != 0 {
					return nil, false
				}
			}
		}
		requests = append(requests, evmRequest{
			target:   target,
			input:    input,
			gasLimit: gasLimit,
			reader:   reader,
		})
	}
	if len(requests) == 0 {
		return nil, false
	}
	return requests, true
}

func (h *EVMHandler) Schedule(tx parallel.IndexedTx, _ vm.BlockContext) (parallel.Schedule, bool) {
	requests, ok := parseEVMRequests(tx, h.PrecompileAddress, h.MaxRequests)
	if !ok || h.MaxGasPerRequest == 0 {
		return parallel.Schedule{}, false
	}
	var totalGas uint64
	for _, request := range requests {
		if request.gasLimit > h.MaxGasPerRequest {
			return parallel.Schedule{}, false
		}
		if request.gasLimit > ^uint64(0)-totalGas {
			return parallel.Schedule{}, false
		}
		totalGas += request.gasLimit
	}

	if h.requestsByTxHash == nil {
		h.requestsByTxHash = make(map[common.Hash]evmRequests)
	}
	h.requestsByTxHash[tx.Hash()] = requests

	return parallel.Schedule{
		Priority: h.Priority,
		Gas:      totalGas,
	}, true
}

func (h *EVMHandler) Prefetch(libevm.StateReader, parallel.IndexedTx, vm.BlockContext) struct{} {
	return struct{}{}
}

func (h *EVMHandler) BeforeBlock(_ libevm.StateReader, header *types.Header) vm.BlockContext {
	clear(h.requestsByTxHash)
	return core.NewEVMBlockContext(header, h.ChainContext, nil)
}

func (h *EVMHandler) Process(sdb vm.StateDB, tx parallel.IndexedTx, blockContext vm.BlockContext, _ struct{}) EVMResult {
	signer := types.MakeSigner(h.ChainConfig, blockContext.BlockNumber, blockContext.Time)
	msg, err := core.TransactionToMessage(tx.Transaction, signer, blockContext.BaseFee)

	requests, ok := h.requestsByTxHash[tx.Hash()]
	if !ok {
		return nil
	}

	if err != nil {
		results := make(EVMResult, len(requests))
		for i := range results {
			results[i] = EVMCallResult{
				authorizedReader: requests[i].reader,
				Err:              err,
			}
		}

		return results
	}

	txContext := core.NewEVMTxContext(msg)

	results := make([]EVMCallResult, len(requests))

	for i, request := range requests {
		results[i] = func() EVMCallResult {
			snapShot := sdb.Snapshot()
			defer sdb.RevertToSnapshot(snapShot)

			evm := vm.NewEVM(
				blockContext,
				txContext,
				sdb,
				h.ChainConfig,
				vm.Config{},
			)

			ret, remainingGas, err := evm.StaticCall(vm.AccountRef(request.reader), request.target, request.input, request.gasLimit)
			return EVMCallResult{Ret: ret, RemainingGas: remainingGas, authorizedReader: request.reader, Err: err}

		}()
	}
	return results
}

func (r EVMResult) PrecompileOutput(env vm.PrecompileEnvironment, input []byte) ([]byte, error) {

	index, ok := parseGetResultInput(input)
	if !ok {
		return nil, vm.ErrExecutionReverted
	}
	if index >= uint64(len(r)) {
		return nil, vm.ErrExecutionReverted
	}

	result := r[int(index)]
	caller := env.Addresses().EVMSemantic.Caller
	if caller != result.authorizedReader {
		return nil, vm.ErrExecutionReverted
	}

	switch result.Err {
	case nil:
		return encodeABIBytes(result.Ret), nil
	case vm.ErrExecutionReverted:
		return encodeTargetCallReverted(index, result.Ret), vm.ErrExecutionReverted
	default:
		return nil, result.Err
	}
}

func (h *EVMHandler) PostProcess(vm.BlockContext, parallel.Results[EVMResult]) struct{} {
	return struct{}{}
}

func (h *EVMHandler) AfterBlock(parallel.StateDB, struct{}, *types.Block, types.Receipts) {}
