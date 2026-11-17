package parallel

import (
	"encoding/binary"
	"errors"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/core/vm"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/libevm"
	"github.com/ava-labs/libevm/params"
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
}

type EVMCallResult struct {
	Ret              []byte
	RemainingGas     uint64
	authorizedReader common.Address
	Err              error
}

type EVMResult struct {
	Requests []EVMCallResult
}

const targetCallRevertedSignature = "TargetCallReverted(uint64,bytes)"

var targetCallRevertedSelector = crypto.Keccak256([]byte(targetCallRevertedSignature))[:4]

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

func parseEVMRequests(tx IndexedTx, precompile common.Address, maxRequests int) (evmRequests, bool) {
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

		// key[0] is 32 bytes. 20 bytes target address, 8 bytes length of call data, 4 zero padding.
		header := keys[0]

		target := common.BytesToAddress(header[0:20])
		length := binary.BigEndian.Uint64(header[20:28])

		for _, b := range header[28:32] {
			if b != 0 {
				return nil, false
			}
		}

		metadata := keys[1]
		gasLimit := binary.BigEndian.Uint64(metadata[0:8])
		reader := common.BytesToAddress(metadata[8:28])

		for _, b := range metadata[28:32] {
			if b != 0 {
				return nil, false
			}
		}

		if reader == (common.Address{}) || gasLimit == 0 {
			return nil, false
		}

		maxInt := uint64(^uint(0) >> 1)
		if length > maxInt {
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

func (h *EVMHandler) Schedule(tx IndexedTx, _ vm.BlockContext) (Schedule, bool) {
	requests, ok := parseEVMRequests(tx, h.PrecompileAddress, h.MaxRequests)
	if !ok || h.MaxGasPerRequest == 0 {
		return Schedule{}, false
	}
	var totalGas uint64
	for _, request := range requests {
		if request.gasLimit > h.MaxGasPerRequest {
			return Schedule{}, false
		}
		if request.gasLimit > ^uint64(0)-totalGas {
			return Schedule{}, false
		}
		totalGas += request.gasLimit
	}
	return Schedule{
		Priority: h.Priority,
		Gas:      totalGas,
	}, true
}

func (h *EVMHandler) Prefetch(_ libevm.StateReader, tx IndexedTx, _ vm.BlockContext) evmRequests {
	requests, ok := parseEVMRequests(tx, h.PrecompileAddress, h.MaxRequests)
	if !ok {
		return nil
	}
	return requests
}

func (h *EVMHandler) BeforeBlock(_ libevm.StateReader, header *types.Header) vm.BlockContext {
	return core.NewEVMBlockContext(header, h.ChainContext, nil)
}

func (h *EVMHandler) Process(sdb vm.StateDB, tx IndexedTx, blockContext vm.BlockContext, requests evmRequests) EVMResult {
	signer := types.MakeSigner(h.ChainConfig, blockContext.BlockNumber, blockContext.Time)
	msg, err := core.TransactionToMessage(tx.Transaction, signer, blockContext.BaseFee)

	if err != nil {
		results := make([]EVMCallResult, len(requests))
		for i := range results {
			results[i] = EVMCallResult{
				authorizedReader: requests[i].reader,
				Err:              err,
			}
		}
		return EVMResult{Requests: results}
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

			ret, remainingGas, err := evm.StaticCall(vm.AccountRef(msg.From), request.target, request.input, request.gasLimit)
			return EVMCallResult{Ret: ret, RemainingGas: remainingGas, authorizedReader: request.reader, Err: err}

		}()
	}
	return EVMResult{Requests: results}
}

func (r EVMResult) PrecompileOutput(env vm.PrecompileEnvironment, input []byte) ([]byte, error) {
	if len(input) != 32 {
		return nil, vm.ErrExecutionReverted
	}
	for _, b := range input[:24] {
		if b != 0 {
			return nil, vm.ErrExecutionReverted
		}
	}
	index := binary.BigEndian.Uint64(input[24:])
	if index >= uint64(len(r.Requests)) {
		return nil, vm.ErrExecutionReverted
	}

	result := r.Requests[int(index)]
	caller := env.Addresses().EVMSemantic.Caller
	if caller != result.authorizedReader {
		return nil, vm.ErrExecutionReverted
	}
	if result.Err == nil {
		return result.Ret, nil
	}

	if errors.Is(result.Err, vm.ErrExecutionReverted) {
		return encodeTargetCallReverted(index, result.Ret), vm.ErrExecutionReverted
	}

	return nil, result.Err
}

func (h *EVMHandler) PostProcess(vm.BlockContext, Results[EVMResult]) struct{} {
	return struct{}{}
}

func (h *EVMHandler) AfterBlock(StateDB, struct{}, *types.Block, types.Receipts) {}
