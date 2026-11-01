package parallel

import (
	"encoding/binary"
	"errors"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/core/vm"
	"github.com/ava-labs/libevm/libevm"
	"github.com/ava-labs/libevm/params"
)

type evmRequest struct {
	target common.Address
	input  []byte
}

type evmRequests []evmRequest

type EVMHandler struct {
	ChainConfig  *params.ChainConfig
	ChainContext core.ChainContext

	PrecompileAddress common.Address
	MaxRequests       int
	GasCap            uint64
	Priority          uint64
}

type EVMCallResult struct {
	Ret []byte
	Err error
}

type EVMResult struct {
	Requests []EVMCallResult
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
		// key[0] is 32 bytes. 12 zero bytes followed by 20-byte address
		addressWord := keys[0]
		for _, b := range addressWord[:12] {
			if b != 0 {
				return nil, false
			}
		}
		target := common.BytesToAddress(addressWord[12:])

		lengthWord := keys[1]
		for _, b := range lengthWord[:24] {
			if b != 0 {
				return nil, false
			}
		}
		length := binary.BigEndian.Uint64(lengthWord[24:])

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
			target: target,
			input:  input,
		})
	}
	if len(requests) == 0 {
		return nil, false
	}
	return requests, true
}

func (h *EVMHandler) Schedule(tx IndexedTx, _ vm.BlockContext) (Schedule, bool) {
	requests, ok := parseEVMRequests(tx, h.PrecompileAddress, h.MaxRequests)
	if !ok || h.GasCap == 0 {
		return Schedule{}, false
	}
	count := uint64(len(requests))
	if count > ^uint64(0)/h.GasCap {
		return Schedule{}, false
	}
	return Schedule{
		Priority: h.Priority,
		Gas:      count * h.GasCap,
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
			results[i].Err = err
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

			ret, _, err := evm.StaticCall(vm.AccountRef(msg.From), request.target, request.input, h.GasCap)
			return EVMCallResult{Ret: ret, Err: err}

		}()
	}
	return EVMResult{Requests: results}
}

func (r EVMResult) PrecompileOutput(_ vm.PrecompileEnvironment, input []byte) ([]byte, error) {
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
	if result.Err == nil {
		return result.Ret, nil
	}
	if errors.Is(result.Err, vm.ErrExecutionReverted) {
		return result.Ret, result.Err
	}

	return nil, result.Err
}

func (h *EVMHandler) PostProcess(_ vm.BlockContext, _ Results[EVMResult]) struct{} {
	return struct{}{}
}

func (h *EVMHandler) AfterBlock(_ StateDB, _ struct{}, _ *types.Block, _ types.Receipts) {}
