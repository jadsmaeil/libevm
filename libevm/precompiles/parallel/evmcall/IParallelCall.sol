pragma solidity ^0.8.0; 

interface IParallelCall {
    error TargetCallReverted(uint64 requestIndex, bytes revertData);

    function getResult(uint64 requestIndex)
        external
        view
        returns (bytes memory result);
}