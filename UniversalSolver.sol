// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

interface IUniversalSolver {
    enum Phase {INACTIVE, CONTEXT, VALIDATION, EXECUTION}

    struct UserEnvelopeTx {
        address sender;
        uint256 sliceInfo;
        bytes envelopeTx;
    }

    function resolve(UserEnvelopeTx[] calldata userEnvelopeTxs) external;

    function senderCallback(bytes calldata intentInfo) external;
   
    function context() external view returns (
        Phase phase,
        uint256 currentIndex,
        address initiator,
        bytes32[] memory executionHash,
        UserEnvelopeTx[] memory userEnvelopeTxs,
        bytes[] memory executorPreContext,
        bytes[] memory executorPostContext
    );
}

contract UniversalSolver is IUniversalSolver {
    uint64 constant MAX_TOTAL_LENGTH = type(uint64).max;
    uint256 constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 constant USER_ENVELOPE_TX_SLOT = bytes32(erc7201("user.envelope.tx.slot"));
    bytes32 constant PRE_CONTEXT_SLOT = bytes32(erc7201("pre.context.slot"));
    bytes32 constant POST_CONTEXT_SLOT = bytes32(erc7201("post.context.slot"));
    bytes32 constant INTENT_HASHES_SLOT = bytes32(erc7201("intent.hashes.slot"));

    Phase public transient phase;
    address public transient initiator;
    uint256 public transient currIdx;
    address transient validSenderCallback;
    bool transient callbackAccepted;

    event CacheUserEnvelopeTx(UserEnvelopeTx userEnvelopeTx);
    event CachePreContext(address indexed sender, address indexed executor, bytes preContext);
    event ContextPhaseSuccess();
    event ValidateSenderSuccess(address indexed sender, bytes result);
    event SenderCallbackSuccess(address indexed sender, bytes result);
    event ValidateSenderPhaseSuccess();
    event ExecuteIntentSuccess(address indexed executor, bytes result);
    event ExecuteIntentPhaseSuccess();

    error Overflow();
    error Reentrancy();
    error InactiveSolver();
    error IntentNotAccepted();
    error TotalLengthTooLarge(uint256 totalLength);
    error InvalidSender(address sender);
    error ValidateSenderFailed(bytes result);
    error ExecuteIntentFailed(bytes result);
    error PreContextFailed(address executor, bytes reason);
    error CallbackAlreadyAccepted(address executor, bytes intent);
    error InvalidIntent(address executor, bytes intent);

    modifier nonReentrant {
        require (phase == Phase.INACTIVE, Reentrancy());
        phase = Phase.CONTEXT;
        _;
        phase = Phase.INACTIVE;
    }

    modifier onlySolverActive {
        require(phase != Phase.INACTIVE, InactiveSolver());
        _;
    }

    fallback() external {}

    function resolve(UserEnvelopeTx[] calldata userEnvelopeTxs) external nonReentrant {
        _setContextPhase(userEnvelopeTxs);
        _validateSenderPhase(userEnvelopeTxs);
        _executeIntentPhase(userEnvelopeTxs);
        _clearContext();
    }

    function senderCallback(bytes calldata intentInfo) external onlySolverActive {
        require(msg.sender == validSenderCallback, InvalidSender(msg.sender));
        
        (address executor, bytes calldata intent) = _decodeIntentInfo(intentInfo);

        if (callbackAccepted) revert CallbackAlreadyAccepted(executor, intent);
        unchecked {
            bytes32 intentHash = bytes32(_tload(bytes32((uint256(INTENT_HASHES_SLOT) + 1) + currIdx)));
            require(keccak256(intentInfo) == intentHash, InvalidIntent(executor, intent));
        }
        callbackAccepted = true;
        emit SenderCallbackSuccess(msg.sender, intent);
    }

    function context() external view returns (
        Phase _phase,
        uint256 currentIndex,
        address _initiator,
        bytes32[] memory executionHash,
        UserEnvelopeTx[] memory userEnvelopeTxs,
        bytes[] memory executorPreContext,
        bytes[] memory executorPostContext
    ) {
        uint256 length = _tload(USER_ENVELOPE_TX_SLOT);
        executionHash = new bytes32[](length);
        userEnvelopeTxs = new UserEnvelopeTx[](length);
        executorPreContext = new bytes[](length);
        if (length > 0) executorPostContext = new bytes[](length - 1);
        unchecked {
            for (uint256 i = 0 ; i < length ; i++) {
                executionHash[i] = bytes32(_tload(bytes32((uint256(INTENT_HASHES_SLOT) + 1) + i)));
                userEnvelopeTxs[i] = _getUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i);
                executorPreContext[i] = _getCacheData(_getHashedSlot(PRE_CONTEXT_SLOT, i));
                if (i + 1 < length) {
                    executorPostContext[i] = _getCacheData(_getHashedSlot(POST_CONTEXT_SLOT, i));
                }
            }
        }
        return (phase, currIdx, initiator, executionHash, userEnvelopeTxs, executorPreContext, executorPostContext);
    }

    function _setContextPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        initiator = msg.sender;
        _tstore(USER_ENVELOPE_TX_SLOT, userEnvelopeTxs.length);
        _tstore(INTENT_HASHES_SLOT, userEnvelopeTxs.length);
        _tstore(PRE_CONTEXT_SLOT, userEnvelopeTxs.length);
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; i++) {
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

            bytes calldata intentInfo = _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx);

            _cacheUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i, userEnvelopeTx);
            _tstore(bytes32((uint256(INTENT_HASHES_SLOT) + 1) + i), uint256(keccak256(intentInfo)));
        }
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

            bytes calldata intentInfo = _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx);

            (address executor, bytes calldata intent) = _decodeIntentInfo(intentInfo);

            currIdx = i;
            _cachePreContext(PRE_CONTEXT_SLOT, i, userEnvelopeTx.sender, executor, intent);
            unchecked { ++i; }
        }
        _markPhase1Pass();
    }

    function _validateSenderPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            uint256 ptr = _getFreePtr();
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            currIdx = i;
            validSenderCallback = userEnvelopeTx.sender;
            (bool success, bytes memory result)
            = userEnvelopeTx.sender.call(userEnvelopeTx.envelopeTx);
            require(success, ValidateSenderFailed(result));
            require(callbackAccepted, IntentNotAccepted());
            callbackAccepted = false;

            emit ValidateSenderSuccess(userEnvelopeTx.sender, result);
            _restoreFreePtr(ptr);
            unchecked { ++i; }
        }
        validSenderCallback = address(0);
        _markPhase2Pass();
    }

    function _executeIntentPhase(
        UserEnvelopeTx[] calldata userEnvelopeTxs
    ) internal {
        unchecked {
            if (userEnvelopeTxs.length > 0) _tstore(POST_CONTEXT_SLOT, userEnvelopeTxs.length - 1);
            for (uint256 i = 0 ; i < userEnvelopeTxs.length ; i++) {
                uint256 ptr = _getFreePtr();
                UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

                (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

                (address executor, bytes calldata intent)
                = _decodeIntentInfo(
                    _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx)
                );

                currIdx = i;
                (bool success, bytes memory result) = executor.call(intent);
                require(success, ExecuteIntentFailed(result));
                if (i + 1 < userEnvelopeTxs.length) {
                    _setCacheData(_getHashedSlot(POST_CONTEXT_SLOT, i), result);
                }
                emit ExecuteIntentSuccess(executor, result);
                _restoreFreePtr(ptr);
            }
            emit ExecuteIntentPhaseSuccess();
        }
    }

    function _clearContext() internal {
        initiator = address(0);
        currIdx = 0;
        uint256 length = _tload(USER_ENVELOPE_TX_SLOT);
        _tstore(USER_ENVELOPE_TX_SLOT, 0);
        _tstore(PRE_CONTEXT_SLOT, 0);
        _tstore(POST_CONTEXT_SLOT, 0);
        _tstore(INTENT_HASHES_SLOT, 0);
        unchecked {
            for (uint256 i = 0 ; i < length ; i++) {
                _clearUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i);
                _setCacheData(_getHashedSlot(PRE_CONTEXT_SLOT, i), new bytes(0));
                _tstore(bytes32(uint256(INTENT_HASHES_SLOT) + 1 + i), 0);
            }
            for (uint256 i = 0 ; i + 1 < length ; i++) {
                _setCacheData(_getHashedSlot(POST_CONTEXT_SLOT, i), new bytes(0));
            }
        }
    }

    function _clearUserEnvelopeTx(bytes32 namespace, uint256 index) internal {
        bytes32 slot = _getHashedSlot(namespace, index);
        unchecked {
            _tstore(slot, 0);
            _tstore(bytes32(uint256(slot) + 1), 0);
            _setCacheData(bytes32(uint256(slot) + 2), new bytes(0));
        }
    }

    function _cacheUserEnvelopeTx(
        bytes32 namespace,
        uint256 index,
        UserEnvelopeTx calldata userEnvelopeTx
    ) internal {
        bytes32 slot = _getHashedSlot(namespace, index);
        _tstore(slot, uint256(uint160(userEnvelopeTx.sender)));
        unchecked { _tstore(bytes32(uint256(slot) + 1), userEnvelopeTx.sliceInfo); }
        _setCacheCallData(bytes32(uint256(slot) + 2), userEnvelopeTx.envelopeTx);
        emit CacheUserEnvelopeTx(userEnvelopeTx);
    }

    function _cachePreContext(
        bytes32 namespace,
        uint256 index,
        address sender,
        address executor,
        bytes calldata intent
    ) internal {
        uint256 ptr = _getFreePtr();
        (bool success, bytes memory preContext) = executor.staticcall(intent);
        require(success, PreContextFailed(executor, preContext));
        _setCacheData(_getHashedSlot(namespace, index), preContext);
        emit CachePreContext(sender, executor, preContext);
        _restoreFreePtr(ptr);
    }

    function _getUserEnvelopeTx(
        bytes32 namespace,
        uint256 index
    ) internal view returns (UserEnvelopeTx memory) {
        bytes32 slot = _getHashedSlot(namespace, index);
        unchecked {
            return UserEnvelopeTx(
                address(uint160(_tload(slot))),
                _tload(bytes32(uint256(slot) + 1)),
                _getCacheData(bytes32(uint256(slot) + 2))
            );
        }
    }

    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := data.length
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot
            {
                let _cacheLength := add(cacheLength, 31)
                if gt(cacheLength, _cacheLength) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                totalCacheSlot := shr(5, _cacheLength)
            }
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := data.offset
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), calldataload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := calldataload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot) {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, cacheLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := mload(data)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot := shr(5, add(cacheLength, 31))
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := add(data, 32)
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), mload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := mload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot)  {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, maxTotalLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            data := mload(64)
            let length := tload(namespace)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            mstore(data, length)
            let offset := add(data, 32)
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                let lastSlot := add(namespace, floorTotalSlot)
                {
                    let _namespace := add(namespace, 1)
                    if gt(namespace, _namespace) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                    namespace := _namespace
                    if gt(namespace, lastSlot) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                }
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    mstore(add(offset, shl(5, i)), tload(add(namespace, i)))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := tload(lastSlot)
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    mstore(add(offset, roundingLength), mask)
                }
                offset := add(offset, shl(5, totalSlot))
            }
            mstore(64, offset)
        }
    }

    function _markPhase1Pass() internal {
        emit ContextPhaseSuccess();
        phase = Phase.VALIDATION;
    }

    function _markPhase2Pass() internal {
        emit ValidateSenderPhaseSuccess();
        phase = Phase.EXECUTION;
    }

    function _tstore(bytes32 key, uint256 value) internal {
        assembly ("memory-safe") {
            tstore(key, value)
        }
    }

    function _tload(bytes32 key) internal view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(key)
        }
    }

    function _getOffsetAndLength(uint256 sliceInfo) 
        internal 
        pure 
        returns (uint256 offset, uint256 length) 
    {
        return (sliceInfo >> 128, sliceInfo & SLICE_INFO_MASKING);
    }

    function _getHashedSlot(
        bytes32 namespace,
        uint256 index
    ) internal pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0, namespace)
            mstore(32, index)
            slot := keccak256(0, 64)
        }
    }

    function _decodeIntentInfo(
        bytes calldata intentInfo
    ) internal pure returns (
        address executor,
        bytes calldata intent
    ) {
        return (address(bytes20(intentInfo[0 : 20])), intentInfo[20 : ]);
    }

    function _sliceEnvelopeTx(
        uint256 offset,
        uint256 length,
        bytes calldata envelopeTx
    ) internal pure returns (
        bytes calldata intentInfo
    ) {
        return envelopeTx[offset : offset + length];
    }

    /**
     * save free memory pointer.
     * save "free memory" pointer, so that it can be restored later using restoreFreePtr.
     * This reduce unneeded memory expansion, and reduce memory expansion cost.
     * NOTE: all dynamic allocations between saveFreePtr and restoreFreePtr MUST NOT be used after restoreFreePtr is called.
     */
    function _getFreePtr() internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
        }
    }

    /**
     * restore free memory pointer.
     * any allocated memory since saveFreePtr is cleared, and MUST NOT be accessed later.
     */
    function _restoreFreePtr(uint256 ptr) internal pure {
        assembly ("memory-safe") {
            mstore(0x40, ptr)
        }
    }
}
