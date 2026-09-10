// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

interface IUniversalSolver {
    event ContextPhaseSuccess();
    event ValidateSenderPhaseSuccess(address indexed sender, bytes result);
    event ValidateIntentPhaseSuccess(address indexed validator, bytes result);

    struct UserIntent {
        address sender;
        address validator;
        bytes32 policy;
        bytes intent;
    }

    struct UserEnvelopeTx {
        address sender;
        uint256 sliceInfo;
        bytes envelopeTx;
    }

    function resolve(
        UserEnvelopeTx[] calldata userEnvelopeTx
    ) external;

    function senderCallback(bytes calldata validatorAndIntent) external;

    function senderIndex(address sender) external view returns (uint256 index);

    function context() external view returns (
        address _initator,
        bytes32[] memory intentHash,
        UserIntent[] memory userIntent,
        bytes[] memory userContext
    );

    function fullContext() external view returns (
        address _initator,
        address _validSenderCallback,
        bool _isSolverActive,
        bytes32[] memory intentHash,
        UserEnvelopeTx[] memory userEnvelopeTx,
        bytes[] memory userContext
    );
}

contract UniversalSolver is IUniversalSolver {
    address public constant PRECOMPILE_ADDRESS_RANGE = address(65535);
    uint64 public constant MAX_TOTAL_SLOT = type(uint64).max;
    uint256 public constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 public constant ENVELOPE_TX_SLOT = bytes32(erc7201("envelope.tx.slot"));
    bytes32 public constant INTENT_SLOT = bytes32(erc7201("intent.slot"));
    bytes32 public constant USER_CONTEXT_SLOT = bytes32(erc7201("user.context.slot"));
    bytes32 public constant INTENT_HASHES_SLOT = bytes32(erc7201("intent.hashes.slot"));
    bytes32 public constant SENDER_INDEX_SLOT = bytes32(erc7201("sender.index.slot"));

    address public transient initator;
    address public transient validSenderCallback;
    bool public transient isSolverActive;

    error Reentrancy();
    error IntentNotAccepted();
    error InactiveSolver();
    error LengthTooShort(uint256 length);
    error TotalSlotTooLarge(uint256 totalSlot);
    error InvalidSender(address sender);
    error ValidateSenderFailed(bytes result);
    error ValidateIntentFailed(bytes result);
    error ExecuteIntentFailed(bytes result);
    error CallUserContextFailed(address validator, bytes reason);
    error IntentAccepted(address validator, bytes intent);
    error InvalidIntent(address validator, bytes intent);

    modifier nonReentrant {
        if (isSolverActive) revert Reentrancy();
        isSolverActive = true;
        _;
        isSolverActive = false;
    }

    modifier onlySolverActive {
        require(isSolverActive, InactiveSolver());
        _;
    }

    function _setUserEnvelopeTx(
        bytes32 namespace,
        uint256 index,
        UserEnvelopeTx calldata userEnvelopeTx
    ) internal {
        bytes32 slot = _getBytesSlot(namespace, index);
        address sender = userEnvelopeTx.sender;
        uint256 sliceInfo = userEnvelopeTx.sliceInfo;
        bytes calldata envelopeTx = userEnvelopeTx.envelopeTx;
        unchecked {
            _tstore(slot, uint256(uint160(sender)));
            _tstore(bytes32(uint256(slot) + 1), sliceInfo);
        }
        _setCacheCallData(bytes32(uint256(slot) + 2), envelopeTx);
    }

    function _setUserIntent(
        bytes32 namespace,
        uint256 index,
        address sender,
        address validator,
        bytes32 policy,
        bytes calldata intent
    ) internal {
        bytes32 slot = _getBytesSlot(namespace, index);
        unchecked {
            _tstore(slot, uint256(uint160(sender)));
            _tstore(bytes32(uint256(slot) + 1), uint256(uint160(validator)));
            _tstore(bytes32(uint256(slot) + 2), uint256(policy));
        }
        _setCacheCallData(bytes32(uint256(slot) + 3), intent);
    }

    function senderIndex(address sender) public view returns (uint256 index) {
        return _getMapAddressToUint256(SENDER_INDEX_SLOT, sender);
    }

    function _tload(bytes32 key) internal view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(key)
        }
    }

    function _tstore(bytes32 key, uint256 value) internal {
        assembly ("memory-safe") {
            tstore(key, value)
        }
    }

    function _getBytesSlot(
        bytes32 namespace,
        uint256 index
    ) internal pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0, namespace)
            mstore(32, index)
            slot := keccak256(0, 64)
        }
    }

    function _appendMemoryBytes(
        bytes32 namespace,
        uint256 index,
        bytes memory data
    ) internal {
        _setCacheData(_getBytesSlot(namespace, index), data);
    }

    function resolve(UserEnvelopeTx[] calldata userEnvelopeTxs) public nonReentrant {
        _setContextPhase(userEnvelopeTxs);
        _validateSenderPhase(userEnvelopeTxs);
        _executeIntentPhase(userEnvelopeTxs);
        _clearContext(userEnvelopeTxs);
    }

    function _setMapAddressToUint256(
        bytes32 namespace,
        address key,
        uint256 value
    ) internal {
        assembly ("memory-safe") {
            mstore(0, namespace)
            mstore(32, key)
            let slot := keccak256(0, 64)
            tstore(slot, value)
        }
    }

    function _getMapAddressToUint256(
        bytes32 namespace,
        address key
    ) internal view returns (uint256 value) {
        assembly ("memory-safe") {
            mstore(0, namespace)
            mstore(32, key)
            let slot := keccak256(0, 64)
            value := tload(slot)
        }
    }

    function senderCallback(bytes calldata intentInfo) external onlySolverActive {
        require(msg.sender == validSenderCallback, InvalidSender(validSenderCallback));
        
        (address validator, , bytes calldata intent)
        = _decodeIntentInfo(intentInfo);

        if (validSenderCallback == address(1)) revert IntentAccepted(validator, intent);
        // Kiểm tra intent được user gọi có giống với intent đã được chỉ định trong UserIntent không.
        bytes32 intentHash
        = bytes32(_tload(
            bytes32(
                (uint256(INTENT_HASHES_SLOT) + 1) 
                + _getMapAddressToUint256(SENDER_INDEX_SLOT, msg.sender)
            )
        ));
        require(keccak256(intentInfo) == intentHash, InvalidIntent(validator, intent));
        // Đánh dấu intent này là hợp lệ để sẵn sàng giải quyết.
        validSenderCallback = address(1);
    }

    function _setContextPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        _tstore(ENVELOPE_TX_SLOT, userEnvelopeTxs.length);
        _tstore(INTENT_SLOT, userEnvelopeTxs.length);
        _tstore(USER_CONTEXT_SLOT, userEnvelopeTxs.length);
        _tstore(INTENT_HASHES_SLOT, userEnvelopeTxs.length);
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; i++) {
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            require(userEnvelopeTx.sender > PRECOMPILE_ADDRESS_RANGE);

            (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

            bytes calldata intentInfo
            = _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx);

            (address validator, bytes32 policy, bytes calldata intent)
            = _decodeIntentInfo(intentInfo);

            (bool isCacheEnvelopeTx, bool isCacheIntent, bool isCacheUserContext)
            = _decodePolicy(policy);

            _cacheEnvelopeTx(i, isCacheEnvelopeTx, userEnvelopeTx);
            _cacheIntent(i, isCacheIntent, userEnvelopeTx.sender, validator, policy, intent);
            _cacheUserContext(i, isCacheUserContext, validator, intent);
            _tstore(
                bytes32(uint256(INTENT_HASHES_SLOT) + (i + 1)),
                uint256(keccak256(intentInfo))
            );
            _setMapAddressToUint256(SENDER_INDEX_SLOT, userEnvelopeTx.sender, i);
        }
        initator = msg.sender;
    }

    function _getBytes32Array() internal view returns (bytes32[] memory) {}
    function _getBytesArray() internal view returns (bytes[] memory) {}
    function _getUserIntentArray() internal view returns (UserIntent[] memory) {}
    function _getUserEnvelopeTxArray() internal view returns (UserEnvelopeTx[] memory) {}

    function context() external view returns (
        address _initator,
        bytes32[] memory intentHash,
        UserIntent[] memory userIntent,
        bytes[] memory userContext
    ) {
        return (
            initator,
            _getBytes32Array(),
            _getUserIntentArray(),
            _getBytesArray()
        );
    }

    function fullContext() external view returns (
        address _initator,
        address _validSenderCallback,
        bool _isSolverActive,
        bytes32[] memory intentHash,
        UserEnvelopeTx[] memory userEnvelopeTx,
        bytes[] memory userContext
    ) {
        return (
            initator,
            validSenderCallback,
            isSolverActive,
            _getBytes32Array(),
            _getUserEnvelopeTxArray(),
            _getBytesArray()
        );
    }

    function _clearContext(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        initator = address(0);
        validSenderCallback = address(0);
        _removeBytesArray(ENVELOPE_TX_SLOT);
        _removeBytesArray(INTENT_SLOT);
        _removeBytesArray(USER_CONTEXT_SLOT);
        _removeBytes32Array(INTENT_HASHES_SLOT);
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            _setMapAddressToUint256(
                SENDER_INDEX_SLOT,
                userEnvelopeTxs[i].sender,
                0
            );
            unchecked { ++i; }
        }
    }

    function _removeUserEnvelopeTxArray() internal {
        uint256 length;
        assembly ("memory-safe") {
            length := tload(ENVELOPE_TX_SLOT)
            tstore(ENVELOPE_TX_SLOT, 0)
        }
        for (uint256 i = 0 ; i < length ; ) {
            bytes32 slot = _getBytesSlot(ENVELOPE_TX_SLOT, i);
            _tstore(slot, 0);
            _tstore(bytes32(uint256(slot) + 1), 0);
            _clearCacheData(bytes32(uint256(_getBytesSlot(ENVELOPE_TX_SLOT, i)) + 2));
            unchecked { ++i; }
        }
    }

    function _removeBytesArray(bytes32 namespace) internal {
        uint256 length;
        assembly ("memory-safe") {
            length := tload(namespace)
            tstore(namespace, 0)
        }
        for (uint256 i = 0 ; i < length ; ) {
            _clearCacheData(_getBytesSlot(namespace, i));
            unchecked { ++i; }
        }
    }

    function _removeBytes32Array(bytes32 namespace) internal {
        assembly ("memory-safe") {
            let length := tload(namespace)
            tstore(namespace, 0)
            namespace := add(namespace, 1)
            for { let i } lt(i, length) { i := add(i, 1) } {
                tstore(namespace, 0)
            }
        }
    }

    function _validateSenderPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            uint256 ptr = _getFreePtr();
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            validSenderCallback = userEnvelopeTx.sender;
            (bool success, bytes memory result)
            = userEnvelopeTx.sender.call(userEnvelopeTx.envelopeTx);
            require(success, ValidateIntentFailed(result));
            require(validSenderCallback == address(1), IntentNotAccepted());

            emit ValidateSenderPhaseSuccess(userEnvelopeTx.sender, result);
            _restoreFreePtr(ptr);

            unchecked { ++i; }
        }
    }

    function _cacheEnvelopeTx(
        uint256 index,
        bool isCacheEnvelopeTx,
        UserEnvelopeTx calldata userEnvelopeTx
    ) internal {
        if (isCacheEnvelopeTx) {
            _setUserEnvelopeTx(ENVELOPE_TX_SLOT, index, userEnvelopeTx);
        }
    }

    function _cacheIntent(
        uint256 index, 
        bool isCacheIntent,
        address sender,
        address validator,
        bytes32 policy,
        bytes calldata intent
    ) internal {
        if (isCacheIntent) {
            _setUserIntent(
                INTENT_SLOT,
                index,
                sender,
                validator,
                policy,
                intent
            );
        }
    }

    function _cacheUserContext(
        uint256 index,
        bool isCacheUserContext,
        address validator,
        bytes calldata intent
    ) internal {
        if (isCacheUserContext) {
            uint256 ptr = _getFreePtr();
            (bool success, bytes memory userContext) = validator.staticcall(intent);
            require(success, CallUserContextFailed(validator, intent));
            _appendMemoryBytes(USER_CONTEXT_SLOT, index, userContext);
            _restoreFreePtr(ptr);
        }
    }

    function _executeIntentPhase(
        UserEnvelopeTx[] calldata userEnvelopeTxs
    ) internal {
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            uint256 ptr = _getFreePtr();
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

            (address validator, , bytes calldata intent)
            = _decodeIntentInfo(
                _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx)
            );

            (bool success, bytes memory result) = validator.call(intent);
            require(success, ExecuteIntentFailed(result));

            _restoreFreePtr(ptr);

            unchecked { ++i; }
        }
    }

    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint128 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            data := mload(64)
            let length := tload(namespace)
            mstore(data, length)
            switch length 
            case 0 {
                mstore(64, add(data, 32))
            } default {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                namespace := add(namespace, 1)
                let offset := add(data, 32)
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    mstore(add(offset, shl(5, i)), tload(add(namespace, i)))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitPadding := sub(256, shl(3, bytesLeft))
                    let rawWord := tload(add(namespace, floorTotalSlot))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    mstore(add(offset, roundingLength), mask)
                }
                mstore(64, add(offset, shl(5, totalSlot)))
            }
        }
    }

    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint128 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length := data.length
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                tstore(namespace, length)
                namespace := add(namespace, 1)
                let offset := data.offset
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), calldataload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitPadding := sub(256, shl(3, bytesLeft))
                    let rawWord := calldataload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(add(namespace, floorTotalSlot), mask)
                }
            }
        }
    }

    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint128 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length := mload(data)
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                tstore(namespace, length)
                namespace := add(namespace, 1)
                let offset := add(data, 32)
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), mload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitPadding := sub(256, shl(3, bytesLeft))
                    let rawWord := mload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(add(namespace, floorTotalSlot), mask)
                }
            }
        }
    }

    function _clearCacheData(bytes32 namespace) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint128 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length := tload(namespace)
            if length {
                let totalSlot := shr(5, add(length, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                tstore(namespace, 0)
                namespace := add(namespace, 1)
                for { let i } lt(i, totalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), 0)
                }
            }
        }
    }

    function _getOffsetAndLength(uint256 _sliceInfo) 
        internal 
        pure 
        returns (uint256 offset, uint256 length) 
    {
        return (_sliceInfo >> 128, _sliceInfo & SLICE_INFO_MASKING);
    }

    function _decodeIntentInfo(
        bytes calldata intentInfo
    ) internal pure returns (
        address _validator,
        bytes32 _policy,
        bytes calldata intent
    ) {
        return (
            address(bytes20(intentInfo[0 : 20])),
            bytes32(intentInfo[20 : 52]),
            intentInfo[52 : ]
        );
    }

    function _getIntentInfo(
        uint256 offset,
        uint256 length,
        bytes calldata envelopeTx
    ) internal pure returns (
        address _validator,
        bytes32 _policy,
        bytes calldata intent
    ) {
        return _decodeIntentInfo(
            _sliceEnvelopeTx(
                offset, 
                length, 
                envelopeTx
            )
        );
    }

    function _sliceEnvelopeTx(
        uint256 offset,
        uint256 length,
        bytes calldata envelopeTx
    ) internal pure returns (
        bytes calldata intentInfo
    ) {
        require(length >= 52, LengthTooShort(length));
        return envelopeTx[offset : offset + length];
    }

    function _decodePolicy(bytes32 _policy) 
        internal 
        pure 
        returns (
            bool isCacheEnvelopeTx,
            bool isCacheIntent,
            bool isCacherContext
        ) 
    {
        return (
            uint256(_policy >> 255) == 1,
            (uint256(_policy >> 254) & 1) == 1,
            (uint256(_policy >> 253) & 1) == 1
        );
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
