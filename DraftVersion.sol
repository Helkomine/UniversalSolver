// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
// This file contains a reimplementation of the `_setCacheCallData`, `_setCacheData`, and `_getCacheData` functions, designed for better readability compared to the pure assembly versions. However, as the results did not meet expectations, this version was not adopted as the official implementation; please do not use it, as it has not been audited.
/// @author Helkomine (@Helkomine)

interface IUniversalSolver {
    event CacheUserEnvelopeTx(UserEnvelopeTx userEnvelopeTx);
    event CacheUserIntent(UserIntent userIntent);
    event CacheUserContext(address indexed sender, address indexed validator, bytes userContext);
    event ContextPhaseSuccess();
    event ValidateSenderSuccess(address indexed sender, bytes result);
    event ValidateSenderPhaseSuccess();
    event SenderCallbackSuccess(address indexed sender, bytes result);
    event ValidateIntentSuccess(address indexed validator, bytes result);
    event ValidateIntentPhaseSuccess();

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
        UserEnvelopeTx[] calldata userEnvelopeTxs
    ) external;

    function senderCallback(bytes calldata intentInfo) external;

    function senderIndex(address sender) external view returns (uint256 index);

    function context() external view returns (
        bool _isSolverActive,
        address _initator,
        address _validSenderCallback,
        bytes32[] memory intentHash,
        UserIntent[] memory userIntent,
        bytes[] memory userContext
    );

    function fullContext() external view returns (
        bool _isSolverActive,
        address _initator,
        address _validSenderCallback,
        bytes32[] memory intentHash,
        UserEnvelopeTx[] memory userEnvelopeTx,
        bytes[] memory userContext
    );
}

contract UniversalSolver is IUniversalSolver {
    address constant PRECOMPILE_ADDRESS_RANGE = address(65535);
    uint64 constant MAX_TOTAL_LENGTH = type(uint64).max;
    uint256 constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 constant USER_ENVELOPE_TX_SLOT = bytes32(erc7201("user.envelope.tx.slot"));
    bytes32 constant USER_INTENT_SLOT = bytes32(erc7201("user.intent.slot"));
    bytes32 constant USER_CONTEXT_SLOT = bytes32(erc7201("user.context.slot"));
    bytes32 constant INTENT_HASHES_SLOT = bytes32(erc7201("intent.hashes.slot"));
    bytes32 constant SENDER_INDEX_SLOT = bytes32(erc7201("sender.index.slot"));

    bool public transient isSolverActive;
    address public transient initator;
    address public transient validSenderCallback;

    error Overflow();
    error Reentrancy();
    error InactiveSolver();
    error IntentNotAccepted();
    error LengthTooShort(uint256 length);
    error TotalLengthTooLarge(uint256 totalLength);
    error InitatorIsPrecompiler(address initator);
    error SenderIsPrecompiler(address sender);
    error InvalidSender(address sender);
    error ValidateSenderFailed(bytes result);
    error ExecuteIntentFailed(bytes result);
    error UserContextFailed(address validator, bytes reason);
    error IntentAccepted(address validator, bytes32 policy, bytes intent);
    error InvalidIntent(address validator, bytes32 policy, bytes intent);

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

    function resolve(UserEnvelopeTx[] calldata userEnvelopeTxs) public nonReentrant {
        _setContextPhase(userEnvelopeTxs);
        _validateSenderPhase(userEnvelopeTxs);
        _executeIntentPhase(userEnvelopeTxs);
        _clearContext(userEnvelopeTxs);
    }

    function senderCallback(bytes calldata intentInfo) external onlySolverActive {
        require(msg.sender == validSenderCallback, InvalidSender(validSenderCallback));
        
        (address validator, bytes32 policy, bytes calldata intent)
        = _decodeIntentInfo(intentInfo);

        if (validSenderCallback == address(1)) revert IntentAccepted(validator, policy, intent);
        // Kiểm tra intent được user gọi có giống với intent đã được chỉ định trong UserIntent không.
        bytes32 intentHash
        = bytes32(_tload(bytes32(
            (uint256(INTENT_HASHES_SLOT) + 1)
            + _getMapAddressToUint256(SENDER_INDEX_SLOT, msg.sender)))
        );
        require(keccak256(intentInfo) == intentHash, InvalidIntent(validator, policy, intent));
        // Đánh dấu intent này là hợp lệ để sẵn sàng giải quyết.
        validSenderCallback = address(1);
        emit SenderCallbackSuccess(msg.sender, intent);
    }

    function senderIndex(address sender) public view returns (uint256 index) {
        return _getMapAddressToUint256(SENDER_INDEX_SLOT, sender);
    }

    function context() public view returns (
        bool _isSolverActive,
        address _initator,
        address _validSenderCallback,
        bytes32[] memory intentHash,
        UserIntent[] memory userIntent,
        bytes[] memory userContext
    ) {
        uint256 length = _tload(USER_INTENT_SLOT);
        intentHash = new bytes32[](length);
        userIntent = new UserIntent[](length);
        userContext = new bytes[](length);
        for (uint256 i = 0 ; i < length ; ) {
            intentHash[i] = bytes32(_tload(bytes32((uint256(INTENT_HASHES_SLOT) + 1) + i)));
            userIntent[i] = _getUserIntent(USER_INTENT_SLOT, i);
            userContext[i] = _getCacheData(_getHashedSlot(USER_CONTEXT_SLOT, i));
            unchecked { ++i; }
        }
        return (isSolverActive, initator, validSenderCallback, intentHash, userIntent, userContext);
    }

    function fullContext() public view returns (
        bool _isSolverActive,
        address _initator,
        address _validSenderCallback,
        bytes32[] memory intentHash,
        UserEnvelopeTx[] memory userEnvelopeTx,
        bytes[] memory userContext
    ) {
        uint256 length = _tload(USER_ENVELOPE_TX_SLOT);
        intentHash = new bytes32[](length);
        userEnvelopeTx = new UserEnvelopeTx[](length);
        userContext = new bytes[](length);
        for (uint256 i = 0 ; i < length ; ) {
            intentHash[i] = bytes32(_tload(bytes32((uint256(INTENT_HASHES_SLOT) + 1) + i)));
            userEnvelopeTx[i] = _getUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i);
            userContext[i] = _getCacheData(_getHashedSlot(USER_CONTEXT_SLOT, i));
            unchecked { ++i; }
        }
        return (
            isSolverActive,
            initator,
            validSenderCallback,
            intentHash,
            userEnvelopeTx,
            userContext
        );
    }

    function _setContextPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        _tstore(USER_ENVELOPE_TX_SLOT, userEnvelopeTxs.length);
        _tstore(USER_INTENT_SLOT, userEnvelopeTxs.length);
        _tstore(USER_CONTEXT_SLOT, userEnvelopeTxs.length);
        _tstore(INTENT_HASHES_SLOT, userEnvelopeTxs.length);
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; i++) {
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            require(userEnvelopeTx.sender > PRECOMPILE_ADDRESS_RANGE, 
                SenderIsPrecompiler(userEnvelopeTx.sender)
            );

            (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

            bytes calldata intentInfo
            = _sliceEnvelopeTx(offset, length, userEnvelopeTx.envelopeTx);

            (address validator, bytes32 policy, bytes calldata intent)
            = _decodeIntentInfo(intentInfo);

            (bool isCacheUserEnvelopeTx, bool isCacheUserIntent, bool isCacheUserContext)
            = _decodePolicy(policy);

            _cacheUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i, isCacheUserEnvelopeTx, userEnvelopeTx);
            _cacheUserIntent(
                USER_INTENT_SLOT,
                i,
                isCacheUserIntent,
                userEnvelopeTx.sender,
                validator,
                policy,
                intent
            );
            _cacheUserContext(
                USER_CONTEXT_SLOT,
                i,
                isCacheUserContext,
                userEnvelopeTx.sender,
                validator,
                intent
            );
            _tstore(
                bytes32((uint256(INTENT_HASHES_SLOT) + 1) + i),
                uint256(keccak256(intentInfo))
            );
            _setMapAddressToUint256(SENDER_INDEX_SLOT, userEnvelopeTx.sender, i);
        }
        emit ContextPhaseSuccess();
        _markPhase1Pass();
    }

    function _validateSenderPhase(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; ) {
            uint256 ptr = _getFreePtr();
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            validSenderCallback = userEnvelopeTx.sender;
            (bool success, bytes memory result)
            = userEnvelopeTx.sender.call(userEnvelopeTx.envelopeTx);
            require(success, ValidateSenderFailed(result));
            require(validSenderCallback == address(1), IntentNotAccepted());

            emit ValidateSenderSuccess(userEnvelopeTx.sender, result);
            _restoreFreePtr(ptr);
            unchecked { ++i; }
        }
        emit ValidateSenderPhaseSuccess();
        _markPhase2Pass();
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
            emit ValidateIntentSuccess(validator, result);

            _restoreFreePtr(ptr);
            unchecked { ++i; }
        }
        emit ValidateIntentPhaseSuccess();
    }

    function _clearContext(UserEnvelopeTx[] calldata userEnvelopeTxs) internal {
        initator = address(0);
        validSenderCallback = address(0);
        uint256 length = _tload(USER_ENVELOPE_TX_SLOT);
        _tstore(USER_ENVELOPE_TX_SLOT, 0);
        _tstore(USER_INTENT_SLOT, 0);
        _tstore(USER_CONTEXT_SLOT, 0);
        _tstore(INTENT_HASHES_SLOT, 0);
        for (uint256 i = 0 ; i < length ; ) {
            _clearUserEnvelopeTx(USER_ENVELOPE_TX_SLOT, i);
            _clearUserIntent(USER_INTENT_SLOT, i);
            _setCacheData(_getHashedSlot(USER_CONTEXT_SLOT, i), new bytes(0));
            _tstore(bytes32(uint256(INTENT_HASHES_SLOT) + 1 + i), 0);
            _setMapAddressToUint256(SENDER_INDEX_SLOT, userEnvelopeTxs[i].sender, 0);
            unchecked { ++i; }
        }
    }

    function _clearUserEnvelopeTx(bytes32 namespace, uint256 index) internal {
        bytes32 slot = _getHashedSlot(namespace, index);
        _tstore(slot, 0);
        _tstore(bytes32(uint256(slot) + 1), 0);
        _setCacheData(bytes32(uint256(slot) + 2), new bytes(0));
    }

    function _clearUserIntent(bytes32 namespace, uint256 index) internal {
        bytes32 slot = _getHashedSlot(namespace, index);
        _tstore(slot, 0);
        _tstore(bytes32(uint256(slot) + 1), 0);
        _tstore(bytes32(uint256(slot) + 2), 0);
        _setCacheData(bytes32(uint256(slot) + 3), new bytes(0));
    }

    function _cacheUserEnvelopeTx(
        bytes32 namespace,
        uint256 index,
        bool isCacheUserEnvelopeTx,
        UserEnvelopeTx calldata userEnvelopeTx
    ) internal {
        if (isCacheUserEnvelopeTx) {
            bytes32 slot = _getHashedSlot(namespace, index);
            unchecked {
                _tstore(slot, uint256(uint160(userEnvelopeTx.sender)));
                _tstore(bytes32(uint256(slot) + 1), userEnvelopeTx.sliceInfo);
            }
            _setCacheCallData(bytes32(uint256(slot) + 2), userEnvelopeTx.envelopeTx);
            emit CacheUserEnvelopeTx(userEnvelopeTx);
        }
    }

    function _cacheUserIntent(
        bytes32 namespace,
        uint256 index, 
        bool isCacheUserIntent,
        address sender,
        address validator,
        bytes32 policy,
        bytes calldata intent
    ) internal {
        if (isCacheUserIntent) {
            bytes32 slot = _getHashedSlot(namespace, index);
            unchecked {
                _tstore(slot, uint256(uint160(sender)));
                _tstore(bytes32(uint256(slot) + 1), uint256(uint160(validator)));
                _tstore(bytes32(uint256(slot) + 2), uint256(policy));
            }
            _setCacheCallData(bytes32(uint256(slot) + 3), intent);
            emit CacheUserIntent(UserIntent(sender, validator, policy, intent));
        }
    }

    function _cacheUserContext(
        bytes32 namespace,
        uint256 index,
        bool isCacheUserContext,
        address sender,
        address validator,
        bytes calldata intent
    ) internal {
        if (isCacheUserContext) {
            uint256 ptr = _getFreePtr();
            (bool success, bytes memory userContext) = validator.staticcall(intent);
            require(success, UserContextFailed(validator, intent));
            _setCacheData(_getHashedSlot(namespace, index), userContext);
            emit CacheUserContext(sender, validator, userContext);
            _restoreFreePtr(ptr);
        }
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

    function _getUserIntent(
        bytes32 namespace,
        uint256 index
    ) internal view returns (UserIntent memory) {
        bytes32 slot = _getHashedSlot(namespace, index);
        unchecked {
            return UserIntent(
                address(uint160(_tload(slot))),
                address(uint160(_tload(bytes32(uint256(slot) + 1)))),
                bytes32(_tload(bytes32(uint256(slot) + 2))),
                _getCacheData(bytes32(uint256(slot) + 3))
            );
        }
    }

    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        unchecked {
            uint256 length = data.length;
            if (length > MAX_TOTAL_LENGTH) revert TotalLengthTooLarge(length);
            uint256 totalSlot = (length + 31) >> 5;
            uint256 cacheLength = _tload(namespace);
            uint256 _cacheLength = cacheLength + 31;
            if (cacheLength > _cacheLength) revert Overflow();
            uint256 totalCacheSlot = _cacheLength >> 5;
            _tstore(namespace, length);
            {
                uint256 _namespace = uint256(namespace) + 1;
                if (uint256(namespace) > _namespace) revert Overflow();
                namespace = bytes32(_namespace);
            }
            if (length > 0) { 
                uint256 floorTotalSlot = length >> 5;
                uint256 lastSlot = uint256(namespace) + floorTotalSlot;
                if (floorTotalSlot > lastSlot) revert Overflow();
                uint256 offset;
                assembly ("memory-safe") { offset := data.offset }
                for (uint256 i = 0 ; i < floorTotalSlot ; i++) {
                    uint256 value;
                    assembly ("memory-safe") {
                        value := calldataload(add(offset, shl(5, i)))
                    }
                    _tstore(bytes32(uint256(namespace) + i), value);
                }
                uint256 roundingLength = floorTotalSlot << 5;
                uint256 bytesLeft = length - roundingLength;
                if (bytesLeft > 0) {
                    uint256 bitsLeft = bytesLeft << 3;
                    uint256 bitPadding = 256 - bitsLeft;
                    uint256 rawWord;
                    assembly ("memory-safe") {
                        rawWord := calldataload(add(offset, roundingLength))
                    }
                    uint256 mask = (rawWord >> bitPadding) << bitPadding;
                    _tstore(bytes32(lastSlot), mask);
                }
            }
            if (totalCacheSlot > totalSlot) {
                if (cacheLength > MAX_TOTAL_LENGTH) revert TotalLengthTooLarge(cacheLength);
                if (uint256(namespace) > (uint256(namespace) + totalCacheSlot)) revert Overflow();
                uint256 slotLeft = totalCacheSlot - totalSlot;
                namespace = bytes32(uint256(namespace) + totalSlot);
                for (uint256 j = 0 ; j < slotLeft ; j++) {
                    _tstore(bytes32(uint256(namespace) + j), 0);
                }
            }
        }
    }

    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        unchecked {
            uint256 length = data.length;
            if (length > MAX_TOTAL_LENGTH) revert TotalLengthTooLarge(length);
            uint256 totalSlot = (length + 31) >> 5;
            uint256 cacheLength = _tload(namespace);
            uint256 _cacheLength = cacheLength + 31;
            if (cacheLength > _cacheLength) revert Overflow();
            uint256 totalCacheSlot = _cacheLength >> 5;
            _tstore(namespace, length);
            {
                uint256 _namespace = uint256(namespace) + 1;
                if (uint256(namespace) > _namespace) revert Overflow();
                namespace = bytes32(_namespace);
            }
            if (length > 0) {
                uint256 floorTotalSlot = length >> 5;
                uint256 lastSlot = uint256(namespace) + floorTotalSlot;
                if (floorTotalSlot > lastSlot) revert Overflow();
                uint256 offset;
                assembly ("memory-safe") { offset := add(data, 32) }
                for (uint256 i = 0 ; i < floorTotalSlot ; i++) {
                    uint256 value;
                    assembly ("memory-safe") {
                        value := mload(add(offset, shr(5, i)))
                    }
                    _tstore(bytes32(uint256(namespace) + i), value);
                }
                uint256 roundingLength = floorTotalSlot << 5;
                uint256 bytesLeft = length - roundingLength;
                if (bytesLeft > 0) {
                    uint256 bitsLeft = bytesLeft << 3;
                    uint256 bitPadding = 256 - bitsLeft;
                    uint256 rawWord;
                    assembly ("memory-safe") {
                        rawWord := mload(add(offset, roundingLength))
                    }
                    uint256 mask = (rawWord >> bitPadding) << bitPadding;
                    _tstore(bytes32(lastSlot), mask);
                }
            }
            if (totalCacheSlot > totalSlot) {
                if (cacheLength > MAX_TOTAL_LENGTH) revert TotalLengthTooLarge(cacheLength);
                if (uint256(namespace) > uint256(namespace) + totalCacheSlot) revert Overflow();
                uint256 slotLeft = totalCacheSlot - totalSlot;
                namespace = bytes32(uint256(namespace) + totalSlot);
                for (uint256 j = 0 ; j < slotLeft ; j++) {
                    _tstore(bytes32(uint256(namespace) + j), 0);
                }
            }
        }
    }

    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        uint256 length = _tload(namespace);
        data = new bytes(length);
        if (length > MAX_TOTAL_LENGTH) revert TotalLengthTooLarge(length);
        uint256 offset;
        assembly ("memory-safe") { offset := add(data, 32) }
        if (length > 0) {
            uint256 floorTotalSlot = length >> 5;
            uint256 totalSlot = (length + 31) >> 5;
            uint256 lastSLot = uint256(namespace) + floorTotalSlot;
            {
                uint256 _namespace = uint256(namespace) + 1;
                if (uint256(namespace) > _namespace) revert Overflow();
                namespace = bytes32(_namespace);
                if (floorTotalSlot > lastSLot) revert Overflow();
            }
            for (uint256 i = 0 ; i < floorTotalSlot ; i++) {
                assembly ("memory-safe") {
                    mstore(add(offset, shl(5, i)), tload(add(namespace, i)))
                }
            }
            uint256 roundingLength = floorTotalSlot << 5;
            uint256 bytesLeft = length - roundingLength;
            if (bytesLeft > 0) {
                uint256 bitsLeft = bytesLeft << 3;
                uint256 bitPadding = 256 - bitsLeft;
                uint256 rawWord = _tload(bytes32(lastSLot));
                uint256 mask = (rawWord >> bitPadding) << bitPadding;
                assembly ("memory-safe") {
                    mstore(add(offset, roundingLength), mask)
                }
            }
        }
    }

    function _markPhase1Pass() internal {
        require(msg.sender > PRECOMPILE_ADDRESS_RANGE, InitatorIsPrecompiler(msg.sender));
        initator = msg.sender;
    }

    function _markPhase2Pass() internal {
        validSenderCallback = address(2);
    }

    function _setMapAddressToUint256(
        bytes32 namespace,
        address key,
        uint256 value
    ) internal {
        _tstore(_getHashedSlot(namespace, uint256(uint160(key))), value);
    }

    function _getMapAddressToUint256(
        bytes32 namespace,
        address key
    ) internal view returns (uint256 value) {
        return _tload(_getHashedSlot(namespace, uint256(uint160(key))));
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

    function _getOffsetAndLength(uint256 _sliceInfo) 
        internal 
        pure 
        returns (uint256 offset, uint256 length) 
    {
        return (_sliceInfo >> 128, _sliceInfo & SLICE_INFO_MASKING);
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
        address validator,
        bytes32 policy,
        bytes calldata intent
    ) {
        return (
            address(bytes20(intentInfo[0 : 20])),
            bytes32(intentInfo[20 : 52]),
            intentInfo[52 : ]
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

    function _decodePolicy(bytes32 policy) 
        internal 
        pure 
        returns (
            bool isCacheUserEnvelopeTx,
            bool isCacheUserIntent,
            bool isCacheUserContext
        ) 
    {
        return (
            uint256(policy >> 255) == 1,
            (uint256(policy >> 254) & 1) == 1,
            (uint256(policy >> 253) & 1) == 1
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
