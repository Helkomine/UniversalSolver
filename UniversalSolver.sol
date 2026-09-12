// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
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
    address constant PRECOMPILE_ADDRESS_RANGE = address(65535);
    uint64 constant MAX_TOTAL_LENGTH = type(uint64).max;
    uint256 constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 constant USER_ENVELOPE_TX_SLOT = bytes32(erc7201("user.envelope.tx.slot"));
    bytes32 constant USER_INTENT_SLOT = bytes32(erc7201("user.intent.slot"));
    bytes32 constant USER_CONTEXT_SLOT = bytes32(erc7201("user.context.slot"));
    bytes32 constant INTENT_HASHES_SLOT = bytes32(erc7201("intent.hashes.slot"));
    bytes32 constant SENDER_INDEX_SLOT = bytes32(erc7201("sender.index.slot"));

    address public transient initator;
    address public transient validSenderCallback;
    bool public transient isSolverActive;

    error Reentrancy();
    error InactiveSolver();
    error IntentNotAccepted();
    error LengthTooShort(uint256 length);
    error TotalSlotTooLarge(uint256 totalSlot);
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
        address _initator,
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
        return (initator, intentHash, userIntent, userContext);
    }

    function fullContext() public view returns (
        address _initator,
        address _validSenderCallback,
        bool _isSolverActive,
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
            initator,
            validSenderCallback,
            isSolverActive,
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

            _cacheUserEnvelopeTx(i, isCacheUserEnvelopeTx, userEnvelopeTx);
            _cacheUserIntent(i, isCacheUserIntent, userEnvelopeTx.sender, validator, policy, intent);
            _cacheUserContext(i, isCacheUserContext, userEnvelopeTx.sender, validator, intent);
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
        uint256 index,
        bool isCacheUserEnvelopeTx,
        UserEnvelopeTx calldata userEnvelopeTx
    ) internal {
        if (isCacheUserEnvelopeTx) {
            bytes32 slot = _getHashedSlot(USER_ENVELOPE_TX_SLOT, index);
            unchecked {
                _tstore(slot, uint256(uint160(userEnvelopeTx.sender)));
                _tstore(bytes32(uint256(slot) + 1), userEnvelopeTx.sliceInfo);
            }
            _setCacheCallData(bytes32(uint256(slot) + 2), userEnvelopeTx.envelopeTx);
            emit CacheUserEnvelopeTx(userEnvelopeTx);
        }
    }

    function _cacheUserIntent(
        uint256 index, 
        bool isCacheUserIntent,
        address sender,
        address validator,
        bytes32 policy,
        bytes calldata intent
    ) internal {
        if (isCacheUserIntent) {
            bytes32 slot = _getHashedSlot(USER_INTENT_SLOT, index);
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
            _setCacheData(_getHashedSlot(USER_CONTEXT_SLOT, index), userContext);
            emit CacheUserContext(sender, validator, userContext);
            _restoreFreePtr(ptr);
        }
    }

    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := data.length
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot
            {
                let _cacheLength := add(cacheLength, 31)
                if gt(cacheLength, _cacheLength) {
                    revert(0, 0)
                }
                totalCacheSlot := shr(5, _cacheLength)
            }
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    revert(0, 0)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    revert(0, 0)
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
            switch gt(totalCacheSlot, totalSlot)
            case 0 {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, errorSelector)
                    mstore(4, cacheLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    revert(0, 0)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            } default {
                if gt(length, maxTotalLength) {
                    mstore(0, errorSelector)
                    mstore(4, length)
                    revert(0, 36)
                }
            }
        }
    }

    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := mload(data)
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot := shr(5, add(cacheLength, 31))
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    revert(0, 0)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    revert(0, 0)
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
            switch gt(totalCacheSlot, totalSlot) 
            case 0 {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, errorSelector)
                    mstore(4, maxTotalLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    revert(0, 0)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            } default {
                if gt(length, maxTotalLength) {
                    mstore(0, errorSelector)
                    mstore(4, length)
                    revert(0, 36)
                }
            }
        }
    }

    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            data := mload(64)
            let length := tload(namespace)
            mstore(data, length)
            let offset := add(data, 32)
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                if gt(length, maxTotalLength) {
                    mstore(0, errorSelector)
                    mstore(4, length)
                    revert(0, 36)
                }
                let lastSlot := add(namespace, floorTotalSlot)
                {
                    let _namespace := add(namespace, 1)
                    if gt(namespace, _namespace) {
                        revert(0, 0)
                    }
                    namespace := _namespace
                    if gt(namespace, lastSlot) {
                        revert(0, 0)
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
        require(msg.sender > PRECOMPILE_ADDRESS_RANGE, InitatorIsPrecompiler(msg.sender));
        initator = msg.sender;
    }

    function _markPhase2Pass() internal {
        validSenderCallback = address(2);
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
