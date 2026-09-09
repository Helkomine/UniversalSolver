// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

interface IUniversalSolver {
    event ContextPhaseSuccess();
    event ValidateSenderPhaseSuccess(address indexed sender, bytes result);
    event ResolvePhaseSuccess(address indexed resolver, bytes result);
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
        bool _intentAccepted,
        uint256[] memory _sliceInfo,
        bytes32[] memory _intentHash,
        UserIntent[] memory userIntent,
        bytes[] memory userContext
    );

    function fullContext() external view returns (
        address _initator,
        bool _intentAccepted,
        bool _isSolverActive,
        bytes32[] memory _intentHash,
        UserEnvelopeTx[] memory userEnvelopeTx,
        bytes[] memory userContext
    );
}

contract UniversalSolver is IUniversalSolver {
    uint128 public constant MAX_TOTAL_SLOT = type(uint128).max;
    uint256 public constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 public constant ENVELOPE_TX_SLOT = bytes32(erc7201("envelope.tx.slot"));
    bytes32 public constant INTENT_SLOT = bytes32(erc7201("intent.slot"));
    bytes32 public constant USER_CONTEXT_SLOT = bytes32(erc7201("user.context.slot"));

    address public transient initator;
    address public transient validSenderCallback;
    address[] public transient sender;
    address[] public transient validator;
    bytes32[] public transient policy;
    bytes32[] public transient intentHash;
    uint256[] public transient sliceInfo;
    bytes[] public envelopeTxs;
    bytes[] public intents;
    bytes[] public contexts;
    // Biến nội bộ để xác minh intent đã được user chấp thuận trong giai đoạn callback hay không.
    bool public transient intentAccepted;
    // Biến nội bộ dùng để chống reentrancy và mở khóa thực thi cho hàm callback.
    bool public transient isSolverActive;

    error Reentrancy();
    error IntentNotAccepted();
    error InactiveSolver();
    error LengthTooShort(uint256 length);
    error TotalSlotTooLarge(uint256 totalSlot);
    error InvalidSender(address sender);
    error ValidateSenderFailed(bytes result);
    error ValidateIntentFailed(bytes result);
    error ResolveFailed(bytes result);
    error CallUserContextFailed(address validator, bytes reason);
    error CallResolverContextFailed(address resolver, bytes reason);
    error IntentAccepted(address validator, bytes intent);
    error InvalidIntent(address validator, bytes intent);

    modifier nonReentrant {
        if (isSolverActive) revert Reentrancy();
        isSolverActive = true;
        _;
        isSolverActive = false;
    }

    // Kiểm tra Solver có đang chạy không.
    modifier onlySolverActive {
        require(isSolverActive, InactiveSolver());
        _;
    }

    function _getSlot(
        bytes32 namespace,
        uint256 index
    ) internal view returns (bytes32 slot) {
        assembly ("memory-safe") {
            length := tload(namespace)
            switch lt(index, length)
            case 0 {
                revert(0, 0)
            } default {
                mstore(0, namespace)
                mstore(32, index)
                slot := keccak256(0, 64)
            }
        }
    }

    function _appendCallData(
        bytes32 namespace,
        uint256 index,
        bytes calldata data
    ) internal {
        _setCacheCallData(_getSlot(namespace, index), data);
    }

    function _appendData(
        bytes32 namespace,
        uint256 index,
        bytes memory data
    ) internal {
        _setCacheData(_getSlot(namespace, index), data);
    }

    function _allocate(bytes32 namespace, uint256 length) internal {
        assembly ("memory-safe") {
            tstore(namespace, length)
        }
    }

    function resolve(UserEnvelopeTx[] calldata userEnvelopeTxs) public nonReentrant {
        for (uint256 i = 0 ; i < userEnvelopeTxs.length ; i++) {
            UserEnvelopeTx calldata userEnvelopeTx = userEnvelopeTxs[i];

            (address _validator, bytes calldata intent) 
            = _getValidatorAndIntent(
                _sliceInfo.offset,
                _sliceInfo.length,
                userEnvelopeTx.envelopeTx
            );

            _setContext(
                userEnvelopeTx.sender,
                _validator,
                _getResolver(resolverSolution.resolver),
                msg.sender,
                resolverSolution.policy,
                keccak256(
                    _sliceEnvelopeTx(
                        _sliceInfo.offset,
                        _sliceInfo.length,
                        userEnvelopeTx.envelopeTx
                    )
                ), 
                keccak256(resolverSolution.solution),
                userEnvelopeTx.sliceInfo
            );
            _validateSender(userEnvelopeTx.sender, userEnvelopeTx.envelopeTx);
            _executeIntent(_validator, intent);
        }
    }

    // Đây là hàm nhận callback từ sender
    function senderCallback(bytes calldata validatorAndIntent) external onlySolverActive {
        // Xác minh người gọi có phải là user đã được chỉ định trong UserIntent không..
        require(msg.sender == validSenderCallback, InvalidSender(validSenderCallback));
        (address _validator, bytes calldata intent) = _decodeValidatorAndIntent(validatorAndIntent);
        // Nếu intent đã được xác thực hàm này sẽ hoàn tác.
        if (intentAccepted) revert IntentAccepted(_validator, intent);
        // Kiểm tra intent được user gọi có giống với intent đã được chỉ định trong UserIntent không.
        require(keccak256(validatorAndIntent) == intentHash, InvalidIntent(_validator, intent));
        // Đánh dấu intent này là hợp lệ để sẵn sàng giải quyết.
        intentAccepted = true;
    }

    function _setContext(uint256 index, UserEnvelopeTx calldata userEnvelopeTx) internal {
        (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);

        (
            address _validator,
            bytes32 _policy,
            bytes calldata intent
        ) = _getIntentInfo(userEnvelopeTx.envelopeTx);

        (
            bool isCacheEnvelopeTx,
            bool isCacheIntent,
            bool isCacheUserContext
        ) = _decodePolicy(_policy);

        _cacheEnvelopeTx(index, isCacheEnvelopeTx, userEnvelopeTx.envelopeTx);
        _cacheIntent(index, isCacheIntent, intent);
        _cacheContext(index, isCacheUserContext, intent);
    }

    function context() public view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        uint256 _sliceInfo,
        bool _intentAccepted,
        UserIntent memory userIntent,
        bytes memory userContext
    ) {
        return (
            initator,
            intentHash,
            solutionHash,
            sliceInfo,
            intentAccepted,
            UserIntent(
                sender,
                validator,
                getCacheData(INTENT_SLOT)
            ),
            ResolverSolution(
                resolver,
                policy,
                getCacheData(SOLUTION_SLOT)
            ),
            getCacheData(USER_CONTEXT_SLOT),
            getCacheData(RESOLVER_CONTEXT_SLOT)
        );
    }

    function fullContext() public view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        bool _intentAccepted,
        bool _isSolverActive,
        UserEnvelopeTx memory userEnvelopeTx,
        ResolverSolution memory resolverSolution,
        bytes memory userContext,
        bytes memory resolverContext
    ) {
        return (
            initator,
            intentHash,
            solutionHash,
            intentAccepted,
            isSolverActive,
            UserEnvelopeTx(
                sender,
                sliceInfo,
                getCacheData(ENVELOPE_TX_SLOT)
            ),
            ResolverSolution(
                resolver,
                policy,
                getCacheData(SOLUTION_SLOT)
            ),
            getCacheData(USER_CONTEXT_SLOT),
            getCacheData(RESOLVER_CONTEXT_SLOT)
        );
    }

    function getUserIntent(
        UserEnvelopeTx calldata userEnvelopeTx
    ) public pure returns (
        UserIntent memory userIntent
    ) {
        (uint256 offset, uint256 length) = _getOffsetAndLength(userEnvelopeTx.sliceInfo);
        (address _validator, bytes calldata intent) 
        = _getValidatorAndIntent(
            offset,
            length,
            userEnvelopeTx.envelopeTx
        );
        return UserIntent(
            userEnvelopeTx.sender,
            _validator,
            intent
        );
    }

    function _setInternalContext(
        address _sender,
        address _validator,
        address _resolver,
        address _initator,
        bytes32 _policy,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        uint256 _sliceInfo
    ) internal {
        sender = _sender;
        validator = _validator;
        resolver = _resolver;
        initator = _initator;
        policy = _policy;
        intentHash = _intentHash;
        solutionHash = _solutionHash;
        sliceInfo = _sliceInfo;
        emit ContextPhaseSuccess();
    }

    function _clearInternalContext() internal {
        sender = address(0);
        validator = address(0);
        resolver = address(0);
        initator = address(0);
        policy = 0;
        intentHash = 0;
        solutionHash = 0;
        sliceInfo = 0;
        intentAccepted = false;
        _clearCacheData(ENVELOPE_TX_SLOT);
        _clearCacheData(INTENT_SLOT);
        _clearCacheData(SOLUTION_SLOT);
        _clearCacheData(USER_CONTEXT_SLOT);
        _clearCacheData(RESOLVER_CONTEXT_SLOT);
    }

    function _validateSender(address _sender, bytes calldata envelopeTx) internal {
        uint256 ptr = _getFreePtr();
        // Solver gọi đến user để xác thực và thiết lập môi trường cần thiết, chẳng hạn chuyển số dư
        // cần hoán đổi đến địa chỉ dễ tiếp cận để cho phép resolver giải quyết ở vào giai đoạn sau.
        (bool success, bytes memory result) = _sender.call(envelopeTx);
        // Solver revert nếu user bị lỗi vì bất kỳ lý do gì.
        require(success, ValidateIntentFailed(result));
        // Solver revert nếu intent chưa được chấp thuận, đảm bảo an toàn ngay cả khi tài khoản user
        // không thể từ chối intent không hợp lệ đúng cách, khi đó toàn bộ thao tác phụ như di chuyển
        // số dư đều được khôi phục làm cho tài khoản user trở lại nguyên trạng.
        require(intentAccepted, IntentNotAccepted());
        // Phát log sau khi đã được xác thực hoàn tất.
        emit ValidateSenderPhaseSuccess(_sender, result);
        _restoreFreePtr(ptr);
    }

    function _cacheEnvelopeTx(
        uint256 index,
        bool isCacheEnvelopeTx,
        bytes calldata envelopeTx
    ) internal {
        if (isCacheEnvelopeTx) {
            _appendCallData(ENVELOPE_TX_SLOT, index, envelopeTx);
        }
    }

    function _cacheIntent(
        bool isCacheIntent,
        bytes calldata intent
    ) internal {
        if (isCacheIntent) {
            _setCacheCallData(INTENT_SLOT, intent);
        }
    }

    function _cacheContext(address _validator, bytes calldata intent) internal {
        uint256 ptr = _getFreePtr();
        (bool success, bytes memory userContext) = _validator.staticcall(intent);
        require(success, CallUserContextFailed(_validator, intent));
        _setCacheData(USER_CONTEXT_SLOT, userContext);
        _restoreFreePtr(ptr);
    }

    function _executeIntent(
        address _resolver,
        bytes calldata solution
    ) internal {
        uint256 ptr = _getFreePtr();
        // Solver chuyển giao toàn bộ công việc cho resolver, resolver được tự do lựa chọn phương án
        // giải quyết theo các điều kiện mà intent đặt ra.
        (bool success, bytes memory result) = _resolver.call(solution);
        require(success, ResolveFailed(result));
        emit ResolvePhaseSuccess(_resolver, result);
        _restoreFreePtr(ptr);
    }

    function getCacheData(bytes32 namespace) 
        public 
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
            intentInfo[20 : 52],
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
        bytes calldata intentInfo 
        = _sliceEnvelopeTx(
            offset, 
            length, 
            envelopeTx
        );
        return(
            address(bytes20(intentInfo[0 : 20])),
            intentInfo[20 : 52],
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
