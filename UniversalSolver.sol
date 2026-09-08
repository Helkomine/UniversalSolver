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
        bytes intent;
    }

    struct UserEnvelopeTx {
        address sender;
        uint256 sliceInfo;
        bytes envelopeTx;
    }

    struct ResolverSolution {
        address resolver;
        bytes32 policy;
        bytes solution;
    }

    function resolve(
        UserEnvelopeTx calldata userEnvelopeTx, 
        ResolverSolution calldata resolverSolution
    ) external;

    function senderCallback(bytes calldata validatorAndIntent) external;

    function context() external view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        uint256 _sliceInfo,
        bool _intentAccepted,
        UserIntent memory userIntent,
        ResolverSolution memory resolverSolution,
        bytes memory userContext,
        bytes memory resolverContext
    );

    function fullContext() external view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        bool _intentAccepted,
        bool _isSolverActive,
        UserEnvelopeTx memory userEnvelopeTx,
        ResolverSolution memory resolverSolution,
        bytes memory userContext,
        bytes memory resolverContext
    );
}

contract UniversalSolver is IUniversalSolver {
    uint128 public constant MAX_TOTAL_SLOT = type(uint128).max;
    uint256 public constant SLICE_INFO_MASKING = type(uint128).max;
    bytes32 public constant ENVELOPE_TX_SLOT = bytes32(erc7201("envelope.tx.slot"));
    bytes32 public constant INTENT_SLOT = bytes32(erc7201("intent.slot"));
    bytes32 public constant SOLUTION_SLOT = bytes32(erc7201("solution.slot"));
    bytes32 public constant USER_CONTEXT_SLOT = bytes32(erc7201("user.context.slot"));
    bytes32 public constant RESOLVER_CONTEXT_SLOT = bytes32(erc7201("resolver.context.slot"));

    address public transient sender;
    address public transient validator;
    address public transient resolver;
    address public transient initator;
    bytes32 public transient policy;
    // Lưu trữ intentHash dùng để xác thực intent.
    bytes32 public transient intentHash;
    bytes32 public transient solutionHash;
    uint256 public transient sliceInfo;
    // Biến nội bộ để xác minh intent đã được user chấp thuận trong giai đoạn callback hay không.
    bool public transient intentAccepted;
    // Biến nội bộ dùng để chống reentrancy và mở khóa thực thi cho hàm callback.
    bool public transient isSolverActive;

    error Reentrancy();
    error IntentNotAccepted();
    error InactiveSolver();
    error LengthTooShort(uint256 length);
    error TotalSlotTooLarge(uint256 totalSlot);
    error CallRequesterContextFailed(address validator, bytes reason);
    error CallResolverContextFailed(address resolver, bytes reason);
    error InvalidSender(address sender);
    error IntentAccepted(address validator, bytes intent);
    error InvalidIntent(address validator, bytes intent);
    error ValidateIntentFailed(bytes result);
    error RequesterFailed(bytes result);
    error SolverFailed(bytes result);

    // Tránh stack too deep
    struct Flags {
        bool isCacheEnvelopeTx;
        bool isCacheIntent;
        bool isCacheSolution;
        bool isCacheResolverContext;
    }

    // Tránh stack too deep
    struct SilceInfo {
        uint256 offset;
        uint256 length;
    }

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

    function resolve(
        UserEnvelopeTx calldata userEnvelopeTx, 
        ResolverSolution calldata resolverSolution
    ) public nonReentrant {
        Flags memory flags;
        (
            flags.isCacheEnvelopeTx,
            flags.isCacheIntent,
            flags.isCacheSolution,
            flags.isCacheResolverContext
        ) = decodePolicy(resolverSolution.policy);

        SilceInfo memory _sliceInfo;
        (_sliceInfo.offset, _sliceInfo.length) = getOffsetAndLength(userEnvelopeTx.sliceInfo);

        (address _validator, bytes calldata intent) 
        = getValidatorAndIntent(
            _sliceInfo.offset,
            _sliceInfo.length,
            userEnvelopeTx.envelopeTx
        );

        _cacheEnvelopeTx(flags.isCacheEnvelopeTx, userEnvelopeTx.envelopeTx);
        _cacheIntent(flags.isCacheIntent, intent);
        _cacheSolution(flags.isCacheSolution, resolverSolution.solution);
        _cacheUserContext(_validator, intent);
        _cacheResolverContext(
            flags.isCacheResolverContext,
            getResolver(resolverSolution),
            resolverSolution.solution
        );
        _setContext(
            userEnvelopeTx.sender,
            _validator,
            getResolver(resolverSolution),
            msg.sender,
            resolverSolution.policy,
            keccak256(
                sliceEnvelopeTx(
                    _sliceInfo.offset,
                    _sliceInfo.length,
                    userEnvelopeTx.envelopeTx
                )
            ), 
            keccak256(resolverSolution.solution),
            userEnvelopeTx.sliceInfo
        );
        _validateOnSender(userEnvelopeTx.sender, userEnvelopeTx.envelopeTx);
        _resolveSolution(getResolver(resolverSolution), resolverSolution.solution);
        _validateIntent(_validator, intent);

        // Xóa các thông tin về intent và hoàn tất chu trình làm việc.
        _clearContext();
    }

    // Đây là hàm nhận callback từ sender
    function senderCallback(bytes calldata validatorAndIntent) external onlySolverActive {
        // Xác minh người gọi có phải là user đã được chỉ định trong UserIntent không..
        require(msg.sender == sender, InvalidSender(sender));
        (address _validator, bytes calldata intent) = decodeValidatorAndIntent(validatorAndIntent);
        // Nếu intent đã được xác thực hàm này sẽ hoàn tác.
        if (intentAccepted) revert IntentAccepted(_validator, intent);
        // Kiểm tra intent được user gọi có giống với intent đã được chỉ định trong UserIntent không.
        require(keccak256(validatorAndIntent) == intentHash, InvalidIntent(_validator, intent));
        // Đánh dấu intent này là hợp lệ để sẵn sàng giải quyết.
        intentAccepted = true;
    }

    function context() public view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        uint256 _sliceInfo,
        bool _intentAccepted,
        UserIntent memory userIntent,
        ResolverSolution memory resolverSolution,
        bytes memory userContext,
        bytes memory resolverContext
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

    function getResolver(
        ResolverSolution calldata resolverSolution
    ) public view returns (address) {
        return resolverSolution.resolver != address(0) 
            ? resolverSolution.resolver 
            : msg.sender;
    }

    function getOffsetAndLength(uint256 _sliceInfo) 
        public 
        pure 
        returns (uint256 offset, uint256 length) 
    {
        return (_sliceInfo >> 128, _sliceInfo & SLICE_INFO_MASKING);
    }

    function decodeValidatorAndIntent(
        bytes calldata validatorAndIntent
    ) public pure returns (
        address _validator,
        bytes calldata intent
    ) {
        return (
            address(bytes20(validatorAndIntent[0 : 20])),
            validatorAndIntent[20 : ]
        );
    }

    function getValidatorAndIntent(
        uint256 offset,
        uint256 length,
        bytes calldata envelopeTx
    ) public pure returns (
        address _validator,
        bytes calldata intent
    ) {
        bytes calldata validatorAndIntent 
        = sliceEnvelopeTx(
            offset, 
            length, 
            envelopeTx
        );
        return (
            address(bytes20(validatorAndIntent[0 : 20])),
            validatorAndIntent[20 : ]
        );
    }

    function sliceEnvelopeTx(
        uint256 offset,
        uint256 length,
        bytes calldata envelopeTx
    ) public pure returns (
        bytes calldata validatorAndIntent
    ) {
        require(length >= 20, LengthTooShort(length));
        return envelopeTx[offset : offset + length];
    }

    function getUserIntent(
        UserEnvelopeTx calldata userEnvelopeTx
    ) public pure returns (
        UserIntent memory userIntent
    ) {
        (uint256 offset, uint256 length) = getOffsetAndLength(userEnvelopeTx.sliceInfo);
        (address _validator, bytes calldata intent) 
        = getValidatorAndIntent(
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

    function decodePolicy(bytes32 _policy) 
        public 
        pure 
        returns (
            bool isCacheEnvelopeTx,
            bool isCacheIntent,
            bool isCacheSolution,
            bool isCacheResolverContext
        ) 
    {
        return (
            uint256(_policy >> 255) == 1,
            (uint256(_policy >> 254) & 1) == 1,
            (uint256(_policy >> 253) & 1) == 1,
            (uint256(_policy >> 252) & 1) == 1
        );
    }

    function _setContext(
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

    function _clearContext() internal {
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

    function _validateOnSender(address _sender, bytes calldata envelopeTx) internal {
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
        bool isCacheEnvelopeTx,
        bytes calldata envelopeTx
    ) internal {
        if (isCacheEnvelopeTx) {
            _setCacheCallData(ENVELOPE_TX_SLOT, envelopeTx);
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

    function _cacheSolution(
        bool isCacheSolution,
        bytes calldata solution
    ) internal {
        if (isCacheSolution) {
            _setCacheCallData(SOLUTION_SLOT, solution);
        }
    }

    function _cacheUserContext(address _validator, bytes calldata intent) internal {
        uint256 ptr = _getFreePtr();
        (bool success, bytes memory userContext) = _validator.staticcall(intent);
        require(success, CallRequesterContextFailed(_validator, intent));
        _setCacheData(USER_CONTEXT_SLOT, userContext);
        _restoreFreePtr(ptr);
    }

    function _cacheResolverContext(
        bool isCacheResolverContext,
        address _resolver,
        bytes calldata solution
    ) internal {
        if (isCacheResolverContext) {
            uint256 ptr = _getFreePtr();
            (bool success, bytes memory resolverContext) = _resolver.staticcall(solution);
            require(success, CallResolverContextFailed(_resolver, resolverContext));
            _setCacheData(RESOLVER_CONTEXT_SLOT, resolverContext);
            _restoreFreePtr(ptr);
        }
    }

    function _resolveSolution(
        address _resolver,
        bytes calldata solution
    ) internal {
        uint256 ptr = _getFreePtr();
        // Solver chuyển giao toàn bộ công việc cho resolver, resolver được tự do lựa chọn phương án
        // giải quyết theo các điều kiện mà intent đặt ra.
        (bool success, bytes memory result) = _resolver.call(solution);
        require(success, SolverFailed(result));
        emit ResolvePhaseSuccess(_resolver, result);
        _restoreFreePtr(ptr);
    }

    function _validateIntent(address _validator, bytes calldata intent) internal {
        uint256 ptr = _getFreePtr();
        (bool success, bytes memory result) = _validator.call(intent);
        require(success, RequesterFailed(result));
        emit ValidateIntentPhaseSuccess(_validator, result);
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
            if length {
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
