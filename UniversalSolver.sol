// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

// Đây là hợp đồng bộ giải intent, trong đó requester cung cấp một intent cần được giải quyết bên trong
// đối tượng UserIntent và resolver cung cấp phương án giải quyết thông qua dữ liệu bytes answer.
// Solver thu thập các thông tin này để thực thi thông qua answer và xác nhận hợp lệ thông qua intent.
// Hệ thống offchain nhận UserIntent từ người dùng và phát tán nó qua một mempool công khai, nếu ai đó
// có thể cung cấp được lời giải tương ứng thì sẽ thu gom UserIntent và answer tương ứng gửi vào hợp
// đồng này. Trong đó luồng hoạt động on-chain của UniversalSolver như sau:
// 1. Solver trích xuất intent thông qua slice calldata bằng hai tham số offset và length, intent này
// được hash và lưu vào bộ đệm để xác minh sau này.
// 2. Solver lấy bytes intentAndData để gọi đến tài khoản thông minh của user và chờ đợi phản hồi. Luồng
// thực thi trên tài khoản thông minh không thay đổi, tuy nhiên dữ liệu cho nó phải bao gồm lời gọi đến
// chính solver này để xác minh và có thể thêm các thao tác bổ sung như chuyển token ERC20 nhằm cung cấp
// môi trường cho việc giải quyết, lưu ý rằng thao tác phụ phải diễn ra trước khi callback solver và các
// tài sản phải được gửi đến hợp đồng interpreter vì đó là nơi diễn giải calldata thành chương trình thực thi.
// 3. Tài khoản user callback Solver với chữ ký hàm userCallback(bytes), tại đây Solver xác minh intent
// được gửi đến có trùng khớp với intentHash đã được lưu trước đó hay không, nếu đúng thì chứng tỏ user
// đã chấp thuận intent này trên on-chain tức là Solver được phép chuyển giao công việc cho resolver,
// ngược lại intent này là không hợp lệ và bị revert. Mặc định Solver revert intent không hợp lệ ngay
// cả khi user không thực hiện revert call không hợp lệ để đảm bảo an toàn. Solver cũng phải xác minh
// người gọi có đến từ chính user đó hay không.
// 4. Khi user trả lại quyền kiểm soát cho Solver, hàm giải quyết kiểm tra intent đó đã được user chấp
// nhận hay chưa, nếu không thì revert, ngược lại nó bắt đầu quy trình giải quyết bằng cách chuyển giao
// answer cho resolver, để đơn giản và vì lý do an toàn, Solver luôn chuyển giao answer cho msg.sender,
// điều này yêu cầu resolver phải là một tài khoản có mã để thực thi callback từ phía Solver, trong thời
// gian này resolver có toàn quyền quyết định lộ trình thực thi mà họ mong muốn.
// 5. Sau khi thời gian chạy của resolver kết thúc, Solver chuyển tiếp toàn bộ intent của requester đến
// hợp đồng interpreter, đây là một hợp đồng tiện ích để cho phép thực thi calldata động theo ngữ cảnh
// tương tự một bytecode EVM hoàn chỉnh, calldata bytecode này tiến hành các kiểm tra về số dư và có thể
// thực hiện di chuyển số dư cuối cùng về tài khoản đã được chỉ định. Giao dịch hoàn tất!
// Note: Thiết kế chưa bao gồm cơ chế chống reentrancy, tuy nhiên hàm giải quyết chỉ nên chấp nhận một 
// lần gọi trên mỗi lượt, hàm callback chỉ nên chấp nhận lời gọi một khi hàm giải quyết được kích hoạt
// trước đó, hàm này nên từ chối sau khi đã xác thực intent thành công.
interface IUniversalSolver {
    event ValidateIntentSuccess(bytes intent);
    event RequesterResult(bytes result);
    event SolverResult(bytes result);

    // Đối tượng chứa intent của user
    struct UserIntent {
        // Người nhận intentAndData, phải là tài khoản thông minh để xác thực dữ liệu này
        address sender;
        uint256 offset;
        uint256 length;
        // Dữ liệu cần chuyển tiếp đến user, trong đó luôn mang theo intent. Việc slice calldata để lấy
        // intent là khả thi vì thực tế tài khoản thông minh luôn chấp nhận các đoạn dữ liệu liên tục,
        // chẳng hạn execute(address target, uint256 value, bytes data) luôn có đoạn data liên tục và có
        // thể được tận dụng để chứa intent mà không cần yêu cầu bất kỳ sửa đổi nào trên tài khoản hiện có.
        // Dữ liệu intent được xác định bằng offset và length trong intentAndData, giá trị này có thể
        // được chọn tùy ý tuy nhiên Solver luôn xác thực tính hợp lệ của intent thực tế được requester
        // cung cấp.
        address validator;
        bytes intent;
    }

    struct ResolverSolution {
        bytes32 policy;
        address resolver;
        bytes solution;
    }

    function resolve(
        bytes calldata packedUserIntent, 
        bytes calldata packedResolverSolution
    ) external;

    function senderCallback(bytes calldata validatorAndIntent) external;
}

contract UniversalSolver is IUniversalSolver {
    struct Flags {
        bool isUsingResolver;
        bool isCacheRequesterIntent;
        bool isCacheResolverSolution;
        bool isCacheResolverContext;
        bool isCacheRequesterFullData;
    }

    bytes32 public constant REQUESTER_INTENT_SLOT = bytes32(erc7201("requester.intent.slot"));
    bytes32 public constant RESOLVER_SOLUTION_SLOT = bytes32(erc7201("resolver.solution.slot"));
    bytes32 public constant REQUESTER_CONTEXT_SLOT = bytes32(erc7201("requester.context.slot"));
    bytes32 public constant RESOLVER_CONTEXT_SLOT = bytes32(erc7201("resolver.context.slot"));
    bytes32 public constant REQUESTER_FULL_DATA_SLOT = bytes32(erc7201("requester.full.data.slot"));
    uint32 public constant MAX_TOTAL_SLOT = type(uint32).max;
    uint32 public constant MASKING = type(uint32).max;

    // Lưu trữ user để xác minh trong giai đoạn callback.
    address public transient sender;
    address public transient validator;
    address public transient resolver;
    address public transient initator;
    bytes32 public transient policy;
    // Lưu trữ intentHash dùng để xác thực intent.
    bytes32 public transient intentHash;
    bytes32 public transient solutionHash;
    uint256 public transient offset;
    uint256 public transient length;
    // Biến nội bộ để xác minh intent đã được user chấp thuận trong giai đoạn callback hay không.
    bool public transient intentAccepted;
    // Biến nội bộ dùng để chống reentrancy và mở khóa thực thi cho hàm callback.
    bool public transient locked;

    error Reentrancy();
    error IntentNotAccepted();
    error InactiveSolver();
    error LengthTooShort(uint256 length);
    error TotalSlotTooLarge(uint256 totalSlot);
    error CallRequesterContextFailed(address validator, bytes reason);
    error CallResolverContextFailed(address resolver, bytes reason);
    error InvalidUser(address user);
    error IntentAccepted(address validator, bytes intent);
    error InvalidIntent(address validator, bytes intent);
    error ValidateIntentFailed(bytes result);
    error RequesterFailed(bytes result);
    error SolverFailed(bytes result);

    modifier nonReentrant {
        if (locked) revert Reentrancy();
        locked = true;

        _;

        locked = false;
    }

    // Đây là hàm giải quyết intent, bất kỳ ai cũng có thể gọi hàm này để cung cấp một answer hợp lệ
    // với mỗi intent tương ứng. Việc giải quyết cũng có thể được thực hiện theo lô bằng cách sử dụng
    // các hợp đồng Multicall từ hợp đồng công khai hoặc từ tài khoản cá nhân.
    function resolve(
        bytes calldata packedUserIntent, 
        bytes calldata packedResolverSolution
    ) public nonReentrant {
        // Lấy intent từ intentAndData và sau đó lưu lại ở dạng hash để tiết kiệm chi phí.
        UserIntent memory userIntent = 
        decodeUserIntent(packedUserIntent);

        ResolverSolution memory resolverSolution = 
        decodeResolverSolution(packedResolverSolution);

        Flags memory flags;
        (
            flags.isUsingResolver,
            flags.isCacheRequesterIntent,
            flags.isCacheResolverSolution,
            flags.isCacheResolverContext,
            flags.isCacheRequesterFullData
        ) = decodePolicy(resolverSolution.policy);

        address _resolver = _getResolver(flags.isUsingResolver, resolverSolution.resolver);

        _setContext(
            userIntent.sender,
            userIntent.validator,
            _resolver,
            resolverSolution.policy,
            sliceUserIntent(
                userIntent.offset, 
                userIntent.length, 
                packedUserIntent
            ), 
            packedResolverSolution
        );

        _cacheRequesterIntent(
            flags.isCacheRequesterIntent,
            userIntent.offset,
            userIntent.length,
            userIntent.intent
        );
        _cacheRequesterFullData(flags.isCacheRequesterFullData, packedUserIntent);
        _cacheResolverSolution(flags.isCacheResolverSolution, resolverSolution.solution);
        _cacheRequesterContext(userIntent.validator, userIntent.intent);
        _cacheResolverContext(flags.isCacheResolverContext, _resolver, resolverSolution.solution);
        _validateOnSender(userIntent.sender, getEnvelopeTx(packedUserIntent));
        _resolveSolution(_resolver, resolverSolution.solution);
        _validateIntent(userIntent.validator, userIntent.intent);

        // Xóa các thông tin về intent và hoàn tất chu trình làm việc.
        _clearContext();
    }

    // Đây là hàm nhận callback từ sender
    function senderCallback(bytes calldata validatorAndIntent) external {
        // Xác minh người gọi có phải là user đã được chỉ định trong UserIntent không..
        require(msg.sender == sender, InvalidUser(sender));
        // Kiểm tra trạng thái hàm resolve có đang chạy không.
        require(locked, InactiveSolver());
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
        bool _intentAccepted,
        UserIntent memory userIntent,
        ResolverSolution memory resolverSolution,
        bytes memory requesterContext,
        bytes memory resolverContext
    ) {
        return (
            initator,
            intentHash,
            solutionHash,
            intentAccepted,
            UserIntent(
                sender,
                offset,
                length,
                validator,
                getCacheData(REQUESTER_INTENT_SLOT)
            ),
            ResolverSolution(
                policy,
                resolver,
                getCacheData(RESOLVER_SOLUTION_SLOT)
            ),
            getCacheData(REQUESTER_CONTEXT_SLOT),
            getCacheData(RESOLVER_CONTEXT_SLOT)
        );
    }

    function fullContext() public view returns (
        address _initator,
        bytes32 _intentHash,
        bytes32 _solutionHash,
        bool _intentAccepted,
        bool _locked,
        bytes memory packedUserIntent,
        bytes memory packedResolverSolution,
        bytes memory requesterContext,
        bytes memory resolverContext
    ) {
        (bool isUsingResolver,,,,) = decodePolicy(policy);
        return (
            initator,
            intentHash,
            solutionHash,
            intentAccepted,
            locked,
            getCacheData(REQUESTER_FULL_DATA_SLOT),
            abi.encodePacked(
                bytes1(policy), 
                isUsingResolver ? abi.encodePacked(resolver) : new bytes(0), 
                getCacheData(RESOLVER_SOLUTION_SLOT)
            ),
            getCacheData(REQUESTER_CONTEXT_SLOT),
            getCacheData(RESOLVER_CONTEXT_SLOT)
        );
    }

    function getEnvelopeTx(
        bytes calldata packedUserIntent
    ) public pure returns (
        bytes calldata envelopeTx
    ) {
        return packedUserIntent[28 : ];
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

    function sliceUserIntent(
        uint256 _offset,
        uint256 _length,
        bytes calldata packedUserIntent
    ) public pure returns (
        bytes calldata validatorAndIntent
    ) {
        require(_length >= 20, LengthTooShort(_length));
        return getEnvelopeTx(packedUserIntent)[_offset : _offset + _length];
    }

    function decodeUserIntent(
        bytes calldata packedUserIntent
    ) public pure returns (
        UserIntent memory userIntent
    ) {
        address _sender = address(bytes20(packedUserIntent[0 : 20]));
        uint256 _offset = uint32(bytes4(packedUserIntent[20 : 24]));
        uint256 _length = uint32(bytes4(packedUserIntent[24 : 28]));
        bytes calldata validatorAndIntent = 
        sliceUserIntent(_sender, _length, packedUserIntent);
        (address _validator, bytes calldata intent) = 
        decodeValidatorAndIntent(validatorAndIntent);
        return UserIntent(
            _sender,
            _offset,
            _length,
            _validator,
            intent
        );
    }

    function decodeResolverSolution(
        bytes calldata packedResolverSolution
    ) public pure returns (
        ResolverSolution memory resolverSolution
    ) {
        bytes32 _policy = bytes32(packedResolverSolution[0]);
        (bool isUsingResolver,,,,) = decodePolicy(_policy);
        (address executor, bytes calldata solution) = 
            isUsingResolver 
            ? (
                address(bytes20(packedResolverSolution[1 : 21])), 
                packedResolverSolution[21 : ]
            )
            : (address(0), packedResolverSolution[1 : ]);
        return ResolverSolution(
            _policy,
            executor,
            solution
        );
    }

    function decodePolicy(bytes32 _policy) 
        public 
        pure 
        returns (
            bool isUsingResolver,
            bool isCacheRequesterIntent,
            bool isCacheResolverSolution,
            bool isCacheResolverContext,
            bool isCacheRequesterFullData
        ) 
    {
        return (
            uint256(_policy >> 255) == 1,
            (uint256(_policy >> 254) & 1) == 1,
            (uint256(_policy >> 253) & 1) == 1,
            (uint256(_policy >> 252) & 1) == 1,
            (uint256(_policy >> 251) & 1) == 1
        );
    }

    function _setContext(
        address _sender,
        address _validator,
        address _resolver,
        bytes32 _policy,
        bytes calldata validatorAndIntent,
        bytes calldata packedResolverSolution
    ) internal {
        // Lưu user hợp lệ để xác minh trong callback.
        sender = _sender;
        validator = _validator;
        resolver = _resolver;
        initator = msg.sender;
        policy = _policy;
        intentHash = keccak256(validatorAndIntent);
        solutionHash = keccak256(packedResolverSolution);
    }

    function _clearContext() internal {
        sender = address(0);
        validator = address(0);
        resolver = address(0);
        initator = address(0);
        policy = 0;
        intentHash = 0;
        solutionHash = 0;
        offset = 0;
        length = 0;
        intentAccepted = false;
        _clearCacheData(bytes32(uint256(REQUESTER_INTENT_SLOT) + 1));
        _clearCacheData(RESOLVER_SOLUTION_SLOT);
        _clearCacheData(REQUESTER_CONTEXT_SLOT);
        _clearCacheData(RESOLVER_CONTEXT_SLOT);
        _clearCacheData(REQUESTER_FULL_DATA_SLOT);
    }

    function _validateOnSender(address _sender, bytes calldata envelopeTx) internal {
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
        emit ValidateIntentSuccess(result);
    }

    function _cacheRequesterIntent(
        bool isCacheRequesterIntent,
        uint256 _offset,
        uint256 _length,
        bytes memory intent
    ) internal {
        if (isCacheRequesterIntent) {
            offset = _offset;
            length = _length;
            _setCacheData(REQUESTER_INTENT_SLOT, intent);
        }
    }

    function _cacheResolverSolution(
        bool isCacheResolverSolution,
        bytes memory solution
    ) internal {
        if (isCacheResolverSolution) {
            _setCacheData(RESOLVER_SOLUTION_SLOT, solution);
        }
    }

    function _cacheRequesterContext(address _validator, bytes memory intent) internal {
        (bool success, bytes memory requesterContext) = _validator.staticcall(intent);
        require(success, CallRequesterContextFailed(_validator, intent));
        _setCacheData(REQUESTER_CONTEXT_SLOT, requesterContext);
    }

    function _cacheResolverContext(
        bool isCacheResolverContext,
        address _resolver,
        bytes memory solution
    ) internal {
        if (isCacheResolverContext) {
            (bool success, bytes memory resolverContext) = _resolver.staticcall(solution);
            require(success, CallResolverContextFailed(_resolver, resolverContext));
            _setCacheData(RESOLVER_CONTEXT_SLOT, resolverContext);
        }
    }

    function _cacheRequesterFullData(
        bool isCacheRequesterFullData,
        bytes calldata packedUserIntent
    ) internal {
        if (isCacheRequesterFullData) {
            _setCacheData(REQUESTER_FULL_DATA_SLOT, packedUserIntent);
        }
    }

    function _resolveSolution(
        address _resolver,
        bytes memory solution
    ) internal {
        // Solver chuyển giao toàn bộ công việc cho resolver, resolver được tự do lựa chọn phương án
        // giải quyết theo các điều kiện mà intent đặt ra.
        (bool success, bytes memory result) = _resolver.call(solution);
        require(success, SolverFailed(result));
        emit SolverResult(result);
    }

    function _validateIntent(address _validator, bytes memory intent) internal {
        // Để đơn giản và linh hoạt, Solver gọi đến hợp đồng interpreter sau khi resolver hoàn tất để
        // cho phép calldata tĩnh hoạt động như một EVM bytecode, điều này cho phép điều kiện có thể
        // được lập trình bằng cách ngôn ngữ cấp cao như Solidity.
        (bool success, bytes memory result) = _validator.call(intent);
        require(success, RequesterFailed(result));
        emit RequesterResult(result);
    }

    function getCacheData(
        bytes32 namespace
    ) 
        public 
        view 
        returns (bytes memory data) 
    {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint32 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length_ := tload(namespace)
            if length_ {
                let totalSlot := shr(5, add(length, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                mstore(data, length_)
                namespace := add(namespace, 1)
                let offset_ := add(data, 32)
                for { let i } lt(i, totalSlot) { i := add(i, 1) } {
                    mstore(add(offset_, shl(5, i)), tload(add(namespace, i)))
                }
            }
        }
    }

    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint32 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length_ := mload(data)
            if length_ {
                let totalSlot := shr(5, add(length_, 31))
                if gt(totalSlot, maxTotalSlot) {
                    mstore(0, errorSelector)
                    mstore(4, totalSlot)
                    revert(0, 36)
                }
                tstore(namespace, length_)
                namespace := add(namespace, 1)
                let offset_ := add(data, 32)
                for { let i } lt(i, totalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), mload(add(offset_, shl(5, i))))
                }
            }
        }
    }

    function _clearCacheData(bytes32 namespace) internal {
        bytes4 errorSelector = TotalSlotTooLarge.selector;
        uint32 maxTotalSlot = MAX_TOTAL_SLOT;
        assembly ("memory-safe") {
            let length_ := tload(namespace)
            if length_ {
                let totalSlot := shr(5, add(length_, 31))
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

    function _getResolver(
        bool isUsingResolver,
        address _resolver
    ) internal view returns (address) {
        return isUsingResolver ? _resolver : msg.sender;
    }
}
