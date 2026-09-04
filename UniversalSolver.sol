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

contract UniversalSolver {
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
        address executor;
        bytes intent;
    }

    struct ResolverSolution {
        uint8 policy;
        bytes solution;
    }

    uint256 constant REQUESTER_INTENT_SLOT = erc7201("requester.intent.slot");
    uint256 constant RESOLVER_SOLUTION_SLOT = erc7201("resolver.solution.slot");
    uint256 constant REQUESTER_CONTEXT_SLOT = erc7201("requester.context.slot");
    uint256 constant RESOLVER_CONTEXT_SLOT = erc7201("resolver.context.slot");
    uint256 constant REQUESTER_FULL_INTENT_SLOT = erc7201("requester.full.intent.slot");

    // Lưu trữ intentHash dùng để xác thực intent.
    bytes32 transient intentHash;
    bytes32 transient solutionHash;
    // Lưu trữ user để xác minh trong giai đoạn callback.
    address transient sender;
    address transient resolver;
    // Biến nội bộ để xác minh intent đã được user chấp thuận trong giai đoạn callback hay không.
    bool transient intentAccepted;
    // Biến nội bộ dùng để chống reentrancy và mở khóa thực thi cho hàm callback.
    bool transient locked;

    error Reentrancy();
    error IntentNotAccepted();
    error InactiveSolver();
    error LengthTooShort(uint256 length);
    error CallRequesterContextFailed(address requester, address executor, bytes reason);
    error CallResolverContextFailed(address resolver, bytes reason);
    error InvalidUser(address user);
    error IntentAccepted(address executor, bytes intent);
    error InvalidIntent(address executor, bytes intent);
    error ValidateIntentFailed(bytes result);
    error RequesterFailed(bytes result);
    error SolverFailed(bytes result);

    event ValidateIntentSuccess(bytes intent);
    event RequesterResult(bytes result);
    event SolverResult(bytes result);

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

        _setContext(
            userIntent.sender, 
            sliceUserIntent(
                userIntent.offset, 
                userIntent.length, 
                packedUserIntent
            ), 
            packedResolverSolution
        );

        (
            bool isCacheRequesterIntent,
            bool isCacheResolverSolution,
            bool isCacheResolverContext
        ) = decodePolicy(resolverSolution.policy);

        _setRequesterContext(userIntent.executor, userIntent.intent);
        _setResolverContext(resolverSolution.solution);
        _validateOnSender(userIntent.sender, userIntent.intent);
        _resolveAnswer(resolverSolution.solution);
        _validateIntent(userIntent.executor, userIntent.intent);

        // Xóa các thông tin về intent và hoàn tất chu trình làm việc.
        _clearContext();
    }

    // Đây là hàm nhận callback từ sender
    function senderCallback(bytes calldata executorAndIntent) external {
        // Xác minh người gọi có phải là user đã được chỉ định trong UserIntent không..
        require(msg.sender == sender, InvalidUser(sender));
        // Kiểm tra trạng thái hàm resolve có đang chạy không.
        require(locked, InactiveSolver());
        (address executor, bytes calldata intent) = decodeExecutorAndIntent(executorAndIntent);
        // Nếu intent đã được xác thực hàm này sẽ hoàn tác.
        if (intentAccepted) revert IntentAccepted(executor, intent);
        // Kiểm tra intent được user gọi có giống với intent đã được chỉ định trong UserIntent không.
        require(keccak256(executorAndIntent) == intentHash, InvalidIntent(executor, intent));
        // Đánh dấu intent này là hợp lệ để sẵn sàng giải quyết.
        intentAccepted = true;
    }

    function context() public view returns (
        address _sender,
        address _resolver,
        bytes32 _intentHash,
        bytes32 _answerHash,
        UserIntent memory userIntent,
        bytes memory answer,
        bytes memory _requesterContext,
        bytes memory _resolverContext
    ) {
        uint256 requesterContextNamespace = REQUESTER_CONTEXT_SLOT;
        assembly ("memory-safe") {
            let length := tload(requesterContextNamespace)
            let round := shr(5, add(length, 31))
            mstore(_requesterContext, length)
        }
        return (
            sender, 
            resolver,
            intentHash,
            solutionHash,
            userIntent,
            answer,
            _requesterContext,
            _resolverContext
        );
    }

    function fullContext() public view returns (
        address _resolver,
        bool _locked,
        bool _intentAccepted,
        bytes memory packedUserIntent,
        bytes memory packedResolverSolution,
        bytes memory requesterContext,
        bytes memory resolverContext
    ) {
        assembly ("memory-safe") {}
    }

    function requesterContextSlot() public pure returns (bytes32) {
        return bytes32(REQUESTER_CONTEXT_SLOT);
    }

    function resolverContextSlot() public pure returns (bytes32) {
        return bytes32(RESOLVER_CONTEXT_SLOT);
    }

    function getEnvelopeTx(
        bytes calldata packedUserIntent
    ) public pure returns (
        bytes calldata envelopeTx
    ) {
        return packedUserIntent[28 : ];
    }

    function decodeExecutorAndIntent(
        bytes calldata executorAndIntent
    ) public pure returns (
        address executor,
        bytes calldata intent
    ) {
        return (
            address(bytes20(executorAndIntent[0 : 20])),
            executorAndIntent[20 : ]
        );
    }

    function sliceUserIntent(
        uint256 offset,
        uint256 length,
        bytes calldata packedUserIntent
    ) public pure returns (
        bytes calldata executorAndIntent
    ) {
        require(length >= 20, LengthTooShort(length));
        bytes calldata envelopeTx = getEnvelopeTx(packedUserIntent);
        return packedUserIntent[offset : offset + length];
    }

    function decodeUserIntent(
        bytes calldata packedUserIntent
    ) public pure returns (
        UserIntent memory userIntent
    ) {
        address _sender = address(bytes20(packedUserIntent[0 : 20]));
        uint256 offset = uint32(bytes4(packedUserIntent[20 : 24]));
        uint256 length = uint32(bytes4(packedUserIntent[24 : 28]));
        bytes calldata executorAndIntent = 
        sliceUserIntent(offset, length, packedUserIntent);
        (address executor, bytes calldata intent) = 
        decodeExecutorAndIntent(executorAndIntent);
        return UserIntent(
            _sender,
            offset,
            length,
            executor,
            intent
        );
    }

    function decodeResolverSolution(
        bytes calldata resolverSolutionPacked
    ) public pure returns (
        ResolverSolution memory resolverSolution
    ) {
        return ResolverSolution(
            uint8(resolverSolutionPacked[0]),
            resolverSolutionPacked[1 : ]
        );
    }

    function decodePolicy(uint8 policy) public pure returns (
        bool isCacheRequesterIntent,
        bool isCacheResolverSolution,
        bool isCacheResolverContext
    ) {
        return (
            (policy >> 7) == 1,
            ((policy >> 6) & 1) == 1,
            ((policy >> 5) & 1) == 1
        );
    }

    function _setContext(
        address _sender, 
        bytes calldata executorAndIntent, 
        bytes calldata packedResolverSolution
    ) internal {
        // Lưu user hợp lệ để xác minh trong callback.
        sender = _sender;
        resolver = msg.sender;
        intentHash = keccak256(executorAndIntent);
        solutionHash = keccak256(packedResolverSolution);
    }

    function _clearContext() internal {
        sender = address(0);
        resolver = address(0);
        intentHash = 0;
        solutionHash = 0;
        intentAccepted = false;
    }

    function _cacheIntent(
        bool isCacheRequesterIntent, 
        bytes calldata intent
    ) internal {
        if (isCacheRequesterIntent) {}
    }

    function _cacheSolution() internal {}

    function _validateOnSender(address sender, bytes memory senderData) internal {
        // Solver gọi đến user để xác thực và thiết lập môi trường cần thiết, chẳng hạn chuyển số dư
        // cần hoán đổi đến địa chỉ dễ tiếp cận để cho phép resolver giải quyết ở vào giai đoạn sau.
        (bool success, bytes memory result) = sender.call(senderData);
        // Solver revert nếu user bị lỗi vì bất kỳ lý do gì.
        require(success, ValidateIntentFailed(result));
        // Solver revert nếu intent chưa được chấp thuận, đảm bảo an toàn ngay cả khi tài khoản user
        // không thể từ chối intent không hợp lệ đúng cách, khi đó toàn bộ thao tác phụ như di chuyển
        // số dư đều được khôi phục làm cho tài khoản user trở lại nguyên trạng.
        require(intentAccepted, IntentNotAccepted());
        // Phát log intent sau khi đã được xác thực hoàn tất.
        emit ValidateIntentSuccess(senderData);
    }

    function _setRequesterContext(address executor, bytes memory intent) internal {
        (bool success, bytes memory requesterContext) = executor.staticcall(intent);
        require(success, CallRequesterContextFailed(sender, executor, intent));

        uint256 requesterContextNamespace = REQUESTER_CONTEXT_SLOT;
        uint256 length = requesterContext.length;
        if (length > 0) {
            assembly ("memory-safe") {
                let round := shr(5, add(length, 31))
                tstore(requesterContextNamespace, length)
                let start_slot_ := add(requesterContextNamespace, 1)
                let start_offset_ := add(requesterContext, 32)
                for { let i := 0 } lt(i, round) { i := add(i, 1) } {
                    tstore(add(start_slot_, i), mload(add(start_offset_, shl(5, i))))
                }
            }
        }
    }

    function _setResolverContext(bytes memory answer) internal view {
        (bool success, bytes memory resolverContext) = msg.sender.staticcall(answer);

        uint256 resolverContextNamespace = RESOLVER_CONTEXT_SLOT;
    }

    function _resolveAnswer(bytes memory answer) internal {
        // Solver chuyển giao toàn bộ công việc cho resolver, resolver được tự do lựa chọn phương án
        // giải quyết theo các điều kiện mà intent đặt ra.
        (bool success, bytes memory result) = msg.sender.call(answer);
        require(success, SolverFailed(result));
        emit SolverResult(result);
    }

    function _validateIntent(address executor, bytes memory intent) internal {
        // Để đơn giản và linh hoạt, Solver gọi đến hợp đồng interpreter sau khi resolver hoàn tất để
        // cho phép calldata tĩnh hoạt động như một EVM bytecode, điều này cho phép điều kiện có thể
        // được lập trình bằng cách ngôn ngữ cấp cao như Solidity.
        (bool success, bytes memory result) = executor.call(intent);
        require(success, RequesterFailed(result));
        emit RequesterResult(result);
    }
}
