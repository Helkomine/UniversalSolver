// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;
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
        // Dữ liệu intent được xác định bằng offset và length trong intentAndData, giá trị này có thể
        // được chọn tùy ý tuy nhiên Solver luôn xác thực tính hợp lệ của intent thực tế được requester
        // cung cấp.
        uint256 offset;
        uint256 length;
        // Dữ liệu cần chuyển tiếp đến user, trong đó luôn mang theo intent. Việc slice calldata để lấy
        // intent là khả thi vì thực tế tài khoản thông minh luôn chấp nhận các đoạn dữ liệu liên tục,
        // chẳng hạn execute(address target, uint256 value, bytes data) luôn có đoạn data liên tục và có
        // thể được tận dụng để chứa intent mà không cần yêu cầu bất kỳ sửa đổi nào trên tài khoản hiện có.
        bytes senderData;
    }

    uint256 constant REQUESTER_CONTEXT_NAMESPACE = erc7201("requester.context.namespace");
    uint256 constant RESOLVER_CONTEXT_NAMESPACE = erc7201("resolver.context.namespace");

    // Lưu trữ intentHash dùng để xác thực intent.
    bytes32 transient intentHash;
    bytes32 transient answerHash;
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
    function resolve(bytes calldata answer, UserIntent calldata userIntent) public nonReentrant {
        bool success;
        bytes memory result;

        resolver = msg.sender;

        // Lấy intent từ intentAndData và sau đó lưu lại ở dạng hash để tiết kiệm chi phí.
        bytes calldata executorAndIntent = 
        userIntent.senderData[userIntent.offset : userIntent.offset + userIntent.length];
        intentHash = keccak256(executorAndIntent);

        address executor = address(bytes20(executorAndIntent[0 : 20]));
        bytes calldata intent = executorAndIntent[20 : ];

        // Lưu user hợp lệ để xác minh trong callback.
        sender = userIntent.sender;

        // Solver gọi đến user để xác thực và thiết lập môi trường cần thiết, chẳng hạn chuyển số dư
        // cần hoán đổi đến địa chỉ dễ tiếp cận để cho phép resolver giải quyết ở vào giai đoạn sau.
        (success, result) = userIntent.sender.call(userIntent.senderData);
        // Solver revert nếu user bị lỗi vì bất kỳ lý do gì.
        require(success, ValidateIntentFailed(result));
        // Solver revert nếu intent chưa được chấp thuận, đảm bảo an toàn ngay cả khi tài khoản user
        // không thể từ chối intent không hợp lệ đúng cách, khi đó toàn bộ thao tác phụ như di chuyển
        // số dư đều được khôi phục làm cho tài khoản user trở lại nguyên trạng.
        require(intentAccepted, IntentNotAccepted());
        // Phát log intent sau khi đã được xác thực hoàn tất.
        emit ValidateIntentSuccess(intent);

        // Xóa các thông tin về intent và hoàn tất chu trình làm việc.
        _clearContext();
    }

    // Đây là hàm nhận callback từ sender
    function senderCallback(bytes calldata executorAndIntent) external {
        // Xác minh người gọi có phải là user đã được chỉ định trong UserIntent không..
        require(msg.sender == sender, InvalidUser(sender));
        // Kiểm tra trạng thái hàm resolve có đang chạy không.
        require(locked, InactiveSolver());
        (address executor, bytes calldata intent) = _getExecutorAndIntent(executorAndIntent);
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
        bytes memory _requesterContext,
        bytes memory _resolverContext
    ) {
        uint256 requesterContextNamespace = REQUESTER_CONTEXT_NAMESPACE;
        assembly ("memory-safe") {
            let length := tload(requesterContextNamespace)
            let round := shr(5, add(length, 31))
            mstore(_requesterContext, length)
        }
        return (
            sender, 
            resolver,
            _requesterContext,
            _resolverContext
        );
    }

    function _getExecutorAndIntent(bytes calldata executorAndIntent) internal pure returns (
        address executor,
        bytes calldata intent
    ) {
        return (
            address(bytes20(executorAndIntent[0 : 20])),
            executorAndIntent[20 : ]
        );
    }

    function _getFlagAndAnswer(bytes calldata flagAndAnswer) internal pure returns (
        bool isSetContextForIntent,
        bytes calldata answer
    ) {
        return (
            flagAndAnswer[0] != 0,
            flagAndAnswer[1 : ]
        );
    }

    function _clearContext() internal {
        intentHash = 0;
        sender = address(0);
        resolver = address(0);
        intentAccepted = false;
    }

    function _setRequesterContext(address executor, bytes calldata intent) internal {
        (bool success, bytes memory requesterContext) = executor.staticcall(intent);
        require(success, CallRequesterContextFailed(sender, executor, intent));

        uint256 requesterContextNamespace = REQUESTER_CONTEXT_NAMESPACE;
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

    function _setResolverContext(bytes calldata answer) internal view {
        (bool success, bytes memory resolverContext) = msg.sender.staticcall(answer);

        uint256 resolverContextNamespace = RESOLVER_CONTEXT_NAMESPACE;
    }

    function _resolveAnswer(bytes calldata answer) internal {
        // Solver chuyển giao toàn bộ công việc cho resolver, resolver được tự do lựa chọn phương án
        // giải quyết theo các điều kiện mà intent đặt ra.
        (bool success, bytes memory result) = msg.sender.call(answer);
        require(success, SolverFailed(result));
        emit SolverResult(result);
    }

    function _validateIntent(address executor, bytes calldata intent) internal {
        // Để đơn giản và linh hoạt, Solver gọi đến hợp đồng interpreter sau khi resolver hoàn tất để
        // cho phép calldata tĩnh hoạt động như một EVM bytecode, điều này cho phép điều kiện có thể
        // được lập trình bằng cách ngôn ngữ cấp cao như Solidity.
        (bool success, bytes memory result) = executor.call(intent);
        require(success, RequesterFailed(result));
        emit RequesterResult(result);
    }
}
