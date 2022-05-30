// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "./L1_Bridge.sol";
/**
 * @dev A L1_Bridge that uses an ERC20 as the canonical token
 */
contract L1_ERC20_Bridge is L1_Bridge {
    using SafeERC20 for IERC20;
    IERC20 public immutable l1CanonicalToken;
    constructor (IERC20 _l1CanonicalToken, address[] memory bonders, address _governance) public L1_Bridge(bonders, _governance) {
        l1CanonicalToken = _l1CanonicalToken;
    }
    /* ========== Override Functions ========== */
    function _transferFromBridge(address recipient, uint256 amount) internal override {
        l1CanonicalToken.safeTransfer(recipient, amount);
    }
    function _transferToBridge(address from, uint256 amount) internal override {
        l1CanonicalToken.safeTransferFrom(from, address(this), amount);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;
/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);
    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);
    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);
    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);
    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);
    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;
import "./IERC20.sol";
import "../../math/SafeMath.sol";
import "../../utils/Address.sol";
/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }
    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }
    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.
        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;
import "./Bridge.sol";
import "../interfaces/IMessengerWrapper.sol";
/**
 * @dev L1_Bridge is responsible for the bonding and challenging of TransferRoots. All TransferRoots
 * originate in the L1_Bridge through `bondTransferRoot` and are propagated up to destination L2s.
 */
abstract contract L1_Bridge is Bridge {
    struct TransferBond {
        address bonder;
        uint256 createdAt;
        uint256 totalAmount;
        uint256 challengeStartTime;
        address challenger;
        bool challengeResolved;
    }
    /* ========== State ========== */
    mapping(uint256 => mapping(bytes32 => uint256)) public transferRootCommittedAt;
    mapping(bytes32 => TransferBond) public transferBonds;
    mapping(uint256 => mapping(address => uint256)) public timeSlotToAmountBonded;
    mapping(uint256 => uint256) public chainBalance;
    /* ========== Config State ========== */
    address public governance;
    mapping(uint256 => IMessengerWrapper) public crossDomainMessengerWrappers;
    mapping(uint256 => bool) public isChainIdPaused;
    uint256 public challengePeriod = 1 days;
    uint256 public challengeResolutionPeriod = 10 days;
    uint256 public minTransferRootBondDelay = 15 minutes;
    
    uint256 public constant CHALLENGE_AMOUNT_DIVISOR = 10;
    uint256 public constant TIME_SLOT_SIZE = 4 hours;
    /* ========== Events ========== */
    event TransferSentToL2(
        uint256 indexed chainId,
        address indexed recipient,
        uint256 amount,
        uint256 amountOutMin,
        uint256 deadline,
        address indexed relayer,
        uint256 relayerFee
    );
    event TransferRootBonded (
        bytes32 indexed root,
        uint256 amount
    );
    event TransferRootConfirmed(
        uint256 indexed originChainId,
        uint256 indexed destinationChainId,
        bytes32 indexed rootHash,
        uint256 totalAmount
    );
    event TransferBondChallenged(
        bytes32 indexed transferRootId,
        bytes32 indexed rootHash,
        uint256 originalAmount
    );
    event ChallengeResolved(
        bytes32 indexed transferRootId,
        bytes32 indexed rootHash,
        uint256 originalAmount
    );
    /* ========== Modifiers ========== */
    modifier onlyL2Bridge(uint256 chainId) {
        IMessengerWrapper messengerWrapper = crossDomainMessengerWrappers[chainId];
        messengerWrapper.verifySender(msg.sender, msg.data);
        _;
    }
    constructor (address[] memory bonders, address _governance) public Bridge(bonders) {
        governance = _governance;
    }
    /* ========== Send Functions ========== */
    /**
     * @notice `amountOutMin` and `deadline` should be 0 when no swap is intended at the destination.
     * @notice `amount` is the total amount the user wants to send including the relayer fee
     * @dev Send tokens to a supported layer-2 to mint hToken and optionally swap the hToken in the
     * AMM at the destination.
     * @param chainId The chainId of the destination chain
     * @param recipient The address receiving funds at the destination
     * @param amount The amount being sent
     * @param amountOutMin The minimum amount received after attempting to swap in the destination
     * AMM market. 0 if no swap is intended.
     * @param deadline The deadline for swapping in the destination AMM market. 0 if no
     * swap is intended.
     * @param relayer The address of the relayer at the destination.
     * @param relayerFee The amount distributed to the relayer at the destination. This is subtracted from the `amount`.
     */
    function sendToL2(
        uint256 chainId,
        address recipient,
        uint256 amount,
        uint256 amountOutMin,
        uint256 deadline,
        address relayer,
        uint256 relayerFee
    )
        external
        payable
    {
        IMessengerWrapper messengerWrapper = crossDomainMessengerWrappers[chainId];
        require(messengerWrapper != IMessengerWrapper(0), "L1_BRG: chainId not supported");
        require(isChainIdPaused[chainId] == false, "L1_BRG: Sends to this chainId are paused");
        require(amount > 0, "L1_BRG: Must transfer a non-zero amount");
        require(amount >= relayerFee, "L1_BRG: Relayer fee cannot exceed amount");
        _transferToBridge(msg.sender, amount);
        bytes memory message = abi.encodeWithSignature(
            "distribute(address,uint256,uint256,uint256,address,uint256)",
            recipient,
            amount,
            amountOutMin,
            deadline,
            relayer,
            relayerFee
        );
        chainBalance[chainId] = chainBalance[chainId].add(amount);
        messengerWrapper.sendCrossDomainMessage(message);
        emit TransferSentToL2(
            chainId,
            recipient,
            amount,
            amountOutMin,
            deadline,
            relayer,
            relayerFee
        );
    }
    /* ========== TransferRoot Functions ========== */
    /**
     * @dev Setting a TransferRoot is a two step process.
     * @dev   1. The TransferRoot is bonded with `bondTransferRoot`. Withdrawals can now begin on L1
     * @dev      and recipient L2's
     * @dev   2. The TransferRoot is confirmed after `confirmTransferRoot` is called by the l2 bridge
     * @dev      where the TransferRoot originated.
     */
    /**
     * @dev Used by the Bonder to bond a TransferRoot and propagate it up to destination L2s
     * @param rootHash The Merkle root of the TransferRoot Merkle tree
     * @param destinationChainId The id of the destination chain
     * @param totalAmount The amount destined for the destination chain
     */
    function bondTransferRoot(
        bytes32 rootHash,
        uint256 destinationChainId,
        uint256 totalAmount
    )
        external
        onlyBonder
        requirePositiveBalance
    {
        bytes32 transferRootId = getTransferRootId(rootHash, totalAmount);
        require(transferRootCommittedAt[destinationChainId][transferRootId] == 0, "L1_BRG: TransferRoot has already been confirmed");
        require(transferBonds[transferRootId].createdAt == 0, "L1_BRG: TransferRoot has already been bonded");
        uint256 currentTimeSlot = getTimeSlot(block.timestamp);
        uint256 bondAmount = getBondForTransferAmount(totalAmount);
        timeSlotToAmountBonded[currentTimeSlot][msg.sender] = timeSlotToAmountBonded[currentTimeSlot][msg.sender].add(bondAmount);
        transferBonds[transferRootId] = TransferBond(
            msg.sender,
            block.timestamp,
            totalAmount,
            uint256(0),
            address(0),
            false
        );
        _distributeTransferRoot(rootHash, destinationChainId, totalAmount);
        emit TransferRootBonded(rootHash, totalAmount);
    }
    /**
     * @dev Used by an L2 bridge to confirm a TransferRoot via cross-domain message. Once a TransferRoot
     * has been confirmed, any challenge against that TransferRoot can be resolved as unsuccessful.
     * @param originChainId The id of the origin chain
     * @param rootHash The Merkle root of the TransferRoot Merkle tree
     * @param destinationChainId The id of the destination chain
     * @param totalAmount The amount destined for each destination chain
     * @param rootCommittedAt The block timestamp when the TransferRoot was committed on its origin chain
     */
    function confirmTransferRoot(
        uint256 originChainId,
        bytes32 rootHash,
        uint256 destinationChainId,
        uint256 totalAmount,
        uint256 rootCommittedAt
    )
        external
        onlyL2Bridge(originChainId)
    {
        bytes32 transferRootId = getTransferRootId(rootHash, totalAmount);
        require(transferRootCommittedAt[destinationChainId][transferRootId] == 0, "L1_BRG: TransferRoot already confirmed");
        require(rootCommittedAt > 0, "L1_BRG: rootCommittedAt must be greater than 0");
        transferRootCommittedAt[destinationChainId][transferRootId] = rootCommittedAt;
        chainBalance[originChainId] = chainBalance[originChainId].sub(totalAmount, "L1_BRG: Amount exceeds chainBalance. This indicates a layer-2 failure.");
        // If the TransferRoot was never bonded, distribute the TransferRoot.
        TransferBond storage transferBond = transferBonds[transferRootId];
        if (transferBond.createdAt == 0) {
            _distributeTransferRoot(rootHash, destinationChainId, totalAmount);
        }
        emit TransferRootConfirmed(originChainId, destinationChainId, rootHash, totalAmount);
    }
    function _distributeTransferRoot(
        bytes32 rootHash,
        uint256 chainId,
        uint256 totalAmount
    )
        internal
    {
        // Set TransferRoot on recipient Bridge
        if (chainId == getChainId()) {
            // Set L1 TransferRoot
            _setTransferRoot(rootHash, totalAmount);
        } else {
            chainBalance[chainId] = chainBalance[chainId].add(totalAmount);
            IMessengerWrapper messengerWrapper = crossDomainMessengerWrappers[chainId];
            require(messengerWrapper != IMessengerWrapper(0), "L1_BRG: chainId not supported");
            // Set L2 TransferRoot
            bytes memory setTransferRootMessage = abi.encodeWithSignature(
                "setTransferRoot(bytes32,uint256)",
                rootHash,
                totalAmount
            );
            messengerWrapper.sendCrossDomainMessage(setTransferRootMessage);
        }
    }
    /* ========== External TransferRoot Challenges ========== */
    /**
     * @dev Challenge a TransferRoot believed to be fraudulent
     * @param rootHash The Merkle root of the TransferRoot Merkle tree
     * @param originalAmount The total amount bonded for this TransferRoot
     * @param destinationChainId The id of the destination chain
     */
    function challengeTransferBond(bytes32 rootHash, uint256 originalAmount, uint256 destinationChainId) external payable {
        bytes32 transferRootId = getTransferRootId(rootHash, originalAmount);
        TransferBond storage transferBond = transferBonds[transferRootId];
        require(transferRootCommittedAt[destinationChainId][transferRootId] == 0, "L1_BRG: TransferRoot has already been confirmed");
        require(transferBond.createdAt != 0, "L1_BRG: TransferRoot has not been bonded");
        uint256 challengePeriodEnd = transferBond.createdAt.add(challengePeriod);
        require(challengePeriodEnd >= block.timestamp, "L1_BRG: TransferRoot cannot be challenged after challenge period");
        require(transferBond.challengeStartTime == 0, "L1_BRG: TransferRoot already challenged");
        transferBond.challengeStartTime = block.timestamp;
        transferBond.challenger = msg.sender;
        // Move amount from timeSlotToAmountBonded to debit
        uint256 timeSlot = getTimeSlot(transferBond.createdAt);
        uint256 bondAmount = getBondForTransferAmount(originalAmount);
        address bonder = transferBond.bonder;
        timeSlotToAmountBonded[timeSlot][bonder] = timeSlotToAmountBonded[timeSlot][bonder].sub(bondAmount);
        _addDebit(transferBond.bonder, bondAmount);
        // Get stake for challenge
        uint256 challengeStakeAmount = getChallengeAmountForTransferAmount(originalAmount);
        _transferToBridge(msg.sender, challengeStakeAmount);
        emit TransferBondChallenged(transferRootId, rootHash, originalAmount);
    }
    /**
     * @dev Resolve a challenge after the `challengeResolutionPeriod` has passed
     * @param rootHash The Merkle root of the TransferRoot Merkle tree
     * @param originalAmount The total amount originally bonded for this TransferRoot
     * @param destinationChainId The id of the destination chain
     */
    function resolveChallenge(bytes32 rootHash, uint256 originalAmount, uint256 destinationChainId) external {
        bytes32 transferRootId = getTransferRootId(rootHash, originalAmount);
        TransferBond storage transferBond = transferBonds[transferRootId];
        require(transferBond.challengeStartTime != 0, "L1_BRG: TransferRoot has not been challenged");
        require(block.timestamp > transferBond.challengeStartTime.add(challengeResolutionPeriod), "L1_BRG: Challenge period has not ended");
        require(transferBond.challengeResolved == false, "L1_BRG: TransferRoot already resolved");
        transferBond.challengeResolved = true;
        uint256 challengeStakeAmount = getChallengeAmountForTransferAmount(originalAmount);
        if (transferRootCommittedAt[destinationChainId][transferRootId] > 0) {
            // Invalid challenge
            if (transferBond.createdAt > transferRootCommittedAt[destinationChainId][transferRootId].add(minTransferRootBondDelay)) {
                // Credit the bonder back with the bond amount plus the challenger's stake
                _addCredit(transferBond.bonder, getBondForTransferAmount(originalAmount).add(challengeStakeAmount));
            } else {
                // If the TransferRoot was bonded before it was committed, the challenger and Bonder
                // get their stake back. This discourages Bonders from tricking challengers into
                // challenging a valid TransferRoots that haven't yet been committed. It also ensures
                // that Bonders are not punished if a TransferRoot is bonded too soon in error.
                // Return the challenger's stake
                _addCredit(transferBond.challenger, challengeStakeAmount);
                // Credit the bonder back with the bond amount
                _addCredit(transferBond.bonder, getBondForTransferAmount(originalAmount));
            }
        } else {
            // Valid challenge
            // Burn 25% of the challengers stake
            _transferFromBridge(address(0xdead), challengeStakeAmount.mul(1).div(4));
            // Reward challenger with the remaining 75% of their stake plus 100% of the Bonder's stake
            _addCredit(transferBond.challenger, challengeStakeAmount.mul(7).div(4));
        }
        emit ChallengeResolved(transferRootId, rootHash, originalAmount);
    }
    /* ========== Override Functions ========== */
    function _additionalDebit(address bonder) internal view override returns (uint256) {
        uint256 currentTimeSlot = getTimeSlot(block.timestamp);
        uint256 bonded = 0;
        uint256 numTimeSlots = challengePeriod / TIME_SLOT_SIZE;
        for (uint256 i = 0; i < numTimeSlots; i++) {
            bonded = bonded.add(timeSlotToAmountBonded[currentTimeSlot - i][bonder]);
        }
        return bonded;
    }
    function _requireIsGovernance() internal override {
        require(governance == msg.sender, "L1_BRG: Caller is not the owner");
    }
    /* ========== External Config Management Setters ========== */
    function setGovernance(address _newGovernance) external onlyGovernance {
        require(_newGovernance != address(0), "L1_BRG: _newGovernance cannot be address(0)");
        governance = _newGovernance;
    }
    function setCrossDomainMessengerWrapper(uint256 chainId, IMessengerWrapper _crossDomainMessengerWrapper) external onlyGovernance {
        crossDomainMessengerWrappers[chainId] = _crossDomainMessengerWrapper;
    }
    function setChainIdDepositsPaused(uint256 chainId, bool isPaused) external onlyGovernance {
        isChainIdPaused[chainId] = isPaused;
    }
    function setChallengePeriod(uint256 _challengePeriod) external onlyGovernance {
        require(_challengePeriod % TIME_SLOT_SIZE == 0, "L1_BRG: challengePeriod must be divisible by TIME_SLOT_SIZE");
        challengePeriod = _challengePeriod;
    }
    function setChallengeResolutionPeriod(uint256 _challengeResolutionPeriod) external onlyGovernance {
        challengeResolutionPeriod = _challengeResolutionPeriod;
    }
    function setMinTransferRootBondDelay(uint256 _minTransferRootBondDelay) external onlyGovernance {
        minTransferRootBondDelay = _minTransferRootBondDelay;
    }
    /* ========== Public Getters ========== */
    function getBondForTransferAmount(uint256 amount) public pure returns (uint256) {
        // Bond covers amount plus a bounty to pay a potential challenger
        return amount.add(getChallengeAmountForTransferAmount(amount));
    }
    function getChallengeAmountForTransferAmount(uint256 amount) public pure returns (uint256) {
        // Bond covers amount plus a bounty to pay a potential challenger
        return amount.div(CHALLENGE_AMOUNT_DIVISOR);
    }
    function getTimeSlot(uint256 time) public pure returns (uint256) {
        return time / TIME_SLOT_SIZE;
    }
}
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;
/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }
    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b > a) return (false, 0);
        return (true, a - b);
    }
    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }
    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a / b);
    }
    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a % b);
    }
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }
    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        return a - b;
    }
    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryDiv}.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a / b;
    }
    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a % b;
    }
}
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.8.0;
/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.
        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");
        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain`call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }
    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }
    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;
import "./Accounting.sol";
import "../libraries/Lib_MerkleTree.sol";
/**
 * @dev Bridge extends the accounting system and encapsulates the logic that is shared by both the
 * L1 and L2 Bridges. It allows to TransferRoots to be set by parent contracts and for those
 * TransferRoots to be withdrawn against. It also allows the bonder to bond and withdraw Transfers
 * directly through `bondWithdrawal` and then settle those bonds against their TransferRoot once it
 * has been set.
 */
abstract contract Bridge is Accounting {
    using Lib_MerkleTree for bytes32;
    struct TransferRoot {
        uint256 total;
        uint256 amountWithdrawn;
        uint256 createdAt;
    }
    /* ========== Events ========== */
    event Withdrew(
        bytes32 indexed transferId,
        address indexed recipient,
        uint256 amount,
        bytes32 transferNonce
    );
    event WithdrawalBonded(
        bytes32 indexed transferId,
        uint256 amount
    );
    event WithdrawalBondSettled(
        address indexed bonder,
        bytes32 indexed transferId,
        bytes32 indexed rootHash
    );
    event MultipleWithdrawalsSettled(
        address indexed bonder,
        bytes32 indexed rootHash,
        uint256 totalBondsSettled
    );
    event TransferRootSet(
        bytes32 indexed rootHash,
        uint256 totalAmount
    );
    /* ========== State ========== */
    mapping(bytes32 => TransferRoot) private _transferRoots;
    mapping(bytes32 => bool) private _spentTransferIds;
    mapping(address => mapping(bytes32 => uint256)) private _bondedWithdrawalAmounts;
    uint256 constant RESCUE_DELAY = 8 weeks;
    constructor(address[] memory bonders) public Accounting(bonders) {}
    /* ========== Public Getters ========== */
    /**
     * @dev Get the hash that represents an individual Transfer.
     * @param chainId The id of the destination chain
     * @param recipient The address receiving the Transfer
     * @param amount The amount being transferred including the `_bonderFee`
     * @param transferNonce Used to avoid transferId collisions
     * @param bonderFee The amount paid to the address that withdraws the Transfer
     * @param amountOutMin The minimum amount received after attempting to swap in the destination
     * AMM market. 0 if no swap is intended.
     * @param deadline The deadline for swapping in the destination AMM market. 0 if no
     * swap is intended.
     */
    function getTransferId(
        uint256 chainId,
        address recipient,
        uint256 amount,
        bytes32 transferNonce,
        uint256 bonderFee,
        uint256 amountOutMin,
        uint256 deadline
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            chainId,
            recipient,
            amount,
            transferNonce,
            bonderFee,
            amountOutMin,
            deadline
        ));
    }
    /**
     * @notice getChainId can be overridden by subclasses if needed for compatibility or testing purposes.
     * @dev Get the current chainId
     * @return chainId The current chainId
     */
    function getChainId() public virtual view returns (uint256 chainId) {
        this; // Silence state mutability warning without generating any additional byte code
        assembly {
            chainId := chainid()
        }
    }
    /**
     * @dev Get the TransferRoot id for a given rootHash and totalAmount
     * @param rootHash The Merkle root of the TransferRoot
     * @param totalAmount The total of all Transfers in the TransferRoot
     * @return The calculated transferRootId
     */
    function getTransferRootId(bytes32 rootHash, uint256 totalAmount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(rootHash, totalAmount));
    }
    /**
     * @dev Get the TransferRoot for a given rootHash and totalAmount
     * @param rootHash The Merkle root of the TransferRoot
     * @param totalAmount The total of all Transfers in the TransferRoot
     * @return The TransferRoot with the calculated transferRootId
     */
    function getTransferRoot(bytes32 rootHash, uint256 totalAmount) public view returns (TransferRoot memory) {
        return _transferRoots[getTransferRootId(rootHash, totalAmount)];
    }
    /**
     * @dev Get the amount bonded for the withdrawal of a transfer
     * @param bonder The Bonder of the withdrawal
     * @param transferId The Transfer's unique identifier
     * @return The amount bonded for a Transfer withdrawal
     */
    function getBondedWithdrawalAmount(address bonder, bytes32 transferId) external view returns (uint256) {
        return _bondedWithdrawalAmounts[bonder][transferId];
    }
    /**
     * @dev Get the spent status of a transfer ID
     * @param transferId The transfer's unique identifier
     * @return True if the transferId has been spent
     */
    function isTransferIdSpent(bytes32 transferId) external view returns (bool) {
        return _spentTransferIds[transferId];
    }
    /* ========== User/Relayer External Functions ========== */
    /**
     * @notice Can be called by anyone (recipient or relayer)
     * @dev Withdraw a Transfer from its destination bridge
     * @param recipient The address receiving the Transfer
     * @param amount The amount being transferred including the `_bonderFee`
     * @param transferNonce Used to avoid transferId collisions
     * @param bonderFee The amount paid to the address that withdraws the Transfer
     * @param amountOutMin The minimum amount received after attempting to swap in the destination
     * AMM market. 0 if no swap is intended. (only used to calculate `transferId` in this function)
     * @param deadline The deadline for swapping in the destination AMM market. 0 if no
     * swap is intended. (only used to calculate `transferId` in this function)
     * @param rootHash The Merkle root of the TransferRoot
     * @param transferRootTotalAmount The total amount being transferred in a TransferRoot
     * @param transferIdTreeIndex The index of the transferId in the Merkle tree
     * @param siblings The siblings of the transferId in the Merkle tree
     * @param totalLeaves The total number of leaves in the Merkle tree
     */
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 transferNonce,
        uint256 bonderFee,
        uint256 amountOutMin,
        uint256 deadline,
        bytes32 rootHash,
        uint256 transferRootTotalAmount,
        uint256 transferIdTreeIndex,
        bytes32[] calldata siblings,
        uint256 totalLeaves
    )
        external
        nonReentrant
    {
        bytes32 transferId = getTransferId(
            getChainId(),
            recipient,
            amount,
            transferNonce,
            bonderFee,
            amountOutMin,
            deadline
        );
        require(
            rootHash.verify(
                transferId,
                transferIdTreeIndex,
                siblings,
                totalLeaves
            )
        , "BRG: Invalid transfer proof");
        bytes32 transferRootId = getTransferRootId(rootHash, transferRootTotalAmount);
        _addToAmountWithdrawn(transferRootId, amount);
        _fulfillWithdraw(transferId, recipient, amount, uint256(0));
        emit Withdrew(transferId, recipient, amount, transferNonce);
    }
    /**
     * @dev Allows the bonder to bond individual withdrawals before their TransferRoot has been committed.
     * @param recipient The address receiving the Transfer
     * @param amount The amount being transferred including the `_bonderFee`
     * @param transferNonce Used to avoid transferId collisions
     * @param bonderFee The amount paid to the address that withdraws the Transfer
     */
    function bondWithdrawal(
        address recipient,
        uint256 amount,
        bytes32 transferNonce,
        uint256 bonderFee
    )
        external
        onlyBonder
        requirePositiveBalance
        nonReentrant
    {
        bytes32 transferId = getTransferId(
            getChainId(),
            recipient,
            amount,
            transferNonce,
            bonderFee,
            0,
            0
        );
        _bondWithdrawal(transferId, amount);
        _fulfillWithdraw(transferId, recipient, amount, bonderFee);
    }
    /**
     * @dev Refunds the Bonder's stake from a bonded withdrawal and counts that withdrawal against
     * its TransferRoot.
     * @param bonder The Bonder of the withdrawal
     * @param transferId The Transfer's unique identifier
     * @param rootHash The Merkle root of the TransferRoot
     * @param transferRootTotalAmount The total amount being transferred in a TransferRoot
     * @param transferIdTreeIndex The index of the transferId in the Merkle tree
     * @param siblings The siblings of the transferId in the Merkle tree
     * @param totalLeaves The total number of leaves in the Merkle tree
     */
    function settleBondedWithdrawal(
        address bonder,
        bytes32 transferId,
        bytes32 rootHash,
        uint256 transferRootTotalAmount,
        uint256 transferIdTreeIndex,
        bytes32[] calldata siblings,
        uint256 totalLeaves
    )
        external
    {
        require(
            rootHash.verify(
                transferId,
                transferIdTreeIndex,
                siblings,
                totalLeaves
            )
        , "BRG: Invalid transfer proof");
        bytes32 transferRootId = getTransferRootId(rootHash, transferRootTotalAmount);
        uint256 amount = _bondedWithdrawalAmounts[bonder][transferId];
        require(amount > 0, "L2_BRG: transferId has no bond");
        _bondedWithdrawalAmounts[bonder][transferId] = 0;
        _addToAmountWithdrawn(transferRootId, amount);
        _addCredit(bonder, amount);
        emit WithdrawalBondSettled(bonder, transferId, rootHash);
    }
    /**
     * @dev Refunds the Bonder for all withdrawals that they bonded in a TransferRoot.
     * @param bonder The address of the Bonder being refunded
     * @param transferIds All transferIds in the TransferRoot in order
     * @param totalAmount The totalAmount of the TransferRoot
     */
    function settleBondedWithdrawals(
        address bonder,
        // transferIds _must_ be calldata or it will be mutated by Lib_MerkleTree.getMerkleRoot
        bytes32[] calldata transferIds,
        uint256 totalAmount
    )
        external
    {
        bytes32 rootHash = Lib_MerkleTree.getMerkleRoot(transferIds);
        bytes32 transferRootId = getTransferRootId(rootHash, totalAmount);
        uint256 totalBondsSettled = 0;
        for(uint256 i = 0; i < transferIds.length; i++) {
            uint256 transferBondAmount = _bondedWithdrawalAmounts[bonder][transferIds[i]];
            if (transferBondAmount > 0) {
                totalBond
}
