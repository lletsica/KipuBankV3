// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20 <0.8.31;
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/v0.8/interfaces/AggregatorV3Interface.sol";
import {IUniswapV2Router02} from "v2-periphery/interfaces/IUniswapV2Router02.sol";
/**
 * @title KipuBankV3
 * @author @lletsica
 * @notice A secure banking contract for managing ETH and USDC deposits with whitelist functionality,
 *         price feeds, and Uniswap token swap capabilities. Implements role-based access control,
 *         reentrancy protection, and pausable functionality for enhanced security.
 * @dev This contract uses OpenZeppelin's AccessControl, ReentrancyGuard, and Pausable modules
 *      for security best practices. It integrates with Chainlink price feeds and Uniswap V2
 *      for token swap functionality.
 */
contract KipuBankV3 is AccessControl, ReentrancyGuard, Pausable {
    /* ===========================
     * ===== STATE VARIABLES =====
     * ========================= */
    /// @notice The role granted to addresses authorized to call deposit functions.
    bytes32 public constant DEPOSITOR_ROLE = keccak256("DEPOSITOR_ROLE");

    /// @notice The role granted to addresses authorized to call withdrawal functions.
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /// @notice The maximum total value (in a common denomination, implied USD value) the bank can hold.
    uint256 public immutable BANK_CAP;

    /// @notice The maximum amount allowed per withdrawal transaction.
    uint256 public immutable MAX_WITHD_PER_TX;

    /// @notice The address of the USDC ERC20 token contract.
    IERC20 public immutable USDC_TOKEN;

    /// @notice The number of decimals for the USDC token.
    uint8 public immutable USDC_DECIMALS;

    /// @notice The Chainlink AggregatorV3Interface used for fetching the ETH/USD price.
    AggregatorV3Interface public immutable PRICE_FEED;

    /// @notice The Uniswap V2 Router used for token swaps (e.g., token-to-USDC).
    IUniswapV2Router02 public immutable UNISWAP_ROUTER;

    /// @notice Tracks the total amount of ETH currently deposited and held by the contract.
    uint128 public withdrawalCounter;

    /// @notice Global counter for all withdrawal transactions.
    uint128 public depositCounter;

    /// @notice Global counter for eth deposit transactions.
    uint256 public totalEth;

    /// @notice Global counter for usdc deposit transactions.
    uint256 public totalUsdcDeposits;

    /// @notice Maps user addresses to their deposited ETH balance (in wei).
    mapping(address => uint256) public userEthBalances;

    /// @notice Maps user addresses to their deposited USDC balance (in token units).
    mapping(address => uint256) public userUsdcBalances;

    /// @notice Tracks which addresses are currently whitelisted for deposits and withdrawals.
    mapping(address => bool) public whitelist;

    /* =====================
     * ====== EVENTS =======
     * ===================== */

    /// @notice Emitted when a user successfully deposits ETH.
    /// @param user The address of the depositor.
    /// @param amount The amount of ETH deposited in wei.
    event DepositEth(address indexed user, uint256 amount);

    /// @notice Emitted when a user successfully deposits USDC (or after a token-to-USDC swap).
    /// @param user The address of the depositor.
    /// @param amount The amount of USDC deposited in token units.
    event DepositUsdc(address indexed user, uint256 amount);

    /// @notice Emitted when a user successfully withdraws funds (ETH or token).
    /// @param user The address of the withdrawing user.
    /// @param token The address of the withdrawn token (address(0) for ETH).
    /// @param amount The amount withdrawn in the token's smallest unit.
    event Withdrawal(
        address indexed user,
        address indexed token,
        uint256 amount
    );
    /// @notice Emitted when an address is added to the whitelist.
    /// @param user The address that was whitelisted.
    event Whitelisted(address indexed user);

    /// @notice Emitted when an address is removed from the whitelist.
    /// @param user The address that was removed from the whitelist.
    event RemovedFromWhitelist(address indexed user);

    /// @notice Emitted when an admin performs an emergency withdrawal.
    /// @param admin The address of the administrator executing the withdrawal.
    /// @param token The address of the withdrawn token (address(0) for ETH).
    /// @param amount The amount withdrawn.
    event EmergencyWithdrawal(
        address indexed admin,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted when a swap is successfully executed within the depositTokenToUsdc function.
    /// @param tokenIn The address of the token swapped.
    /// @param amountIn The amount of tokenIn swapped.
    /// @param tokenOut The address of the token received (USDC).
    /// @param amountOut The amount of tokenOut received (USDC).
    event SwapExecuted(
        address indexed tokenIn,
        uint256 amountIn,
        address indexed tokenOut,
        uint256 amountOut
    );

    /* =========================
     * ===== CUSTOM ERRORS =====
     * ========================= */
    /// @notice Reverts if the deposit amount is zero.
    error DepositAmountZero();

    /// @notice Reverts if the withdrawal amount is zero.
    error WithdrawalAmountZero();

    /// @notice Reverts if the deposit would exceed the contract's total capacity (BANK_CAP).
    error DepositExceedsBankCap();

    /// @notice Reverts if the user's balance is less than the requested withdrawal amount.
    error InsufficientUserBalance();

    /// @notice Reverts if the requested withdrawal amount exceeds the maximum allowed per transaction.
    /// @param maxWithdrawal The current maximum allowed withdrawal limit.
    error WithdrawalExceedsLimit(uint256 maxWithdrawal);

    /// @notice Reverts if the caller is not on the whitelist.
    /// @param user The address of the non-whitelisted user.
    error NotWhitelisted(address user);

    /// @notice Reverts if an ERC20 address parameter is address(0) or otherwise invalid (e.g., swap path).
    error InvalidTokenAddress();

    /// @notice Reverts when ETH is sent via `receive()` instead of the intended `depositEth()` function.
    error UseDepositEth();

    /// @notice Reverts when a call is made to an unsupported function via `fallback()`.
    error UnsupportedFunction();

    /// @notice Reverts if a generic transfer operation fails.
    error TransferFailed();

    /// @notice Reverts if an ETH transfer using `call{value:}` fails.
    error EthTransferFailed();

    /// @notice Reverts if an ERC20 token transfer/transferFrom fails.
    error Erc20TransferFailed();

    /// @notice Reverts if the Chainlink price is invalid (e.g., less than or equal to zero).
    /// @param price The invalid price value.
    error InvalidPrice(int256 price);

    /// @notice Reverts if the Chainlink price is too old (stale), indicating a risk of using an outdated value.
    /// @param price The stale price value.
    /// @param updatedAt The timestamp when the price was last updated.
    error StalePrice(int256 price, uint256 updatedAt);

    /// @notice Reverts if the token being swapped does not result in any USDC being received.
    error NoUsdcReceived();

    /// @notice Reverts if the received amount of USDC is less than the specified minimum output amount.
    error InsufficientOutputAmount();

    /// @notice Reverts if the user has not approved enough tokens for the contract to spend.
    error InsufficientAllowance();

    /* =======================
     * ===== CONSTRUCTOR =====
     * ===================== */

    /**
     * @notice Initializes the bank contract with immutable settings and grants initial roles.
     * @param _bankCap The maximum total value the contract can hold (in token base units/wei).
     * @param _maxWithdrawalPerTx The limit for a single withdrawal transaction.
     * @param _usdcAddress The address of the USDC token contract (IERC20).
     * @param _priceFeedAddress The address of the Chainlink ETH/USD price feed (AggregatorV3Interface).
     * @param _usdcDecimals The number of decimals of the USDC token.
     * @param _uniswapRouter The address of the Uniswap V2 Router02 contract.
     */
    constructor(
        uint256 _bankCap,
        uint256 _maxWithdrawalPerTx,
        address _usdcAddress,
        address _priceFeedAddress,
        uint8 _usdcDecimals,
        address _uniswapRouter
    ) {
        if (_usdcAddress == address(0) || _priceFeedAddress == address(0))
            revert InvalidTokenAddress();
        BANK_CAP = _bankCap;
        MAX_WITHD_PER_TX = _maxWithdrawalPerTx;
        USDC_TOKEN = IERC20(_usdcAddress);
        PRICE_FEED = AggregatorV3Interface(_priceFeedAddress);
        USDC_DECIMALS = _usdcDecimals;
        UNISWAP_ROUTER = IUniswapV2Router02(_uniswapRouter);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DEPOSITOR_ROLE, msg.sender);
        _grantRole(WITHDRAWER_ROLE, msg.sender);
    }

    /* =====================
     * ===== MODIFIERS =====
     * ================== */

    /// @notice Restricts access to functions to only whitelisted users.
    modifier onlyWhitelisted() {
        _checkWhitelisted(msg.sender);
        _;
    }

    /* =======================
     * == DEPOSIT FUNCTIONS ==
     * ===================== */

    /**
     * @notice Allows a whitelisted and authorized user to deposit ETH into the bank.
     * @dev Checks for zero amount, bank cap, uses caching for gas optimization, and is non-reentrant.
     */
    function depositEth()
        external
        payable
        whenNotPaused
        nonReentrant
        onlyWhitelisted
        onlyRole(DEPOSITOR_ROLE)
    {
        uint256 _amount = msg.value;
        if (_amount == 0) revert DepositAmountZero();
        uint256 _currentTotalEth = totalEth;
        uint256 _newTotalEth = _currentTotalEth + _amount;
        if (_newTotalEth > BANK_CAP) revert DepositExceedsBankCap();
        totalEth = _newTotalEth;
        unchecked {
            userEthBalances[msg.sender] += _amount;
        }
        depositCounter++;
        emit DepositEth(msg.sender, _amount);
    }

    /**
     * @notice Allows a whitelisted user to deposit any ERC20 token, which is then swapped
     * for USDC via Uniswap V2 and deposited into their USDC balance.
     * @dev Requires the user to have approved this contract to spend `_amountIn` of `_tokenIn`.
     * The contract must have MAX_UINT256 approval for the Uniswap router for token swaps.
     * Implements Checks-Effects-Interactions pattern for security.
     * @param _tokenIn The address of the token the user is depositing/swapping from.
     * @param _amountIn The amount of `_tokenIn` the user is depositing.
     * @param _minAmountOut The minimum amount of USDC the user expects to receive.
     * @param _path The path of the swap (e.g., [tokenIn, WETH, USDC_TOKEN]).
     */
    function depositTokenToUsdc(
        address _tokenIn,
        uint256 _amountIn,
        uint256 _minAmountOut,
        address[] calldata _path
    )
        external
        whenNotPaused
        nonReentrant
        onlyWhitelisted
        onlyRole(DEPOSITOR_ROLE)
    {
        // ===== CHECKS =====
        if (_amountIn == 0) revert DepositAmountZero();
        if (_tokenIn == address(0)) revert InvalidTokenAddress();

        // Validate swap path ends in USDC
        if (_path.length < 2 || _path[_path.length - 1] != address(USDC_TOKEN))
            revert InvalidTokenAddress();

        IERC20 tokenIn = IERC20(_tokenIn);

        // Check user has sufficient balance
        uint256 userBalance = tokenIn.balanceOf(msg.sender);
        if (userBalance < _amountIn) revert InsufficientUserBalance();

        // Check contract allowance
        uint256 allowance = tokenIn.allowance(msg.sender, address(this));
        if (allowance < _amountIn) revert InsufficientAllowance();

        // Check bank cap BEFORE any state changes
        uint256 usdcBefore = USDC_TOKEN.balanceOf(address(this));

        // ===== EFFECTS =====
        // Update user's token balance tracking (if you track input tokens)
        // Note: For this function, we only track USDC output, but we do state updates first

        // Store the current USDC balance for the user BEFORE external calls
        uint256 currentUserUsdcBalance = userUsdcBalances[msg.sender];
        depositCounter++; // State update BEFORE external call

        // ===== INTERACTIONS =====
        // 1. Transfer tokens from user to contract
        SafeERC20.safeTransferFrom(
            tokenIn,
            msg.sender,
            address(this),
            _amountIn
        );

        // 2. Approve Uniswap Router to spend tokens
        // Always set to 0 first for security (some tokens require this)
        SafeERC20.safeApprove(tokenIn, address(UNISWAP_ROUTER), 0);
        SafeERC20.safeApprove(tokenIn, address(UNISWAP_ROUTER), _amountIn);

        // 3. Execute swap
        UNISWAP_ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            _amountIn,
            _minAmountOut,
            _path,
            address(this),
            block.timestamp
        );

        // 4. Reset approval to 0 for security
        SafeERC20.safeApprove(tokenIn, address(UNISWAP_ROUTER), 0);

        // ===== POST-INTERACTION CHECKS & EFFECTS =====
        uint256 usdcAfter = USDC_TOKEN.balanceOf(address(this));
        uint256 usdcReceived = usdcAfter - usdcBefore;

        if (usdcReceived == 0) revert NoUsdcReceived();
        if (usdcReceived < _minAmountOut) revert InsufficientOutputAmount();

        // Check bank cap with the new deposit
        uint256 newTotalUsdc = totalUsdcDeposits + usdcReceived;
        if (newTotalUsdc > BANK_CAP) revert DepositExceedsBankCap();

        // Final state updates after all external interactions
        userUsdcBalances[msg.sender] = currentUserUsdcBalance + usdcReceived;
        totalUsdcDeposits = newTotalUsdc;

        emit DepositUsdc(msg.sender, usdcReceived);
        emit SwapExecuted(
            _tokenIn,
            _amountIn,
            address(USDC_TOKEN),
            usdcReceived
        );
    }

    /**
     * @notice Allows a whitelisted and authorized user to deposit USDC directly into the bank.
     * @dev Uses SafeERC20.safeTransferFrom for robust interaction with non-standard tokens.
     * @param _amount The amount of USDC to deposit.
     */
    function depositUsdc(
        uint256 _amount
    )
        external
        whenNotPaused
        nonReentrant
        onlyWhitelisted
        onlyRole(DEPOSITOR_ROLE)
    {
        if (_amount == 0) revert DepositAmountZero();
        IERC20 _token = USDC_TOKEN; // cache
        bool _ok = _token.transferFrom(msg.sender, address(this), _amount);
        if (!_ok) revert Erc20TransferFailed();
        unchecked {
            userUsdcBalances[msg.sender] += _amount;
        }
        depositCounter++;
        emit DepositUsdc(msg.sender, _amount);
    }

    /* =======================
     * = WITHDRAWAL FUNCTIONS ==
     * ======================= */

    /**
     * @notice Allows a whitelisted and authorized user to withdraw their ETH balance.
     * @dev Uses a low-level call (`call{value:}`) for ETH transfer and updates state before the transfer.
     * @param _amount The amount of ETH (in wei) to withdraw.
     */
    function withdrawEth(
        uint256 _amount
    )
        external
        whenNotPaused
        nonReentrant
        onlyWhitelisted
        onlyRole(WITHDRAWER_ROLE)
    {
        if (_amount == 0) revert WithdrawalAmountZero();
        uint256 _balance = userEthBalances[msg.sender];
        if (_balance < _amount) revert InsufficientUserBalance();
        if (_amount > MAX_WITHD_PER_TX)
            revert WithdrawalExceedsLimit(MAX_WITHD_PER_TX);
        unchecked {
            userEthBalances[msg.sender] = _balance - _amount;
            totalEth -= _amount;
        }
        withdrawalCounter++;
        (bool sent, ) = msg.sender.call{value: _amount}("");
        if (!sent) revert EthTransferFailed();
        emit Withdrawal(msg.sender, address(0), _amount);
    }

    /**
     * @notice Allows a whitelisted and authorized user to withdraw their USDC balance.
     * @dev Uses `SafeERC20.safeTransfer` (via underlying IERC20 transfer) for robust token transfer.
     * @param _amount The amount of USDC (in token units) to withdraw.
     */
    function withdrawUsdc(
        uint256 _amount
    )
        external
        whenNotPaused
        nonReentrant
        onlyWhitelisted
        onlyRole(WITHDRAWER_ROLE)
    {
        if (_amount == 0) revert WithdrawalAmountZero();
        // Cache multiple storage reads
        uint256 _maxLimit = MAX_WITHD_PER_TX;
        uint256 _balance = userUsdcBalances[msg.sender];

        if (_balance < _amount) revert InsufficientUserBalance();
        if (_amount > _maxLimit) revert WithdrawalExceedsLimit(_maxLimit);
        IERC20 _token = USDC_TOKEN;
        unchecked {
            userUsdcBalances[msg.sender] = _balance - _amount;
        }
        withdrawalCounter++;
        bool _ok = _token.transfer(msg.sender, _amount);
        if (!_ok) revert Erc20TransferFailed();
        emit Withdrawal(msg.sender, address(_token), _amount);
    }

    /* =======================
     * === VIEW FUNCTIONS ===
     * ======================= */

    /**
     * @notice Calculates the total USD value of a user's combined ETH and USDC balances.
     * @dev Fetches the current ETH/USD price from Chainlink, checking for staleness and validity.
     * @param _user The address whose total USD value is to be calculated.
     * @return totalUsd The total value in USD, scaled to 1e18 decimals (the standard for Chainlink).
     */
    function getUserTotalUsd(
        address _user
    ) external view returns (uint256 totalUsd) {
        uint256 _ethBalance = userEthBalances[_user];
        uint256 _usdcBalance = userUsdcBalances[_user];
        if (_ethBalance == 0 && _usdcBalance == 0) return 0;
        (, int256 _price, , uint256 _updatedAt, ) = PRICE_FEED
            .latestRoundData();
        if (_price <= 0) revert InvalidPrice(_price);
        if (_updatedAt < block.timestamp - 3600)
            revert StalePrice(_price, _updatedAt);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 _ethPrice = uint256(_price);
        uint256 _ethUsdValue = (_ethBalance * _ethPrice) / 1e26;
        uint256 _usdcUsdValue = _usdcBalance * 1e12;
        return _ethUsdValue + _usdcUsdValue;
    }

    /**
     * @notice Fetches the latest ETH/USD price from the Chainlink price feed.
     * @dev Checks for price validity and staleness (30 minutes).
     * @return The latest ETH/USD price (scaled by the Chainlink feed's decimals, typically 8).
     */
    function getLatestPrice() external view returns (int256) {
        (, int256 _price, , uint256 _updatedAt, ) = PRICE_FEED
            .latestRoundData();
        if (_price <= 0) revert InvalidPrice(_price);
        if (_updatedAt < block.timestamp - 3600)
            revert StalePrice(_price, _updatedAt);
        return _price;
    }

    /**
     * @notice Converts a specified amount of ETH (wei) into its USD value.
     * @dev Uses the Chainlink price feed, checking for validity and staleness.
     * @param _weiAmount The amount of ETH in wei (1e18) to convert.
     * @return _usdPrice The equivalent value in USD, scaled to 1e18 decimals.
     */
    function ethWeiToUsd(
        uint256 _weiAmount
    ) public view returns (uint256 _usdPrice) {
        (, int256 _price, , uint256 _updatedAt, ) = PRICE_FEED
            .latestRoundData();
        if (_price <= 0) revert InvalidPrice(_price);
        if (_updatedAt < block.timestamp - 3600)
            revert StalePrice(_price, _updatedAt);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 _ethPrice = uint256(_price);
        _usdPrice = (_weiAmount * _ethPrice) / 1e26;
    }

    /* =======================
     * ===== ADMIN FUNCTIONS =====
     * ======================= */

    /**
     * @notice Adds an address to the whitelist. Only callable by the Admin role.
     * @param _user The address to be whitelisted.
     */
    function addToWhitelist(
        address _user
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelist[_user] = true;
        emit Whitelisted(_user);
    }

    /**
     * @notice Removes an address from the whitelist. Only callable by the Admin role.
     * @param _user The address to be removed from the whitelist.
     */
    function removeFromWhitelist(
        address _user
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelist[_user] = false;
        emit RemovedFromWhitelist(_user);
    }

    /**
     * @notice Pauses the contract, preventing deposits and withdrawals. Only callable by the Admin role.
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses the contract, allowing normal operations to resume. Only callable by the Admin role.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Allows the Admin role to withdraw any token or ETH held by the contract in case of an emergency.
     * @dev Used for recovering funds or clearing accidental token deposits.
     * @param _token The address of the token to withdraw (address(0) for ETH).
     * @param _amount The amount of the token/ETH to withdraw.
     */
    function emergencyWithdraw(
        address _token,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (_token == address(0)) {
            (bool _sent, ) = msg.sender.call{value: _amount}("");
            if (!_sent) revert EthTransferFailed();
        } else {
            bool _ok = IERC20(_token).transfer(msg.sender, _amount);
            if (!_ok) revert Erc20TransferFailed();
        }
        emit EmergencyWithdrawal(msg.sender, _token, _amount);
    }

    /**
     * @notice Grants the Uniswap V2 Router maximum approval to spend a specific ERC20 token from this contract.
     * @dev This function sets the allowance of `_token` for the Uniswap router to `type(uint256).max`.
     *      It is intended to be called once per token to avoid repeated approvals and reduce gas costs.
     *      Only callable by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _token The address of the ERC20 token to approve for Uniswap Router interactions.
     */
    function approveRouterForToken(address _token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(_token).approve(address(UNISWAP_ROUTER), type(uint256).max);
    }
    
    /* ===================
     * ===== INTERNAL =====
     * =================== */

    /**
     * @notice Internal function to check if a user is whitelisted.
     * @dev Called by the 'onlyWhitelisted' modifier.
     * @param user The address to check.
     */
    function _checkWhitelisted(address user) internal view {
        if (!whitelist[user]) revert NotWhitelisted(user);
    }
    /* ======================
     * == RECEIVE/FALLBACK ==
     * =================== */
    /**
     * @notice Prevents ETH from being sent to the contract's address using the standard transfer/send method.
     * @dev Forces users to use the 'depositEth' function to track balances correctly.
     */
    receive() external payable {
        revert UseDepositEth();
    }

    /**
     * @notice Prevents unsolicited ETH from being sent to the contract's address without calling a function.
     */
    fallback() external payable {
        revert UnsupportedFunction();
    }
}
