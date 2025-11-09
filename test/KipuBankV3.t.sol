// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {KipuBankV3} from "../src/KipuBankV3.sol";
import {MockToken} from "../src/MockToken.sol";
import {DeployKipuBankV3} from "../script/DeployKipuBankV3.s.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUniswapV2Router02} from "v2-periphery/interfaces/IUniswapV2Router02.sol";

contract KipuBankV3Test is Test {
    KipuBankV3 public kipu;
    DeployKipuBankV3 public deployer;
    address public immutable WETH = address(0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9);
    address usdc = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
    address priceFeed = address(0x694AA1769357215DE4FAC081bf1f309aDC325306);
    address router = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    address admin = address(this);
    address user = address(0x123);
    address user2 = address(0x456);
    address userAdmin = address(0x789);
    function setUp() public {
        // Fork desde el RPC definido en .env
        vm.createSelectFork(vm.envString("RPC"));
        deployer = new DeployKipuBankV3();
        // Desplegar el contrato
        kipu = new KipuBankV3(
            100 ether, // _bankCap = 100 ether
            5 ether, // _maxWithdrawalPerTx = 5 ether
            usdc,
            priceFeed,
            6, // Decimales del token USDC
            router
        );

        // Configurar permisos
        kipu.addToWhitelist(user);
        kipu.addToWhitelist(user2);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), user);
        kipu.grantRole(kipu.WITHDRAWER_ROLE(), user);
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);
        // Simular un deposito inicial de USDC por parte de 'user'
        deal(usdc, user, 1_000 * 10 ** 6); // Asignar 1000 USDC (6 decimales) al usuario
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), 100 * 10 ** 6); // Aprobar 100 USDC
        kipu.depositUsdc(100 * 10 ** 6); // Depositar 100 USDC
        vm.stopPrank();
    }

    function testGetLatestPrice() public view {
        console.log("testGetLatestPrice");
        int256 price = kipu.getLatestPrice();
        assert(price > 0);
    }
        
    function testDepositEthZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.DepositAmountZero.selector);
        kipu.depositEth{value: 0}();
    }
    function testDepositUsdcZeroReverts() public {
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), 1e18);
        vm.expectRevert(KipuBankV3.DepositAmountZero.selector);
        kipu.depositUsdc(0);
        vm.stopPrank();
    }

    function testAddRemoveWhitelist() public {
        kipu.addToWhitelist(address(0x999));
        assertTrue(kipu.whitelist(address(0x999)));
        kipu.removeFromWhitelist(address(0x999));
        assertFalse(kipu.whitelist(address(0x999)));
    }

    function testReceiveFallbackReverts() public {
        console.log("testReceiveFallbackReverts");
        (bool ok1, ) = address(kipu).call{value: 1 ether}("");
        assertFalse(ok1);
        (bool ok2, ) = address(kipu).call(
            abi.encodeWithSignature("nonexistent()")
        );
        assertFalse(ok2);
    }

    function testDepositEthSuccess() public {
        uint256 depositAmount = 1 ether;

        // Simular el envío de ETH desde el usuario
        vm.deal(user, depositAmount); // Asignar ETH al usuario
        vm.startPrank(user);

        // Capturar evento
        vm.expectEmit(true, true, false, true);
        emit KipuBankV3.DepositEth(user, depositAmount);

        // Ejecutar el deposito
        kipu.depositEth{value: depositAmount}();

        // Verificar balance interno
        uint256 userBalance = kipu.userEthBalances(user);
        assertEq(
            userBalance,
            depositAmount,
            "El balance ETH del usuario debe coincidir"
        );

        // Verificar contador de depositos
        assertEq(
            kipu.depositCounter(),
            2,
            "El contador de depositos debe incrementarse"
        );

        vm.stopPrank();
    }

    function testWithdrawEthSuccess() public {
        uint256 depositAmount = 2 ether;
        uint256 withdrawAmount = 1 ether;

        // Asignar ETH al usuario y simular deposito previo
        vm.deal(user, depositAmount);
        vm.startPrank(user);
        kipu.depositEth{value: depositAmount}();
        vm.stopPrank();

        // Capturar balance previo del usuario
        uint256 userBalanceBefore = user.balance;

        // Ejecutar retiro
        vm.startPrank(user);
        vm.expectEmit(true, true, false, true);
        emit KipuBankV3.Withdrawal(user, address(0), withdrawAmount);
        kipu.withdrawEth(withdrawAmount);
        vm.stopPrank();

        // Verificar balance interno del contrato
        uint256 remainingBalance = kipu.userEthBalances(user);
        assertEq(
            remainingBalance,
            depositAmount - withdrawAmount,
            "El balance ETH interno debe disminuir"
        );

        // Verificar que el usuario recibio el ETH
        uint256 userBalanceAfter = user.balance;
        assertEq(
            userBalanceAfter,
            userBalanceBefore + withdrawAmount,
            "El usuario debe recibir el ETH retirado"
        );

        // Verificar contador de retiros
        assertEq(
            kipu.withdrawalCounter(),
            1,
            "El contador de retiros debe incrementarse"
        );
    }

    function testWithdrawUsdcSuccess() public {
        uint256 depositAmount = 100 * 10 ** 6;
        uint256 withdrawAmount = 40 * 10 ** 6;

        // Asignar USDC y depositar
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();

        // Capturar balance interno antes del retiro
        uint256 beforeBalance = kipu.userUsdcBalances(user);

        // Ejecutar retiro
        vm.startPrank(user);
        kipu.withdrawUsdc(withdrawAmount);
        vm.stopPrank();

        // Verificar que el retiro se reflejo correctamente
        uint256 afterBalance = kipu.userUsdcBalances(user);
        assertEq(
            afterBalance,
            beforeBalance - withdrawAmount,
            "El retiro debe disminuir el balance interno correctamente"
        );
    }

    function testDepositTokenToUsdcNoUsdcReceivedReverts() public {
        MockToken mock = new MockToken();
        address tokenIn = address(mock);

        address[] memory path = new address[](3);
        path[0] = tokenIn;
        path[1] = WETH; // WETH address definido en setUp
        path[2] = usdc;

        uint256 depositAmount = 1e6;
        uint256 minAmountOut = 100 * 10 ** 6; // Esperamos al menos 100 USDC

        // **CORRECCIoN CLAVE:** Usar 'deal' para asignar tokens al usuario
        deal(tokenIn, user, depositAmount); // El usuario tiene el tokenIn necesario

        // 1. Establecer el balance inicial de USDC en el contrato KipuBank
        uint256 usdcBefore = 1_000 * 10 ** 6;
        deal(usdc, address(kipu), usdcBefore);

        vm.startPrank(user);
        IERC20(tokenIn).approve(address(kipu), depositAmount);

        // 2. Mockear el swap: Simular la llamada al router
        vm.mockCall(
            address(kipu.UNISWAP_ROUTER()),
            abi.encodeWithSelector(
                IUniswapV2Router02
                    .swapExactTokensForTokensSupportingFeeOnTransferTokens
                    .selector,
                depositAmount,
                minAmountOut,
                path,
                address(kipu),
                block.timestamp
            ),
            abi.encode()
        );

        // 3. Simular balance después del swap (menor al mínimo)
        uint256 usdcReceived = minAmountOut - 1;
        deal(usdc, address(kipu), usdcBefore + usdcReceived); // Simula el resultado NoUsdcReceived
        vm.expectRevert(KipuBankV3.NoUsdcReceived.selector);
        kipu.depositTokenToUsdc(tokenIn, depositAmount, minAmountOut, path);

        vm.stopPrank();
    }

    function testEthWeiToUsdReturnsExpectedValue() public {
        // Simular un precio de 2000 USD por ETH (con 8 decimales, como Chainlink)
        int256 mockPrice = 2000 * 10 ** 8;
        uint80 roundId = 1;
        uint256 updatedAt = block.timestamp;
        bytes memory response = abi.encode(roundId, mockPrice, 0, updatedAt, 0);

        // Mockear el price feed
        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );

        // Llamar a la funcion con 1 ether
        uint256 ethAmount = 1 ether;
        uint256 usd = kipu.ethWeiToUsd(ethAmount);

        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 expectedUsd = (ethAmount * uint256(mockPrice)) / 1e26;

        assertEq(
            usd,
            expectedUsd,
            "La conversion de ETH a USD debe ser correcta"
        );
    }
    function testPauseAndUnpause() public {
        // Verificar que el contrato está activo inicialmente
        assertFalse(
            kipu.paused(),
            "El contrato no deberia estar pausado al inicio"
        );

        // Pausar el contrato
        kipu.pause();
        assertTrue(kipu.paused(), "El contrato deberia estar pausado");

        // Despausar el contrato
        kipu.unpause();
        assertFalse(
            kipu.paused(),
            "El contrato deberia estar activo nuevamente"
        );
    }
    function testDepositUsdcFailsWhenPaused() public {
        uint256 depositAmount = 50 * 10 ** 6;

        // Asignar USDC al usuario
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        vm.stopPrank();

        // Pausar el contrato como admin
        kipu.pause();
        assertTrue(kipu.paused(), "El contrato debe estar pausado");

        // Intentar depositar USDC y esperar revert
        vm.startPrank(user);
        vm.expectRevert("Pausable: paused");
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();
    }
    function testUserAdminCanPauseContract() public {
        // Asignar rol de admin
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);

        // Simular accion como userAdmin
        vm.startPrank(userAdmin);
        kipu.pause();
        assertTrue(
            kipu.paused(),
            "El contrato debe estar pausado por userAdmin"
        );
        vm.stopPrank();
    }

    function testUserAdminCanEmergencyWithdrawUsdc() public {
        // Asignar rol de admin
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);

        // Asegurar que el contrato tenga USDC
        uint256 depositAmount = 100 * 10 ** 6;
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();

        // Capturar balance previo de userAdmin
        uint256 balanceBefore = IERC20(usdc).balanceOf(userAdmin);

        // Ejecutar retiro de emergencia
        vm.startPrank(userAdmin);
        kipu.emergencyWithdraw(usdc, depositAmount);
        vm.stopPrank();

        // Verificar que userAdmin recibio los fondos
        uint256 balanceAfter = IERC20(usdc).balanceOf(userAdmin);
        assertEq(
            balanceAfter - balanceBefore,
            depositAmount,
            "userAdmin debe recibir los USDC retirados"
        );
    }

    function testDepositTokenToUsdcFailsWithoutApproval() public {
        address linkToken = address(0x779877A7B0D9E8603169DdbD7836e478b4624789);
        address linkHolder = address(
            0x268b9DbE1Ff41904310C1B83cDF1Be7ee6D3e009
        );
        uint256 linkAmount = 10 * 10 ** 18;
        uint256 minUsdcOut = 1 * 10 ** 6;

        // Asignar permisos y whitelist
        kipu.addToWhitelist(linkHolder);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), linkHolder);
        // Impersonar al admin
        vm.startPrank(admin);
        kipu.approveRouterForToken(linkToken);
        // Impersonar al holder
        vm.startPrank(linkHolder);

        // Asignar LINK al holder
        deal(linkToken, linkHolder, linkAmount);

        // No se aprueba el contrato para gastar LINK

        // Definir el path de swap: LINK → WETH → USDC
        address[] memory path = new address[](3);
        path[0] = linkToken;
        path[1] = WETH;
        path[2] = usdc;

        // Esperar revert por falta de aprobacion
        vm.expectRevert(KipuBankV3.InsufficientAllowance.selector);
        kipu.depositTokenToUsdc(linkToken, linkAmount, minUsdcOut, path);

        vm.stopPrank();
    }

    function testLinkApprovalForRouter() public {
        address linkToken = address(0x779877A7B0D9E8603169DdbD7836e478b4624789);
        address linkHolder = address(
            0x268b9DbE1Ff41904310C1B83cDF1Be7ee6D3e009
        );
        uint256 linkAmount = 10 * 10 ** 18;

        // Asignar permisos y whitelist
        kipu.addToWhitelist(linkHolder);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), linkHolder);

        // Impersonar al holder
        vm.startPrank(linkHolder);

        // Asignar LINK al holder
        deal(linkToken, linkHolder, linkAmount);

        // Aprobar el contrato para gastar LINK
        IERC20(linkToken).approve(address(kipu), linkAmount);

        // Verificar que el contrato tiene aprobacion para gastar LINK del usuario
        uint256 allowanceToKipu = IERC20(linkToken).allowance(
            linkHolder,
            address(kipu)
        );
        assertEq(
            allowanceToKipu,
            linkAmount,
            "KipuBankV3 debe tener aprobacion para gastar LINK del usuario"
        );

        // Simular que el contrato aprueba al router (esto normalmente ocurre dentro de depositTokenToUsdc)
        vm.stopPrank();
        vm.startPrank(address(kipu)); // Simular que el contrato aprueba al router
        IERC20(linkToken).approve(router, type(uint256).max);

        // Verificar que el router tiene aprobacion para gastar LINK desde el contrato
        uint256 allowanceToRouter = IERC20(linkToken).allowance(
            address(kipu),
            router
        );
        assertEq(
            allowanceToRouter,
            type(uint256).max,
            "El router debe tener aprobacion maxima para gastar LINK desde el contrato"
        );
    }

    function testEmergencyWithdrawEthSuccess() public {
        address _admin = user;
        uint256 _amount = 1 ether;

        // Simular que el contrato tiene ETH
        vm.deal(address(kipu), _amount);
        uint256 initialBalance = _admin.balance;

        // Asegurar que el caller tiene rol de admin
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), _admin);

        // Ejecutar como admin
        vm.startPrank(_admin);
        kipu.emergencyWithdraw(address(0), _amount);

        // Verificar que el ETH fue transferido correctamente
        assertEq(
            _admin.balance,
            initialBalance + _amount,
            "El admin debe recibir el ETH"
        );
        assertEq(address(kipu).balance, 0, "El contrato debe quedar sin saldo");
    }

    function testEmergencyWithdrawEthFails() public {
        address _receiver = address(0xe839305F80114568D524eb3048bEFA78dcc06Aa0); //sepolia RejectEth contract
        uint256 _amount = 1 ether;

        // Simular que el contrato tiene ETH
        vm.deal(address(kipu), _amount);

        // Asegurar que el caller tiene rol de admin
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), address(_receiver));

        // Ejecutar como el contrato que rechaza ETH
        vm.startPrank(address(_receiver));
        vm.expectRevert(KipuBankV3.EthTransferFailed.selector);
        kipu.emergencyWithdraw(address(0), _amount);
    }

    function testWithdrawEthZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.WithdrawalAmountZero.selector);
        kipu.withdrawEth(0);
    }

    function testWithdrawUsdcZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.WithdrawalAmountZero.selector);
        kipu.withdrawUsdc(0);
    }

    function testDepositEthExceedsBankCapReverts() public {
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.DepositExceedsBankCap.selector);
        kipu.depositEth{value: 200 ether}();
        vm.stopPrank();
    }

    function testWithdrawUsdcInsufficientBalanceReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InsufficientUserBalance.selector);
        kipu.withdrawUsdc(999_999 * 10 ** 6);
    }

    function testWithdrawEthExceedsLimitReverts() public {
        vm.deal(user, 10 ether);
        vm.startPrank(user);
        kipu.depositEth{value: 10 ether}();
        vm.expectRevert(
            abi.encodeWithSelector(
                KipuBankV3.WithdrawalExceedsLimit.selector,
                5 ether
            )
        );
        kipu.withdrawEth(6 ether);
        vm.stopPrank();
    }

    function testDepositEthNotWhitelistedReverts() public {
        address unlisted = address(0x999);
        vm.deal(unlisted, 1 ether);
        vm.startPrank(unlisted);
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.NotWhitelisted.selector, unlisted)
        );
        kipu.depositEth{value: 1 ether}();
    }

    function testDepositTokenToUsdcInvalidTokenAddressReverts() public {
        address[] memory path = new address[](2);
        path[0] = address(0x123);
        path[1] = usdc;

        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(address(0), 1e18, 1e6, path);
    }
    function testDepositTokenToUsdcInvalidPathReverts() public {
        address tokenIn = address(new MockToken());
        uint256 amountIn = 1e6;

        // Caso 1: Path vacío o muy corto (< 2)
        address[] memory pathShort = new address[](1);
        pathShort[0] = tokenIn;

        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(tokenIn, amountIn, 1, pathShort);

        // Caso 2: Path no termina en USDC
        address[] memory pathEndsInWeth = new address[](2);
        pathEndsInWeth[0] = tokenIn;
        pathEndsInWeth[1] = WETH;

        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(tokenIn, amountIn, 1, pathEndsInWeth);
        vm.stopPrank();
    }
    function testFallbackRevertsWithUnsupportedFunction() public {
        vm.startPrank(user);
        (bool success, bytes memory data) = address(kipu).call(
            abi.encodeWithSignature("nonexistentFunction()")
        );

        assertFalse(success, "La llamada debe fallar");

        // Verificamos que el revert fue por UnsupportedFunction
        bytes4 expectedSelector = KipuBankV3.UnsupportedFunction.selector;
        bytes4 actualSelector;
        assembly {
            actualSelector := mload(add(data, 0x20))
        }
        assertEq(
            actualSelector,
            expectedSelector,
            "El error debe ser UnsupportedFunction"
        );
    }

    function testReceiveRevertsWithUseDepositEth() public {
        vm.deal(user, 1 ether);
        vm.startPrank(user);

        // Esperamos revert con el error personalizado
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.UseDepositEth.selector)
        );
        payable(address(kipu)).transfer(1 ether);
    }

    function testDepositTokenToUsdcInsufficientAllowanceReverts() public {
        address token = usdc;
        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = usdc;

        deal(token, user, 1e6);
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InsufficientAllowance.selector);
        kipu.depositTokenToUsdc(token, 1e6, 1e6, path);
    }

    function testGetLatestPriceInvalidReverts() public {
        bytes memory response = abi.encode(0, int256(0), 0, block.timestamp, 0);
        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.InvalidPrice.selector, int256(0))
        );
        kipu.getLatestPrice();
    }

    function testDeployment() public {
        kipu = deployer.run();

        // Verify deployment was successful
        assertTrue(address(kipu) != address(0), "KipuBank deployment failed");

        // Test initial parameters
        assertEq(
            address(kipu.USDC_TOKEN()),
            address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238)
        );
        assertEq(
            address(kipu.PRICE_FEED()),
            address(0x694AA1769357215DE4FAC081bf1f309aDC325306)
        );
        assertEq(
            address(kipu.UNISWAP_ROUTER()),
            address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)
        );
        assertEq(kipu.USDC_DECIMALS(), 6);
    }

    function testConstructorUsdcZeroAddressReverts() public {
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        new KipuBankV3(
            100 ether,
            5 ether,
            address(0), // USDC Address 0
            priceFeed,
            6,
            router
        );
    }

    function testPriceFeedStaleReverts() public {
        int256 mockPrice = 2000 * 10 ** 8;
        // Simular que el precio se actualizo hace más de 3600 segundos (1 hora)
        uint256 staleUpdatedAt = block.timestamp - 3601;

        bytes memory response = abi.encode(
            uint80(1),
            mockPrice,
            0,
            staleUpdatedAt, // Timestamp obsoleto
            0
        );

        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                KipuBankV3.StalePrice.selector,
                mockPrice,
                staleUpdatedAt
            )
        );
        kipu.getLatestPrice();
    }

}
