// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

import "./TokenUtils.sol"; // Provides TokenAmount struct
import "./interfaces/IDaimoPayBridger.sol";
import "./interfaces/IUniversalAddressBridger.sol";

/// @author Daimo, Inc
/// @notice Simplified bridging interface for the Universal Address system
///         that multiplexes between multiple bridge-specific adapters (e.g.
///         CCTP, Across, Axelar).
contract UniversalAddressBridger is IUniversalAddressBridger {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Immutable routing data (set once in the constructor)
    // ---------------------------------------------------------------------

    /// Map destination chainId to IDaimoPayBridger bridge-specific adapter.
    mapping(uint256 chainId => IDaimoPayBridger adapter)
        public chainIdToBridger;

    /// Map destination chainId to the stablecoin token bridged to.
    mapping(uint256 chainId => address stableOut) public chainIdToStableOut;

    constructor(
        uint256[] memory toChainIds,
        IDaimoPayBridger[] memory bridgers,
        address[] memory stableOut
    ) {
        uint256 n = toChainIds.length;
        require(
            n == bridgers.length && n == stableOut.length,
            "UAB: length mismatch"
        );
        for (uint256 i; i < n; ++i) {
            chainIdToBridger[toChainIds[i]] = bridgers[i];
            chainIdToStableOut[toChainIds[i]] = stableOut[i];
        }
    }

    // ---------------------------------------------------------------------
    // Mutating state
    // ---------------------------------------------------------------------

    /// @inheritdoc IUniversalAddressBridger
    function sendToChain(
        uint256 toChainId,
        address toAddress,
        TokenAmount calldata bridgeTokenOut,
        address refundAddress,
        bytes calldata extraData
    ) external {
        // Determine the required input asset and quantity for the requested bridge.
        (IDaimoPayBridger adapter, TokenAmount[] memory opts) = _getAdapter({
            toChainId: toChainId,
            bridgeTokenOut: bridgeTokenOut
        });
        (address bridgeTokenIn, uint256 inAmount) = adapter.getBridgeTokenIn({
            toChainId: toChainId,
            bridgeTokenOutOptions: opts
        });

        // Pull tokens from caller into this contract.
        IERC20(bridgeTokenIn).safeTransferFrom({
            from: msg.sender,
            to: address(this),
            value: inAmount
        });

        // Approve the adapter to spend and forward the call.
        IERC20(bridgeTokenIn).forceApprove({
            spender: address(adapter),
            value: inAmount
        });

        adapter.sendToChain({
            toChainId: toChainId,
            toAddress: toAddress,
            bridgeTokenOutOptions: opts,
            refundAddress: refundAddress,
            extraData: extraData
        });
    }

    // ---------------------------------------------------------------------
    // View helpers
    // ---------------------------------------------------------------------

    /// @inheritdoc IUniversalAddressBridger
    function getBridgeTokenIn(
        uint256 toChainId,
        TokenAmount calldata bridgeTokenOut
    ) public view returns (address bridgeTokenIn, uint256 inAmount) {
        (IDaimoPayBridger adapter, TokenAmount[] memory opts) = _getAdapter({
            toChainId: toChainId,
            bridgeTokenOut: bridgeTokenOut
        });
        (bridgeTokenIn, inAmount) = adapter.getBridgeTokenIn({
            toChainId: toChainId,
            bridgeTokenOutOptions: opts
        });
    }

    /// @dev Helper to get the bridge-specific adapter contract and the
    ///      TokenAmount[] expected by the adapter.
    function _getAdapter(
        uint256 toChainId,
        TokenAmount calldata bridgeTokenOut
    )
        private
        view
        returns (IDaimoPayBridger adapter, TokenAmount[] memory opts)
    {
        require(toChainId != block.chainid, "UAB: same chain");

        adapter = chainIdToBridger[toChainId];
        require(address(adapter) != address(0), "UAB: unknown chain");

        // Ensure the requested bridgeTokenOut matches configured stablecoin for this chain.
        address tokOut = chainIdToStableOut[toChainId];
        require(address(bridgeTokenOut.token) == tokOut, "UAB: token mismatch");

        // Build a single-element TokenAmount[] expected by the adapter
        opts = new TokenAmount[](1);
        opts[0] = bridgeTokenOut;
    }
}