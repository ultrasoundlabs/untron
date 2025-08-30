// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

import "./TokenUtils.sol";

/// Represents a contract call.
struct Call {
    /// Address of the contract to call.
    address to;
    /// Native token amount for call, or 0
    uint256 value;
    /// Calldata for call
    bytes data;
}

/// @author Daimo, Inc
/// @custom:security-contact security@daimo.com
/// @notice This contract is used to execute arbitrary contract calls on behalf
/// of the DaimoPay escrow contract.
/// WARNING: Never approve tokens directly to this contract. Never transfer
/// tokens to this contract. Such tokens can be stolen by anyone. All
/// interactions with this contract should be done via the DaimoPay contract.
contract DaimoPayExecutor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// The only address that is allowed to call the `execute` function.
    address public immutable escrow;

    constructor(address _escrow) {
        escrow = _escrow;
    }

    /// Execute arbitrary calls. Revert if any fail.
    /// Check that at least one of the expectedOutput tokens is present. Assumes
    /// that exactly one token is present and transfers it to the recipient.
    /// Returns any surplus tokens to the surplus recipient.
    function execute(
        Call[] calldata calls,
        TokenAmount[] calldata expectedOutput,
        address payable recipient,
        address payable surplusRecipient
    ) external nonReentrant {
        require(msg.sender == escrow, "DPCE: only escrow");

        // Execute provided calls.
        uint256 callsLength = calls.length;
        for (uint256 i = 0; i < callsLength; ++i) {
            Call calldata call = calls[i];
            (bool success, ) = call.to.call{value: call.value}(call.data);
            require(success, "DPCE: call failed");
        }

        /// Check that at least one of the expectedOutput tokens is present
        /// with enough balance.
        uint256 outputIndex = TokenUtils.checkBalance({
            tokenAmounts: expectedOutput
        });
        require(
            outputIndex < expectedOutput.length,
            "DPCE: insufficient output"
        );

        // Transfer the expected amount of the token to the recipient.
        TokenUtils.transfer({
            token: expectedOutput[outputIndex].token,
            recipient: recipient,
            amount: expectedOutput[outputIndex].amount
        });

        // Transfer any surplus tokens to the surplus recipient.
        TokenUtils.transferBalance({
            token: expectedOutput[outputIndex].token,
            recipient: surplusRecipient
        });
    }

    /// Execute a final call. Approve the final token and make the call.
    /// Return whether the call succeeded.
    function executeFinalCall(
        Call calldata finalCall,
        TokenAmount calldata finalCallToken,
        address payable refundAddr
    ) external nonReentrant returns (bool success) {
        require(msg.sender == escrow, "DPCE: only escrow");

        // Approve the final call token to the final call contract.
        TokenUtils.approve({
            token: finalCallToken.token,
            spender: address(finalCall.to),
            amount: finalCallToken.amount
        });

        // Then, execute the final call.
        (success, ) = finalCall.to.call{value: finalCall.value}(finalCall.data);

        // Send any excess funds to the refund address.
        TokenUtils.transferBalance({
            token: finalCallToken.token,
            recipient: refundAddr
        });
    }

    /// Accept native-token (eg ETH) inputs
    receive() external payable {}
}