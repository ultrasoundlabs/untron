// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./UniversalAddress.sol";

/// @author Daimo, Inc
/// @custom:security-contact security@daimo.com
/// @notice Factory contract that creates deterministic Universal Address vault
///         contracts using CREATE2 deployment for predictable addresses.
/// @dev Deploys Universal Address contracts at addresses determined by the
///      route parameters, enabling multi-chain systems to know vault addresses
///      before deployment. Each route maps to a unique vault address that can
///      hold funds and execute cross-chain transfers on behalf of users.
contract UniversalAddressFactory {
    /// Singleton implementation that all minimal proxies delegate to.
    UniversalAddress public immutable universalAddressImpl;

    event UniversalAddressDeployed(
        address indexed universalAddress,
        UniversalAddressRoute route
    );

    constructor() {
        universalAddressImpl = new UniversalAddress();
    }

    /// @dev Deploy the Universal Address for the given UniversalAddressRoute
    ///      (or return existing one).
    function createUniversalAddress(
        UniversalAddressRoute calldata route
    ) public returns (UniversalAddress ret) {
        address universalAddress = getUniversalAddress(route);
        if (universalAddress.code.length > 0) {
            // Already deployed, another CREATE2 would revert,
            // so not deploying and just returning the existing one.
            return UniversalAddress(payable(universalAddress));
        }
        ret = UniversalAddress(
            payable(
                address(
                    new ERC1967Proxy{salt: bytes32(0)}(
                        address(universalAddressImpl),
                        abi.encodeCall(
                            UniversalAddress.initialize,
                            calcRouteHash(route)
                        )
                    )
                )
            )
        );
        emit UniversalAddressDeployed(universalAddress, route);
    }

    /// @notice Pure view helper: compute CREATE2 address for a
    ///         UniversalAddressRoute.
    function getUniversalAddress(
        UniversalAddressRoute calldata route
    ) public view returns (address) {
        return
            Create2.computeAddress(
                0,
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(universalAddressImpl),
                            abi.encodeCall(
                                UniversalAddress.initialize,
                                calcRouteHash(route)
                            )
                        )
                    )
                )
            );
    }
}