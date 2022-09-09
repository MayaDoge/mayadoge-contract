// SPDX-License-Identifier: MIT

pragma solidity 0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

import "../owner/Operator.sol";

contract MBond is ERC20Burnable, Operator {
    /**
     * @notice Constructs the MAYA Bond ERC-20 contract.
     */
    constructor() public ERC20("MayaDoge Bond", "MBOND") {}

    /**
     * @notice Operator mints MAYA bonds to a recipient
     * @param recipient_ The address of recipient
     * @param amount_ The amount of mayadoge bonds to mint to
     * @return whether the process has been done
     */
    function mint(address recipient_, uint256 amount_)
        public
        onlyOperator
        returns (bool)
    {
        uint256 balanceBefore = balanceOf(recipient_);
        _mint(recipient_, amount_);
        uint256 balanceAfter = balanceOf(recipient_);

        return balanceAfter > balanceBefore;
    }

    function burn(uint256 amount) public override {
        super.burn(amount);
    }

    function burnFrom(address account, uint256 amount)
        public
        override
        onlyOperator
    {
        super.burnFrom(account, amount);
    }
}