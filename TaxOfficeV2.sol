// SPDX-License-Identifier: MIT

pragma solidity 0.8.0;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "../owner/Operator.sol";
import "../interfaces/ITaxable.sol";
import "../interfaces/IUniswapV2Router.sol";
import "../interfaces/IERC20.sol";

contract TaxOfficeV2 is Operator {
    using SafeMath for uint256;

    address public mayadoge = address(0x731beFdb2c76B726E49b9f81c3650aa8c03b8a7a); 
    address public weth = address(0xB7ddC6414bf4F5515b52D8BdD69973Ae205ff101);
    address public uniRouter = address(0xa4EE06Ce40cb7e8c04E127c1F7D3dFB7F7039C81);

    mapping(address => bool) public taxExclusionEnabled;

    function setTaxTiersTwap(uint8 _index, uint256 _value)
        public
        onlyOperator
        returns (bool)
    {
        return ITaxable(mayadoge).setTaxTiersTwap(_index, _value);
    }

    function setTaxTiersRate(uint8 _index, uint256 _value)
        public
        onlyOperator
        returns (bool)
    {
        return ITaxable(mayadoge).setTaxTiersRate(_index, _value);
    }

    function enableAutoCalculateTax() public onlyOperator {
        ITaxable(mayadoge).enableAutoCalculateTax();
    }

    function disableAutoCalculateTax() public onlyOperator {
        ITaxable(mayadoge).disableAutoCalculateTax();
    }

    function setTaxRate(uint256 _taxRate) public onlyOperator {
        ITaxable(mayadoge).setTaxRate(_taxRate);
    }

    function setBurnThreshold(uint256 _burnThreshold) public onlyOperator {
        ITaxable(mayadoge).setBurnThreshold(_burnThreshold);
    }

    function setTaxCollectorAddress(address _taxCollectorAddress)
        public
        onlyOperator
    {
        ITaxable(mayadoge).setTaxCollectorAddress(_taxCollectorAddress);
    }

    function excludeAddressFromTax(address _address)
        external
        onlyOperator
        returns (bool)
    {
        return _excludeAddressFromTax(_address);
    }

    function _excludeAddressFromTax(address _address) private returns (bool) {
        if (!ITaxable(mayadoge).isAddressExcluded(_address)) {
            return ITaxable(mayadoge).excludeAddress(_address);
        }
    }

    function includeAddressInTax(address _address)
        external
        onlyOperator
        returns (bool)
    {
        return _includeAddressInTax(_address);
    }

    function _includeAddressInTax(address _address) private returns (bool) {
        if (ITaxable(mayadoge).isAddressExcluded(_address)) {
            return ITaxable(mayadoge).includeAddress(_address);
        }
    }

    function taxRate() external returns (uint256) {
        return ITaxable(mayadoge).taxRate();
    }

    function addLiquidityTaxFree(
        address token,
        uint256 amtMayaDoge,
        uint256 amtToken,
        uint256 amtMayaDogeMin,
        uint256 amtTokenMin
    )
        external
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        require(amtMayaDoge != 0 && amtToken != 0, "amounts can't be 0");
        _excludeAddressFromTax(msg.sender);

        IERC20(mayadoge).transferFrom(msg.sender, address(this), amtMayaDoge);
        IERC20(token).transferFrom(msg.sender, address(this), amtToken);
        _approveTokenIfNeeded(mayadoge, uniRouter);
        _approveTokenIfNeeded(token, uniRouter);

        _includeAddressInTax(msg.sender);

        uint256 resultAmtMayaDoge;
        uint256 resultAmtToken;
        uint256 liquidity;
        (resultAmtMayaDoge, resultAmtToken, liquidity) = IUniswapV2Router(
            uniRouter
        ).addLiquidity(
                mayadoge,
                token,
                amtMayaDoge,
                amtToken,
                amtMayaDogeMin,
                amtTokenMin,
                msg.sender,
                block.timestamp
            );

        if (amtMayaDoge.sub(resultAmtMayaDoge) > 0) {
            IERC20(mayadoge).transfer(msg.sender, amtMayaDoge.sub(resultAmtMayaDoge));
        }
        if (amtToken.sub(resultAmtToken) > 0) {
            IERC20(token).transfer(msg.sender, amtToken.sub(resultAmtToken));
        }
        return (resultAmtMayaDoge, resultAmtToken, liquidity);
    }

    function addLiquidityETHTaxFree(
        uint256 amtMayaDoge,
        uint256 amtMayaDogeMin,
        uint256 amtEthMin
    )
        external
        payable
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        require(amtMayaDoge != 0 && msg.value != 0, "amounts can't be 0");
        _excludeAddressFromTax(msg.sender);

        IERC20(mayadoge).transferFrom(msg.sender, address(this), amtMayaDoge);
        _approveTokenIfNeeded(mayadoge, uniRouter);

        _includeAddressInTax(msg.sender);

        uint256 resultAmtMayaDoge;
        uint256 resultAmtEth;
        uint256 liquidity;
        (resultAmtMayaDoge, resultAmtEth, liquidity) = IUniswapV2Router(uniRouter)
            .addLiquidityETH{value: msg.value}(
            mayadoge,
            amtMayaDoge,
            amtMayaDogeMin,
            amtEthMin,
            msg.sender,
            block.timestamp
        );

        if (amtMayaDoge.sub(resultAmtMayaDoge) > 0) {
            IERC20(mayadoge).transfer(msg.sender, amtMayaDoge.sub(resultAmtMayaDoge));
        }
        return (resultAmtMayaDoge, resultAmtEth, liquidity);
    }

    function setTaxableMayaDogeOracle(address _mayadogeOracle) external onlyOperator {
        ITaxable(mayadoge).setMayaDogeOracle(_mayadogeOracle);
    }

    function transferTaxOffice(address _newTaxOffice) external onlyOperator {
        ITaxable(mayadoge).setTaxOffice(_newTaxOffice);
    }

    function taxFreeTransferFrom(
        address _sender,
        address _recipient,
        uint256 _amt
    ) external {
        require(
            taxExclusionEnabled[msg.sender],
            "Address not approved for tax free transfers"
        );
        _excludeAddressFromTax(_sender);
        IERC20(mayadoge).transferFrom(_sender, _recipient, _amt);
        _includeAddressInTax(_sender);
    }

    function setTaxExclusionForAddress(address _address, bool _excluded)
        external
        onlyOperator
    {
        taxExclusionEnabled[_address] = _excluded;
    }

    function _approveTokenIfNeeded(address _token, address _router) private {
        if (IERC20(_token).allowance(address(this), _router) == 0) {
            IERC20(_token).approve(_router, type(uint256).max);
        }
    }
}