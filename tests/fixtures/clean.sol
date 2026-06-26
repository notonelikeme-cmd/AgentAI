// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// Clean vault — no vulnerabilities. Used to verify zero false positives.
contract SafeVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    mapping(address => uint256) private _balances;
    IERC20 public immutable token;

    constructor(address _token, address _owner) Ownable(_owner) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), amount);
        _balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(_balances[msg.sender] >= amount, "insufficient");
        _balances[msg.sender] -= amount;           // state update BEFORE transfer
        token.safeTransfer(msg.sender, amount);
    }

    function adminDrain(address to) external onlyOwner {
        uint256 bal = token.balanceOf(address(this));
        token.safeTransfer(to, bal);
    }

    function balanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }
}
