// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// Intentionally vulnerable vault — used only in tests.
contract VulnerableVault {
    mapping(address => uint256) public balances;
    IERC20 public token;
    address public owner;
    uint256 public totalDeposited;

    constructor(address _token) {
        token = IERC20(_token);
        owner = msg.sender;
    }

    // HIGH: reentrancy — transfer before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        token.transfer(msg.sender, amount);   // external call BEFORE update
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
    }

    // HIGH: missing access control on privileged function
    function emergencyDrain(address to) external {
        uint256 bal = token.balanceOf(address(this));
        token.transfer(to, bal);
    }

    // MEDIUM: direct balanceOf — donation attack surface
    function totalAssets() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    // MEDIUM: unchecked arithmetic
    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            return a + b;
        }
    }

    // HIGH: tx.origin authentication
    function adminWithdraw(address to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        token.transfer(to, amount);
    }

    // LOW: block.timestamp comparison
    function isExpired(uint256 deadline) external view returns (bool) {
        return block.timestamp > deadline;
    }

    // INFO: floating pragma caught by the pragma pattern in another file
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalDeposited += amount;
    }
}
