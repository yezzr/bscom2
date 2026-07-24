// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface I { function approve(address,uint256) external returns(bool); function balanceOf(address) external view returns(uint256); }
interface R { function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[] calldata,address,uint256) external; }
contract HoneypotTester {
    // code: 0=roundtrip OK(>=50% back), 1=buy reverted, 2=buy gave 0, 3=sell reverted, 4=<50% back, 5=approve reverted
    function run(address usdt, address tok, address router, uint256 cap) external returns (uint8 code, uint256 bought, uint256 back) {
        try I(usdt).approve(router, type(uint256).max) {} catch { return (5,0,0); }
        address[] memory p = new address[](2); p[0]=usdt; p[1]=tok;
        try R(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(cap,0,p,address(this),block.timestamp+300) {}
        catch { return (1,0,0); }
        bought = I(tok).balanceOf(address(this));
        if (bought == 0) return (2,0,0);
        try I(tok).approve(router, type(uint256).max) {} catch { return (5,bought,0); }
        address[] memory s = new address[](2); s[0]=tok; s[1]=usdt;
        try R(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(bought,0,s,address(this),block.timestamp+300) {}
        catch { return (3,bought,0); }
        back = I(usdt).balanceOf(address(this));
        code = back >= cap/2 ? 0 : 4;
    }
}
