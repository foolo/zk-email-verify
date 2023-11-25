pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "../TwitterEmailHandler.sol";
import "../Groth16VerifierTwitter.sol";

contract TwitterUtilsTest is Test {
    using StringUtils for *;

    address constant VM_ADDR = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D; // Hardcoded address of the VM from foundry

    Verifier proofVerifier;
    DKIMRegistry dkimRegistry;
    VerifiedTwitterEmail testVerifier;

    uint16 public constant packSize = 7;

    function setUp() public {
        proofVerifier = new Verifier();
        dkimRegistry = new DKIMRegistry();

        dkimRegistry.setDKIMPublicKeyHash(
            "x.com",
            bytes32(uint256(5857406240302475676709141738935898448223932090884766940073913110146444539372))
        );
        testVerifier = new VerifiedTwitterEmail(proofVerifier, dkimRegistry);
    }

    // function testMint() public {
    //   testVerifier.mint
    // }

    // Should pass (note that there are extra 0 bytes, which are filtered out but should be noted in audits)
    function testUnpack1() public {
        uint256[] memory packedBytes = new uint256[](3);
        packedBytes[0] = 29096824819513600;
        packedBytes[1] = 0;
        packedBytes[2] = 0;

        // This is 0x797573685f670000000000000000000000000000000000000000000000000000
        // packSize = 7
        string memory byteList = StringUtils.convertPackedBytesToString(
            packedBytes,
            15,
            packSize
        );
        // This is 0x797573685f67, since strings are internally arbitrary length arrays
        string memory intended_value = "yush_g";

        // We need to cast both to bytes32, which works since usernames can be at most 15, alphanumeric + '_' characters
        // Note that this may not generalize to non-ascii characters.
        // Weird characters are allowed in email addresses, see https://en.wikipedia.org/wiki/Email_address#Local-part
        // See https://stackoverflow.com/a/2049510/3977093 -- you can even have international characters with RFC 6532
        // Our regex should just disallow most of these emails, but they may end up taking more than two bytes
        // ASCII should fit in 2 bytes but emails may not be ASCII
        assertEq(bytes32(bytes(byteList)), bytes32(bytes(intended_value)));
        assertEq(byteList, intended_value);
        console.logString(byteList);
    }

    function testUnpack2() public {
        uint256[] memory packedBytes = new uint256[](3);
        packedBytes[0] = 28557011619965818;
        packedBytes[1] = 1818845549;
        packedBytes[2] = 0;
        string memory byteList = StringUtils.convertPackedBytesToString(
            packedBytes,
            15,
            packSize
        );
        string memory intended_value = "zktestemail";
        assertEq(bytes32(bytes(byteList)), bytes32(bytes(intended_value)));
        console.logString(byteList);
    }

    // Should pass (note that there are extra 0 bytes, which are filtered out but should be noted in audits)
    function testVerifyTestEmail() public {
        uint256[5] memory publicSignals;
        publicSignals[
            0
        ] = 5857406240302475676709141738935898448223932090884766940073913110146444539372;
        publicSignals[1] = 28557011619965818;
        publicSignals[2] = 1818845549;
        publicSignals[3] = 0;
        publicSignals[4] = 0;

        uint256[2] memory proof_a = [
            1111111111111111111111111111111222222222222222222222222222222333333333333333,
            11111111111111111111114444444444444444444446666666666666666666666666666666666
        ];
        // Note: you need to swap the order of the two elements in each subarray
        uint256[2][2] memory proof_b = [
            [
                8888888888888888888888883333333333333333333333333322222222222222222222222222,
                8888888888888888888888883333333333333333333333333322111111111111111111111111
            ],
            [
                1111111111155555555555555555555555555555555555555555555555555555555555555555,
                11111111111111111111111115555556666666666666666663333333333333333333333333333
            ]
        ];
        uint256[2] memory proof_c = [
            11111111111111111111111111111111111111199999999999999999999999999999999999999,
            11111111111111111111111111111111777777777777777777777777777777777777777777777
        ];

        uint256[8] memory proof = [
            proof_a[0],
            proof_a[1],
            proof_b[0][0],
            proof_b[0][1],
            proof_b[1][0],
            proof_b[1][1],
            proof_c[0],
            proof_c[1]
        ];

        // Test proof verification
        bool verified = proofVerifier.verifyProof(
            proof_a,
            proof_b,
            proof_c,
            publicSignals
        );
        assertEq(verified, true);

        // Test mint after spoofing msg.sender
        Vm vm = Vm(VM_ADDR);
        vm.startPrank(0x0000000000000000000000000000000000000001);
        testVerifier.mint(proof, publicSignals);
        vm.stopPrank();
    }


    // Should pass (note that there are extra 0 bytes, which are filtered out but should be noted in audits)
    function testVerifyYushEmail() public {
        uint256[5] memory publicSignals;
        publicSignals[
            0
        ] = 5857406240302475676709141738935898448223932090884766940073913110146444539372; // DKIM hash
        publicSignals[1] = 28557011619965818;
        publicSignals[2] = 1818845549;
        publicSignals[3] = 0;
        publicSignals[4] = 706787187238086675321187262313978339498517045894; // Wallet address

        // TODO switch order
        uint256[2] memory proof_a = [
            1111111111111111111144444444444444442222222222222222211199999999999999999999,
            5555555555555555555552222222222222222225555555555555555555222222222222222255
        ];
        // Note: you need to swap the order of the two elements in each subarray
        uint256[2][2] memory proof_b = [
            [
                3333333333333333333333333333333333333333333333333333333333333333333333333333,
                1111111111111111111111111111111111111111111111111111111111111111111111111111
            ],
            [
                12312312312312312312312322222222222222222222222222222222222222132312312312313,
                9834798379879879879879879879879879555555555555555555555555555555555555555598
            ]
        ];
        uint256[2] memory proof_c = [
            1244444444443333333333333333333888888888888888822222222222222277777777777777,
            5555555555555555222222222222222226666666666666666222222222222225555555555555
        ];

        uint256[8] memory proof = [
            proof_a[0],
            proof_a[1],
            proof_b[0][0],
            proof_b[0][1],
            proof_b[1][0],
            proof_b[1][1],
            proof_c[0],
            proof_c[1]
        ];

        // Test proof verification
        bool verified = proofVerifier.verifyProof(
            proof_a,
            proof_b,
            proof_c,
            publicSignals
        );
        assertEq(verified, true);

        // Test mint after spoofing msg.sender
        Vm vm = Vm(VM_ADDR);
        vm.startPrank(0x7Bcd6F009471e9974a77086a69289D16EaDbA286);
        testVerifier.mint(proof, publicSignals);
        vm.stopPrank();
    }

    function testSVG() public {
        testVerifyYushEmail();
        testVerifyTestEmail();
        string memory svgValue = testVerifier.tokenURI(1);
        console.log(svgValue);
        assert(bytes(svgValue).length > 0);
    }

    function testChainID() public view {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        console.log(chainId);
        // Local chain, xdai, goerli, mainnet
        assert(
            chainId == 31337 || chainId == 100 || chainId == 5 || chainId == 1
        );
    }
}
