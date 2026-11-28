// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module, its self-test: every primitive
// against its standard's published answers (the cryptography library's checks and vectors, carried forward,
// with RFC 8439's ChaCha20 and the XChaCha draft's HChaCha20 added), the key set in the cryptography library's
// formats, then the seal's own records: key records, sealed records and signature records, each
// made and read back, and every refusal (a wrong password or key, every byte changed, a record
// moved, a forged commitment). The archive's checks of locks are the archive class's
// (stratazip.cpp, selarc); these need no archive.

#include <cstdio>
#include "seal.h"
#include "sealprim.h"
#include "mldsa_acvp.h"
#include "mldsa.h"

#include <QByteArray>

#include <array>
#include <cstring>
#include <random>

using namespace stratazip::selprm;

namespace {

// NIST ACVP-Server, gen-val/json-files: ML-KEM-keyGen-FIPS203 tcId 26, ML-KEM-encapDecap-FIPS203 tcId 26 (encapsulation) and tcId 88 (decapsulation, modified ciphertext). Long values are given by their SHA3-256.
const char kgd[] =
    "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0";
const char kgz[] =
    "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";
const char kgek3[] =
    "81e66ef5a7a221619f6a64039cc369843e10df5c859f6959cc3fd8e5272330fd";
const char kgdk3[] =
    "be81068c104cd6cf8efd800b294f4a15bb8a8050993fd54a2cc428841ef6ca44";
const char enek[] =
    "9c6839354086919bc7b8a547ff18b523075fd1706856400952489e4cd13ed8b17a817a3076e0947b860ec9558bd9d3c94df5418a7a7301763999c09996715ce3"
    "2aacfef767a44969925949cc9b8120cb78953bcf6fb8282427cb3f4cbbc50ab23274493a8ba7e5c09088160fda731b55980867912bac53125b27073bb502afac"
    "5e74973e0f3601dc50ce08cc7f3fa44ce331a43f9673be745295e693077264a8e238f0a912c0a59c44d561e2a8bd831541fe869b3110b051100db3517f87510e"
    "cad8651ce4998bb648002ba41a5351fa2a4ed94a58cb707214a59f8876176cf82fceb99364971c7c0896e8b62c0544463ff101983c2045981ccd9173eb33ba18"
    "483ed915bd11ea950db3a8787c105263242e3a64c748b8b1a5947880c5bf3896e08b4b9916a39fd70c2ff8bd041a2b18e251d16a276e38100a613ea96a86cb36"
    "52dcc83f2d31cd9f8b79e42541a66752d191436cf5b5d8350ee7835cdb122855392c1da5c33fda12ad1028f2806861a2ab9c63785fd11e220346322c250936ab"
    "819254734a8dc9241971ac90cda6696adb90d1e327dc977841aba38324c8fb2092784942003a0808e5546d034592f03bacc19e3138c9070ccea80a933d536c49"
    "e4771091af8a70207d474574c64b9f1c8e47224174061117e98c18897a7b1b3c4478c6558c321a89a84b6c508947cb61c89204fbca43bcaa1d688f768b02e50b"
    "abebf0c5fb8962b2355973c4193fa92e0ce4b9f8473e154828c986bf63e1cd985c6f0462c9b4374594d226c5e99b8a844978db8dd2839e27138aacf75e917635"
    "cec4b407a54f184c22f62981b9f4552fb334ff2b7ff68b470fd61b993c32581cc0f39881a5a6a769a60297f4b0579acbf52a8abb143885886245ca2636e20498"
    "959e4f2857ab96706e6409c4164ba88c7193e568e4446120215a6d8499c6b4bc559628a9f481c7db51e2e10df1f4339a647b4ccc0405b79f70a90ca9a8ad0778"
    "9222ba6e66c3aff42b61baa637af15126c88b2e210a7cad9cb08cbb5123a7f9bb4ad63daaea6b43f9aaba561212823cb898a676c967b2d64f4b6333439f8993b"
    "d7b19687248926e077a9700431a59157b9668ee022b6d31343f15c08f14488877dfb30a552c06f96a16f354b9a3f19090b32a043b43256ba5b1088b56a412558"
    "8c8746d4099ea21c4f33ad8c5c7c32286dee2ca76fc2651d57aee9d847824ac609b5bfd5c87316c2afe0e153d6326af89987ecb70cf0a0a77fa000e0e0acc268"
    "5e2317429c3a7513f42873cb98f669703ae9146919226db58d6c2b93b6f50c7cdab677b505945a0f2523886c1b82a6a7cc7eba9251096d88360d7ef6473acbcd"
    "359a0d20414b95c209b2413b1483a3a061386377b28e3896bcd8c5e2692681cc803e1694efb6ce353082ffca4079ea9bb7b2025bcb68990466ed2803ab11516d"
    "80325dc4cde3da9e020653e084c45f837c88711df3aa6075741c1283121c8b1c691013969a62b2563e556206cf0810848691c7c408d018617a7300ad943e189a"
    "9b44512ef13b669831392f1329e2ac7c623aa044223079139b7f1c213e93682ed86165468377d40884310163a5539f27745e667adf506896ba933b002e4d50b2"
    "497ecff09d0bbca4f7e6f9db9e10c643d23701bd6385e163cf71c1e919a6e20a";
const char enm[] =
    "4e77596168711e913965d8175ac3bd76aab08b7f9385a02ae883cf6c6e17dd81";
const char enk[] =
    "79d74f6c6c2d916bec47bd828fd9b67295a37f54927fab1263c0d122f1c6f1ed";
const char enc3[] =
    "684da17d93e27520cb78ae6169c020d73ef770e6fa89589cc7d653a76a8b1751";
const char dedk[] =
    "5de17b5a596d15390d5695541cb03fae4073e601c7557894ab341fc31982bba0c92e04badd2a826fdc166e72af2838703fe94f87bab64cd971879b6bb8c84a52"
    "c318834c46ae1028cb839fd912773714c651dbadd69a7323e1193059bd4799b14f5cc2ca92219780b3befab65c91b637023b4baa4a63a37d83240393442bb938"
    "6b625a977a5388abb435fb3453e34633a0b803ec28be691c258fe610364b89557c7809357a4c691925ac7d4bd2621f76a07a4b26b3b45a109957d6e236e83592"
    "71f8b4fc054af05158ed6026140543f2d905cc144c3436c966e92e89aa24885c044eca3610921cb1a508e71b2a3f979e0a33c1edb61c2303057842c937453904"
    "c80f4542bf5db886636c8bc392cba8b74afd210b3d3400b7257ea2c2ab03d577c95170d5c7771c54b63f9c6030cb6f02f9516502c478002af1bac2e11b58ec20"
    "09fb085aa8b48c51d4b13375679e7742cb97548b1b8861216e3b739146487405466ccbe1a3ebeb9c6553013cc86ea0fb2cdfe8bb93e38e66b762af97a98ad17b"
    "6f6b1afa935a50bc3e7154229904578fb90d07030ea8716a1af9c787f789d4b2174673131021092a84145d183421ecca36142f4316614c2001bb33ce044c257e"
    "b592b3c57fa7cb7a3e1ac24da08c15a5a0af31900fb2147bd83da4d58b6aa5a109608d53b0a86aa13147435a6fdbad926bb65b83b0df6c432af258f2ac57abb6"
    "3dd5e6c272c50e5d6ac34fba51573245d3a06a1d593fae29240883883a5c5b25058b99f49ca6894e9ac225bf44213537204e824c46f9704b89c3c16a52bb1337"
    "81583317968010c86758c5bf7c190c34b8b7331b8242c84cc96278ae586f8472225e795663b379a93c4696407c00504c810c5fc499a98ba67c0ad6718ba32d40"
    "49713b65147ab1192fb46a2ea7023423aeb6526a80585f551610abd45726864e0af9482f498822778471cb895d1cb1aaa144409873b1eccaecf65a5f5298cab6"
    "85caa0a193584943dcbaa84c255df35ce752630a110a988536c8e02ff0554b5725221ef98614e1bdab923bf222567882869bc819ad470145589d3d749372333b"
    "a5977e2664c56c729e7005b4500544184652d2e1653f813c4829c8787a6e63aab5ee171c18ba4b0c5b3994da4af6c5399c71c910811bdbf48d0267737cf6a791"
    "7b80d6c76aea1c091c943d1dfb1b6f280414d93898e759717509770b215aeb819dd4b1c425cde0259791129f090ab15d81488adc92bd8707edf3c1ebe228cc01"
    "c8d2dbc7c7024b96b2125b965af626aaabfcb7ec2c1a33487c8bd3745fe49c7869172e1b6a8d92632d712b56886732e480d4100a36d8b8b56107a26c8cf6f5a0"
    "7d51b9ba54a52c9a40ad4c31eb687acd445d580107b6948119e555c0c357a8e0bbb8c62404c46d3b232c8f0a40af3b7a05b8bb71f04ed5eabec380b75bbb4d26"
    "2ba1da07c11a958f04cb6483b4737462c2a9a346761c22888a99233511c31a0fb1cb7c97d6a3fbe78addb6c8df1575d7293e98d3cba1dab3d393a55f3c73a38b"
    "8ccd6bcc42b31274cbb7c46acc8c56a85e58bd5f49b736423bf9a050f4e5cb6d395f499624046011c3b02e7b98a02e9b6fb561298da8883ec2b2de4a2db0aa93"
    "8c6a9c67a137342bba5a1a7191c17411a649e9b9b47f0c3522264c38f66437438c7b75588787bb03b1c073d668b355239e7502840a7183e9c9e49270a1339941"
    "e17733792d4beabe4dc50a2351a3f1aa11323490511bb00371ad9ae72f4589bd5da732ea52892d8a6f98386e67d3b8cc97af61ca9c15c23a97725ba5c8204527"
    "86cccc34751ccf13f72d2af1a0b7f81f698b5b8ff9a2cd5b076d23a6219ca9457338236c743360cf9e8a19dc83cea7f5be17d084835b8ed700cb0a1c9d7cdcc4"
    "f5526b63c34d623749c9992a19957aa5c0894a623821acc3cca0b9410c0f8cd59757c53899c1a0d327733c0b7f1961b0c74b9ddbac662c166c5f787141f81d19"
    "b907e8a042fd2b01794b8968486e69fa02fd136ded53c6a633899a368442acca49f66eb4766a16247128c38b7e0287d3bbb1594324d6b1c9c80a368c5903a008"
    "0ebdf6c72a27aa10286859382349d39f9c91acb06800152b9edc9cb965a5ac9e7c8a6f1439b18b2fe1942c9b9943ee830a7adb5eec6501f593361e0c95625b74"
    "97a02a30173faf47c74dcc4e99a436864a5110130b2b6c8007015d1ebb15c232bf91ab19dca7711ed97d98637e051a1e686b21f9eaac8652129b69102eb4a4ca"
    "0906ec9489daea054dbb7afbcca5c4c8c511b753e8847224f95a3fc8b12a65614c8c04ef58a56ebc1170a48886f04e24976411e88e44220f1ce13bba414775e4"
    "63e9826572b6a879625b348aabc7a6445e95052c77b13db39f1c719ff597b688a73a23d7912c3ac06b6b8324153e3b2b4c63b361be77267573c5f2a88477a259"
    "71778151a96b1c8c3033d0a43c7378736a2caf73143e3cc348fa239f74a3ddd51cf10acfd78735f1136576c97718d7822635b2bdb159ca2701493489f4fc8ba2"
    "7a5c891abf9d73316c7583248956bffcbb790c3519b010018887fc891d98b33aa62582f0d9cd790626afe183269834c742589497155c5545706c0e397b25909b"
    "18ec3c734b824a6095c2b0843a0a165a88729dfc1bc0319797946ba4e3d85e3d20b1e0cb1eab0547ea30c41056835d3c78a7487f6cb774b9d68f7e613f566871"
    "7bf81498617fcbc730f93377656c9a6033347a4ac0749374ba8807e2440758788cf7056f9480936524608704281499a7b04a46fb595c7bd274568b2c70074420"
    "59bff1851795739568334b2dd3517092632d839961f7a2b23b33cc3831217ab6ded0a413118f369b859507ad1eea019d0c82b1341146b58da521535e55904ac7"
    "145bdc7174c82e5bc877dafa993049ceb9d3ac2a81955c5508cedc1331a28bce2827d127a0109a8512fb78bbac2cfeb31a997a091af60414e637597a38246842"
    "13588386055e64a515da5a5c670a81ac972b2f6cc6e82abff1150bf5901fb0f0186f4ab76ee22a3638a0018c8dfa04777357cdc5c667f0f81e1b6a833e67529c"
    "71854bb32d206b39ab3247db61ac2874344d82a8b818178c8589e5419d558414f3fc53b72823357b0b50138d4c80864db3685944732793467f5989f283589178"
    "994aa63b01a68d2ac8cad2f3b3b62c6f5aa7ad4bc2cabaf306dc37cf46428855f23e6988bd2b21349bc1223a819b54473f397c60f6d4777dd1775e3685ead34b"
    "9a162c0625e876dd243debe6b4d6e1a2829abdf70d120c02c34ce876bec17a724317826d17b0b62b5fd188ab789f3e51172428146a05978d22a98642c3ae4003"
    "571a76168392f72fdfb415510f1125c8bf5f5474a27277b71147c9eba71cab9a";
const char dect[] =
    "c4ff0334ee9e01b04014ca57fd3c1f02f6b4fa91490864fe7be3f3601a0ba87791c73ac5a54097fbf4c21a8c5051a5ea8a32150ac7f4dda59280afcf938b6b5e"
    "7a023235c2aa330cdc0a976c5387bf1e92ae9c9d195436904cc9a4f9d7f2fc90317957b9744a6f4278bc48094bfe26c9aa09cafe0d7d8e1fc04416ad27c37e95"
    "0dbcfb696a6f9bb96325f99d7143770e9f45c1e011bf6b9e550f28e8dc151d561a0b3048b1fcc07b2ebe0790a589a16c7bc75fff4cdc90dfb571bcd0dce00dca"
    "e5495b54f66881548a0fdbd1b90e529ad7fa2921874088c96af8fb99c7f621560ecc6691c69a8d02322d671f67d67c663bba9b0ba451798eefb2c148324961c1"
    "45737325731fd6b8383137400409478737e792f072a0ed2e7f43768cd132eccdbbb393ac435934d1fb8adc17551d3c2a1d9db4c205888f58b630c80f2c98eda0"
    "0b7e6f2e3e0c6d4124866964c98bd086daa126215a98293957c6ad68724b2bd0e4cf55a45fec8c03622b3b358d3fb45b619d3286e5d7bc429d9e06342b384857"
    "67bca1898691208b4786a3258be2e9a6bb5ab2ec7b8cf3752bdc0e4e6767f5e46d7221bc8e8bd69f36f1b14c6f4b15272b780c18fa118aac52a390a28e886277"
    "3789113371cdcefdc4b45547be5f26a9bc3151fcb87fd9c50a99cf4338562023a15b13860aff9daac05a2409834c0b68ee3a635261053546407e8cfa75046f55"
    "978ad9b2afecc8a79d35b8349e0a33f90f23ad6648761f400228d83fa22366f0d2613814b505c29069fa8f3cb0b6143de9baf4e9dfdaf2b606cc577d06d2b327"
    "94c41199f06517a475313fc9f9d433099fc7b310c99fbaa132082b05c332b00cb3871d2dcc60fa33f8956074b87a2c1e4ea6609670f0e81dfd75ad8b68ddc912"
    "17127930659c6a29e07a9e5102908e218f101d5feec11f9c3e759e381e74379f648c29f7033bb58afca6590f0f84fee54510a78ed12528c960a93a691ff1667e"
    "319d641f97c16cf1d45399daa03bd5ea15c806f19d4e759d641fe1071449cf4e13c70d1c58d2265d53eb07a5cbe012cf9fd6768221d27e69d727af657e215159"
    "3207909d1ca11a8c96e2ccca095c3bb811c87ebe14e995ffb7f763b47ed0eeb604a0cccd74ab0c29dfcfe3b4620f5e8eb3ffd74ae9bc7a6b48ae4651d430871d"
    "4651e64c2b2fbe5701e2c64e20f5279157b55e3e9d166caf03fbaef2472e960d1a0160a92f42d1834b5d493e52e9d0897dbfaa373208eadc16fcff3ce8ae4022"
    "6a469abc60b9a1b67244c5aeebf1abaecfe9dd9f9c1183f125d3b6172afb2c6cc29125a9f8c3a8b31fa880fc447719c5e58c50c4199e17ef9a061eab483bbfe3"
    "70f277b9ca09b3e3e6ff39e97ae392c0ef0b623f9be056db4d21e7704b5127d42f7fea27fea8f9186044e49d2c2d51758329c8cab35b00df58c91a5e2f6fc6fa"
    "afcd2037ba982052f02f204508c9b2c7d6ef53955372010fb3505c8c8e27677ef37ef07bd619342aa3fa6de31eb7e6089ef5f0bf9c4aeb024f9161897906c643";
const char dek[] =
    "2cfb695710a6c4377f46c20c13480aef7ac56030d47a0ab5af07ddd6062c28f4";

const size_t pwdway = 99;                              // a password way in, bytes (seal.h)

QByteArray hx(const char* s) { return QByteArray::fromHex(QByteArray(s)); }
const quint8* u8(const QByteArray& b) { return reinterpret_cast<const quint8*>(b.constData()); }
QByteArray qb(const quint8* p, size_t n) { return QByteArray(reinterpret_cast<const char*>(p), qsizetype(n)); }

} // namespace

bool
stratazip::sel::slftst(QStringList& log) {
    int bad = 0;
    auto chk = [&](bool c, const QString& n) { log << (c ? "pass  " : "FAIL  ") + n; if (!c) ++bad; };
    auto s3 = [](const QByteArray& b) { quint8 d[32]; s3256(d, u8(b), size_t(b.size())); return qb(d, 32); };

    // ---- The primitives, against their standards' published answers ----
    {
        quint8 d[64];
        b2bhsh(d, 64, reinterpret_cast<const quint8*>("abc"), 3);
        chk(qb(d, 64) == hx("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
            "seal: BLAKE2b-512 of \"abc\" (RFC 7693, appendix A)");
    }
    {
        QByteArray k(32, 0);
        for (int i = 0; i < 32; ++i) k[i] = char(i);
        const QByteArray n = hx("000000000000004a00000000"), m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        QByteArray c(m.size(), 0);
        cc20xor(u8(k), u8(n), 1, u8(m), reinterpret_cast<quint8*>(c.data()), size_t(m.size()));
        chk(c == hx("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"),
            "seal: ChaCha20 encryption (RFC 8439, section 2.4.2)");
        quint8 sk[32];
        hcc(u8(k), u8(hx("000000090000004a0000000031415927")), sk);
        chk(qb(sk, 32) == hx("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"), "seal: HChaCha20 (draft-irtf-cfrg-xchacha, section 2.2.1)");
    }
    {
        const QByteArray k = hx("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"), m = "Cryptographic Forum Research Group";
        quint8 t[16];
        p13mac(u8(k), u8(m), size_t(m.size()), t);
        chk(qb(t, 16) == hx("a8061dc1305136c6c22b8baf0c0127a9"), "seal: Poly1305 (RFC 8439, section 2.5.2)");
    }
    {
        QByteArray k(32, 0), n(24, 0);
        for (int i = 0; i < 32; ++i) k[i] = char(0x80 + i);
        for (int i = 0; i < 24; ++i) n[i] = char(0x40 + i);
        const QByteArray ad = hx("50515253c0c1c2c3c4c5c6c7"), m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        QByteArray c(m.size() + 16, 0), o(m.size(), 0);
        aedenc(u8(k), u8(n), u8(ad), 12, u8(m), size_t(m.size()), reinterpret_cast<quint8*>(c.data()));
        const bool ok = c == hx("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")
                     && aeddec(u8(k), u8(n), u8(ad), 12, u8(c), size_t(c.size()), reinterpret_cast<quint8*>(o.data())) && o == m;
        c[7] = char(c[7] ^ 1);
        chk(ok && !aeddec(u8(k), u8(n), u8(ad), 12, u8(c), size_t(c.size()), reinterpret_cast<quint8*>(o.data())),
            "seal: XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha, A.3.1), and a changed byte refused");
    }
    {
        quint8 k[32], n[12], m[4096], a[4096], b[4096];
        rnd(k, 32); rnd(n, 12); rnd(m, sizeof m);
        cc20xor(k, n, 7, m, a, sizeof m);
        for (size_t i = 0; i < sizeof m; i += 64) cc20xor(k, n, quint32(7 + i / 64), m + i, b + i, 64);
        chk(std::memcmp(a, b, sizeof a) == 0, "seal: ChaCha20's eight-block vector path agrees with the one-block path");
    }
    {
        quint8 pw[32], salt[16], sec[8], ad[12], o[32];
        std::memset(pw, 1, 32); std::memset(salt, 2, 16); std::memset(sec, 3, 8); std::memset(ad, 4, 12);
        chk(a2id(o, 32, pw, 32, salt, 16, 3, 32, 4, sec, 8, ad, 12) && qb(o, 32) == hx("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
            "seal: Argon2id, four lanes with secret and associated data (RFC 9106, section 5.3)");
    }
    {
        quint8 d[64];
        s512hsh(d, reinterpret_cast<const quint8*>("abc"), 3);
        chk(qb(d, 64) == hx("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            "seal: SHA-512 of \"abc\" (FIPS 180-4)");
        quint8 a[32], b[64], c[32];
        s3256(a, reinterpret_cast<const quint8*>("abc"), 3);
        s3512(b, reinterpret_cast<const quint8*>("abc"), 3);
        shk256(c, 32, nullptr, 0);
        chk(qb(a, 32) == hx("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
            && qb(b, 64) == hx("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
            && qb(c, 32) == hx("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            "seal: SHA3-256 and SHA3-512 of \"abc\", SHAKE256 of nothing (FIPS 202)");
    }
    {
        const QByteArray ask = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
                         bsk = hx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        quint8 ap[32], bp[32], s1[32], s2[32];
        x255b(ap, u8(ask)); x255b(bp, u8(bsk));
        const bool k1 = x255(s1, u8(ask), bp), k2 = x255(s2, u8(bsk), ap);
        const quint8 zero[32] = {};
        quint8 sz[32];
        chk(qb(ap, 32) == hx("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
            && qb(bp, 32) == hx("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            && k1 && k2 && qb(s1, 32) == hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742") && qb(s1, 32) == qb(s2, 32)
            && !x255(sz, u8(ask), zero),
            "seal: X25519, both public keys and the shared secret (RFC 7748, section 6.1); a small-order key refused");
    }
    {
        const QByteArray seed = hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        quint8 pk[32], sg[64];
        e255pub(pk, u8(seed));
        e255sig(sg, nullptr, 0, u8(seed), false);
        const bool t1 = qb(pk, 32) == hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                     && qb(sg, 64) == hx("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
                     && e255ver(sg, nullptr, 0, pk, false);
        const QByteArray ps = hx("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        quint8 pp[32], h[64], ss[64];
        e255pub(pp, u8(ps));
        s512hsh(h, reinterpret_cast<const quint8*>("abc"), 3);
        e255sig(ss, h, 64, u8(ps), true);
        const bool t2 = qb(pp, 32) == hx("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
                     && qb(ss, 64) == hx("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
                     && e255ver(ss, h, 64, pp, true);
        ss[10] ^= 1;
        chk(t1 && t2 && !e255ver(ss, h, 64, pp, true), "seal: Ed25519 and Ed25519ph (RFC 8032, sections 7.1 test 1 and 7.3); a changed signature refused");
    }
    {
        quint8 ek[1184], dk[2400], ct[1088], ss[32];
        mlkkey(ek, dk, u8(hx(kgd)), u8(hx(kgz)));
        const bool kg = s3(qb(ek, 1184)) == hx(kgek3) && s3(qb(dk, 2400)) == hx(kgdk3);
        const QByteArray e = hx(enek);
        const bool en = mlkenc(ct, ss, u8(e), u8(hx(enm))) && qb(ss, 32) == hx(enk) && s3(qb(ct, 1088)) == hx(enc3);
        quint8 s2[32];
        mlkdec(s2, u8(hx(dect)), u8(hx(dedk)));
        const bool de = qb(s2, 32) == hx(dek);
        chk(kg && en && de, "seal: ML-KEM-768, key generation, encapsulation, and decapsulation of a modified ciphertext (NIST ACVP vectors, FIPS 203)");
        QByteArray eb = e; eb[0] = char(0xff); eb[1] = char(eb[1] | 0x0f);
        QByteArray db = qb(dk, 2400); db[2400 - 40] = char(db[2400 - 40] ^ 1);
        chk(!mlkeck(u8(eb)) && mlkeck(u8(e)) && !mlkdck(u8(db)) && mlkdck(dk) && !mlkenc(ct, ss, u8(eb), u8(hx(enm))),
            "seal: ML-KEM-768, the input checks of FIPS 203 (a coefficient of q or more; a wrong H(ek)) refuse");
    }

    // ---- Key sets, in the cryptography library's formats ----
    kys alice, bob;
    chk(kysgen(alice).isEmpty() && kysgen(bob).isEmpty() && alice.pub_.size() == 1248 && alice.pub_ != bob.pub_,
        "seal: key sets, two made, each 1248 public bytes (X25519, Ed25519, ML-KEM-768)");
    {
        // A fixed seed makes fixed keys: the cryptography library made this public key's key id from it.
        quint8 fs[32]; for (int i = 0; i < 32; ++i) fs[i] = quint8(i);
        kys f, a2, b2;
        const bool same = kysfrm(fs, f).isEmpty() && kysfrm(alice.msd_.dat(), a2).isEmpty() && a2.pub_ == alice.pub_
                       && std::memcmp(a2.sec_.dat(), alice.sec_.dat(), alice.sec_.len()) == 0;
        const QString pp = ppr(alice);
        const bool rt = pprred(pp, b2).isEmpty() && b2.pub_ == alice.pub_;
        int caught = 0, tried = 0;
        for (int i = 8; i < pp.size(); i += 5) {
            if (pp[i] == '-') continue;
            QString q = pp; q[i] = q[i] == 'a' ? 'b' : 'a'; ++tried;
            kys x; if (!pprred(q, x).isEmpty()) ++caught;
        }
        chk(same && rt && caught == tried && pp.size() == 8 + 56 + 13 && kidof(f.pub_).toHex() == QByteArray("9044190f22aea85e"),
            QString("seal: the same seed makes the same keys (the cryptography library's for a fixed seed); the paper key round-trips, and %1 of %2 one-letter mistakes are caught").arg(caught).arg(tried));
        QByteArray p;
        chk(pubred(pubtxt(alice.pub_), p).isEmpty() && p == alice.pub_ && !pubred("hcy2pub:abc", p).isEmpty() && !pubred(pubtxt(alice.pub_).left(100), p).isEmpty(),
            "seal: public key text, round trip, and malformed text refused");
        sbf pw("hunter2", 7), wp("hunter3", 7);
        QByteArray fil;
        kys r1, r2;
        const QString se = secfil(alice, pw, fil, kdftst);
        chk(se.isEmpty() && fil.size() == 111 && secred(fil, pw, r1).isEmpty() && r1.pub_ == alice.pub_ && !secred(fil, wp, r2).isEmpty(),
            "seal: secret key file (HCK2, 111 bytes), opened by its password, refused with another");
    }

    // ---- Key records ----
    lid arc, lck;
    lidrnd(arc); lidrnd(lck);
    sbf lk(32);
    rnd(lk.dat(), 32);
    sbf pw("correct horse", 13), wp("correct horsf", 13);
    {
        std::vector<quint8> r;
        krc k;
        sbf got;
        QString why;
        const QString me = krcmak(arc, lck, "finance", lk.dat(), {&pw}, {alice.pub_}, kdftst, r);
        const bool rd = me.isEmpty() && krcget(r.data(), r.size(), k).isEmpty() && k.arc_ == arc && k.lck_ == lck && k.nam_ == "finance" && k.way_.size() == 2;
        const bool p1 = rd && krcopn(k, &pw, {}, got, why) && std::memcmp(got.dat(), lk.dat(), 32) == 0;
        const bool k1 = rd && krcopn(k, nullptr, {&alice}, got, why) && std::memcmp(got.dat(), lk.dat(), 32) == 0;
        const bool no = rd && !krcopn(k, &wp, {&bob}, got, why) && why.contains("wrong");
        chk(rd && p1 && k1 && no, QString("seal: key record (%1 bytes), opened by its password and by its recipient's key; another password and key refused").arg(r.size()));
        // Every byte changed, in a record of each way's kind: refused as it is read, or its way
        // in no longer opens it (a key id changed finds no key; anything else fails the wrap).
        int held = 0, n = 0;
        for (int kind = 1; kind <= 2; ++kind) {
            std::vector<quint8> r1;
            krcmak(arc, lck, "finance", lk.dat(), kind == 1 ? std::vector<const sbf*>{&pw} : std::vector<const sbf*>{},
                   kind == 2 ? std::vector<QByteArray>{alice.pub_} : std::vector<QByteArray>{}, kdftst, r1);
            for (size_t i = 0; i < r1.size(); ++i) {
                std::vector<quint8> q = r1; q[i] ^= 0x01; ++n;
                krc x; sbf g; QString w;
                if (!krcget(q.data(), q.size(), x).isEmpty() || !krcopn(x, &pw, {&alice}, g, w)) ++held;
            }
        }
        chk(held == n, QString("seal: key records, a changed byte at each of their %1 places refused").arg(n));
        // A forged record: its way opens to a second key, under the first key's commitment.
        sbf lk2(32); rnd(lk2.dat(), 32);
        std::vector<quint8> f1;
        krcmak(arc, lck, "finance", lk.dat(), {&pw}, {}, kdftst, f1);
        std::vector<quint8> pre(f1.begin(), f1.end() - std::ptrdiff_t(pwdway + 2));   // the header and the first key's commitment
        std::vector<quint8> fg = pre;
        fg.push_back(1); fg.push_back(0);
        std::vector<quint8> wy = {1, 1, 1, 0, 0, 0, 0, 4, 0, 0, 1};      // Argon2id, 1 pass, 1 MiB, 1 lane
        std::array<quint8, 40> sn; rnd(sn.data(), 40);
        wy.insert(wy.end(), sn.begin(), sn.end());
        quint8 kek[32], wr[48];
        a2id(kek, 32, pw.dat(), pw.len(), sn.data(), 16, 1, 1024, 1);
        std::vector<quint8> ad = pre; ad.insert(ad.end(), wy.begin(), wy.end());
        aedenc(kek, sn.data() + 16, ad.data(), ad.size(), lk2.dat(), 32, wr);
        wy.insert(wy.end(), wr, wr + 48);
        fg.insert(fg.end(), wy.begin(), wy.end());
        krc x; sbf g; QString w;
        chk(krcget(fg.data(), fg.size(), x).isEmpty() && !krcopn(x, &pw, {}, g, w) && w.contains("forged"),
            "seal: a key record whose way opens to a key it is not committed to refused as forged");
    }

    // ---- Sealed records ----
    {
        auto o = opnmak(lck, "finance", lk.dat());
        lid sid; lidrnd(sid);
        QByteArray pay(1000, 0);
        rnd(reinterpret_cast<quint8*>(pay.data()), 1000);
        pay[0] = char(7);
        std::vector<quint8> s;
        const bool mk = o && selput(*o, arc, sid, 3, modsrc, 4321, 18, 0xdeadbeef, u8(pay), size_t(pay.size()), s) && s.size() == size_t(pay.size()) + selovr;
        shd h;
        std::vector<quint8> back;
        //the small header alone, from only its first selpfx + selshd + 16 bytes.
        const bool pk = mk && selhed(*o, arc, sid, 3, modsrc, s.data(), s.size(), h) && h.imod_ == 18 && h.icrc_ == 0xdeadbeef && h.b0_ == 7 && h.raw_ == 4321 && h.len_ == 1000 && h.flg_ == 0;
        const bool op = mk && selget(*o, arc, sid, 3, modsrc, s.data(), s.size(), h, back) && h.imod_ == 18 && h.icrc_ == 0xdeadbeef && h.raw_ == 4321 && qb(back.data(), back.size()) == pay;
        lid a2 = arc, s2 = sid; a2[0] ^= 1; s2[5] ^= 1;
        auto o2 = opnmak(lck, "finance", alice.msd_.dat());
        const bool mv = mk && !selget(*o, a2, sid, 3, modsrc, s.data(), s.size(), h, back)
                           && !selget(*o, arc, s2, 3, modsrc, s.data(), s.size(), h, back)
                           && !selget(*o, arc, sid, 4, modsrc, s.data(), s.size(), h, back)
                           && !selget(*o, arc, sid, 3, modssh, s.data(), s.size(), h, back)
                           && !selget(*o2, arc, sid, 3, modsrc, s.data(), s.size(), h, back)
                           && !selhed(*o, a2, sid, 3, modsrc, s.data(), s.size(), h) && !selhed(*o, arc, sid, 3, modssh, s.data(), s.size(), h)
                           && !selhed(*o2, arc, sid, 3, modsrc, s.data(), s.size(), h);
        int held = 0, hheld = 0, hbytes = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            std::vector<quint8> q = s; q[i] ^= 0x80;
            if (!selget(*o, arc, sid, 3, modsrc, q.data(), q.size(), h, back)) ++held;
            if (i < selpfx + selshd + 16) { ++hbytes; if (!selhed(*o, arc, sid, 3, modsrc, q.data(), q.size(), h)) ++hheld; }
        }
        std::vector<quint8> cut(s.begin(), s.end() - 1);
        chk(mk && pk && op && mv && held == int(s.size()) && hheld == hbytes && !selget(*o, arc, sid, 3, modsrc, cut.data(), cut.size(), h, back)
                && !selhed(*o, arc, sid, 3, modsrc, cut.data(), cut.size(), h),
            QString("seal: sealed record (version 2), %1 bytes over its payload; read back; its small header opened alone; refused in another archive, segment, place, role, "
                    "under another key, cut, and with a byte changed at each of its %2 (the small header alone at each of its %3)").arg(selovr).arg(s.size()).arg(hbytes));
        std::vector<quint8> s1, s2b;
        selput(*o, arc, sid, 3, modsrc, 4321, 18, 0, u8(pay), size_t(pay.size()), s1);
        selput(*o, arc, sid, 3, modsrc, 4321, 18, 0, u8(pay), size_t(pay.size()), s2b);
        chk(s1 != s2b && std::memcmp(s1.data(), s2b.data(), 36) == 0, "seal: the same record sealed twice differs (a random nonce each time)");
    }

    // ---- Signature records ----
    {
        h256 sha{}; for (int i = 0; i < 32; ++i) sha[size_t(i)] = quint8(i * 7);
        std::vector<quint8> r;
        sgr s;
        QString why;
        const bool mk = sgrmak(alice, 123456, sha, r).isEmpty() && sgrget(r.data(), r.size(), s).isEmpty() && s.cov_ == 123456 && s.sha_ == sha;
        const bool ok = mk && sgrver(s, pubof(alice), why);
        const bool other = mk && !sgrver(s, pubof(bob), why) && why.contains("no signature");
        sgr t = s; t.sha_[3] ^= 1;
        sgr u = s; u.cov_ += 1;
        const bool chg = mk && !sgrver(t, pubof(alice), why) && why.contains("BAD") && !sgrver(u, pubof(alice), why);
        chk(mk && ok && other && chg, QString("seal: signature record (%1 bytes, Ed25519ph and ML-DSA-65), verified; another key's, a changed hash and a changed length refused").arg(r.size()));
    }

    return bad == 0;
}

// ==============================================================================
// ML-DSA-65 in the seal
// ==============================================================================

namespace {

// Golden values, made in a second machine (g++ 13.3) and checked when made against an independent
// implementation (dilithium-py 1.5.1, for the ML-DSA-65 half): any machine must make or accept them.
// The key set of the master seed 20 21 .. 3f: its ML-DSA-65 public key's SHA3-256, the same as
// the cryptography library's, so the two components make one key from one seed.
const char gold9ks[] = "6068587049d94e1e08ef6d4498b69fda98cebe9f795330b42c6cad555539e0f3";
// Its signature record of covers 123456 and the SHA-256 i * 7, ML-DSA-65 deterministic: the record's SHA3-256
// (its ML-DSA-65 signature byte for byte dilithium-py's).
const char gold9dt[] = "1f8eed92f1fb71e0562e32354453fcc070176ac531068dbcb839859b116f63d4";   //version 2 (the first copy's place)
// The same, hedged, made in a second machine: the record itself (14 November: version 2).
const char gold9hd[] =
    "485349470240e201000000000000070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d90201f8"
    "af2d6daf45971a4000334ea3364b619dd91ce45896b920c3d914d14d3f239cd67a6ca14d92b0a247c20e57eedf4240d7"
    "b0e3e6117ca8f84e9121000e70928c3b07a3ae02011e5b090402f8af2d6daf45971aed0c086a7c30aa7420be33594963"
    "8cf55bbe9e5048af73171cdcd1b8161163a7a8973e5ef267e4dbb25b5a9b597eb1bf0929d285e4ff9c48055c4c664de8"
    "8fb75279a3a612965900691eac63860ae8bd5b3b41fc3a16cba8ec2e0a850707fde84c1730ed41883f22dbab488f0e7a"
    "86b3200dae751ccc4d5b21413a59cf8468bad235bc070072bf1fbca3e1c43a44ec699512a9a5856192133b832517033f"
    "325b90ab55a56c23f5b95a70792439995c0dbb3af4705e706a7f4006e1c60cf3c09271fe426ade02ff1ddf6eb43dc3c9"
    "52392425078d1f7e192e7c5db37e06b926c7a623d056b027e2db9c22f6aa0149a085b74b0ca7f6bb9273d05298fd9f62"
    "80855b844cb2302bc048690eede6d8a3f992c156c48ec618e1834166642c1affa3a1f436fd102503ce1d76f88d9a0b54"
    "5861cd943c1a8a1d9ccdcf25d6479706f4c0f1288626c5fb3a92e15e4241056e03d508ea86d15e4d2c689fd0b47e66b4"
    "2019eab0b527ebc9c9b41176bc33109b91921b5e8987216abc865a98f24231fdc4215b4ab81215a11099eebeba7b9aee"
    "024d8f435d99fd94665e6d748b01e837b926bb55caced8cd259d17a5ab29064028408f8ff04ff16d6b46ce1b5c3c3993"
    "04d2f8d5292960125ba236d83504d75728768be8271c04bad2b650b253358e1f95239a2ad8800d84617114d6f4890b67"
    "dc1988f79fe44e80d2ca549ea65d8d4dfc56ca50ae3ba822e648888d44028d0a48d296da9571b1e2acee2e8a2a5bf489"
    "1b1401a22e9fd1f2c32ec796c29d9495cba7617835ed7b434d241d30e4488430b4c2f5a8712778c03c1f31040613c0c3"
    "3ab74e5453bb9c4e876054c317d9683b43aa4280bfb6b35b6605566a5312295c032a9da0d6abf40c0e34a914ff5e99cd"
    "0e179afd97c16c9c6679b09b777fbc39443e893e5562b220e6231461880ac2992a5695b0ece5d99549fc5583bd9441a3"
    "1f25023cea7574cf669fe6f6f3765107a11b78cdab02254dec8ab2d3cc600a70f9cd3b7d1fdcb121926276fd65396d67"
    "33906e1995b9f0759ce502379ef8334a566377b358466a29a49e8648a3a92cac95a57260dc37016462d33a40def5c90a"
    "ca20b7298c94b3555387b929e1918f8539ad4b8ff190366cdae63cb899b9d9a0a7b8aa7fc112dbf219e7908e2c18cd96"
    "c2eed1564e2f60fbf32d6b488f79a73e0b6968570225cefe135162bbc0e489a96fdda6db629fce8d652f325136151d28"
    "488c393651a3b9aefeec9cd86f02a3cd083a3eff781538e17bd0347bef326b4c089e2bf14f1f4ec80e21f268be4326b9"
    "a732243d3e61178f0d943610028bff3992c92fca1a5dbaeb1bbc14b7ec208d0104d1761fafd3c96f27661812cd62c8e8"
    "34a26568fc119ef1391888a594e2ce1f5f0c0bc5c3e93a4fba1c57c0d4f6681c92c669b519f9c588e0017e04e6450d66"
    "a44eb5f769c9d0c66144057a3042256c63358297d596b812aa78980ad63a21a3b1cf52989347037b4cd1fe680cd1081e"
    "07b1b3188f1cdf226e92777ba0b6e6c179fd3e46e6c80b4a3c83b6736f46c1ae7773e27fc530f52c164df9248e5d5f87"
    "fe7c9b01d0cb3a6f75068d8cdaad61e72dd954ba1674750765eed209e9ac8a4bbd082ab6090cbd2bbac48e71e7919a95"
    "a618cf0e09437a64f079f0e730170ab7276375bec4ddd06ef315e6f8f278d693372dc2171d0552c924e87f9e7e2c5e54"
    "73caacd38a595dfec92b875d390ef16910b7d5ad61b045f27ec968e6b89083ea4de37d410149686bd63793988e9a6add"
    "fa734d2d686f3cfbcb094285bf35d577d125a456729063c6a44b190c5156c2dfa8aa297e542feba4d038ed3456d0ceb8"
    "9377a08c9eef4455984be11170f973b913eca3b76cc57cc3c045166d0169daa579f15f745636a190ddba95e73677fe3b"
    "bd57883f66df3583111f48b053046092da4090850b57abc2969a90d8a8ea2270fa6ad452cef17fa889ea9287d67bee12"
    "ff30afb20eacbdef92890723ad1aaa617dd76a6a04149de4cf71c0c7478c89b91d591f2b97ff47b78fc31f0dcf46fd01"
    "c7c2f4d9da9da86e36998c135b98b541b0c89f7d7d84ca5c9e73814b65daafda5d380989b6ce9a56d37d8215d24b839f"
    "2aeeb006fbda9f142d7eafe4d66dacb49f214759583252472903e93e26da1710f5c065be52e0c90741b75a4ac399ba17"
    "bdab068780d4704107b04d3631fc6da488e6da5f8291f63d413fbd3ce78ffac1daecba9165ef104a0591d9e3af49304d"
    "f2006bbe99a813faf3d872f77b555057b29c2f80d53244b96bc819963ca828bfb345dc0e5086ecd35d95405f97e168be"
    "20627d866adeb3889fbffd2cbbc1de8e1b03a887990ac5fa37531376458102677eb33d79faa803df400356aa8d88e73f"
    "01953a5d83bf9bde9611c8b9045d5e7e7824b9425525ca44113177e80af28ce1ae363658fd3bb8e3ac862dd621e1766d"
    "4946c9923612097904eb9d1ed9488126abd0b61adc601b76d42b7e4e4957dc6a4a7b0a24bc24652447b080ea7b86e0c2"
    "351792028abbf3147b85215c356c4c2e86bffcadd280f3c81099067312ff3c8d61fb208c43e42cac2e2edd55a87e6784"
    "b7b947424a0aa06737306643743c512a56643dd4ca7321d7ca0690f150c0452ec6a72164079fb8ef5628a33e19763096"
    "d71bfb3a8629827e8ca4f7fa636ec9356ab0dd98a8051052fb78ca667d3bd9b8e822012ec6e1515fa082c68ea72381b6"
    "b14e1d9892d4ec177dbd2cfc8839b27da37f204c38269a856ffcea2824f33ca820f79362636fafdb73e1d36cf8c75daf"
    "26264ab30e8240120792dc9385403759540187662dfcfa255a292edc07ed1d4de9fcbd125104e579a4edd0bb9c3b0af8"
    "17bf947b06d14d1d171fd524a87becccbf2bea5d448d23a564b70c257f17528802f21cf8a6d2ff74472c13bf303d8c01"
    "f4343dc217eec421d54298684fcbae9da23c0582a676fd243dae78b9cdf0f89c5b2f8589933f8eb396a4916699fb04c6"
    "5f0e2bb0004e7f2ecd5d0c940b3bdca18804e08bfba53b4d2ba9923e49fbbd8f23e29c60c3db166bce465c358cf3ad27"
    "a14a5b8e6916f131aaa245c6f567d3fd393475a95c6ce04aac9b90b1e915a2597c59c690d88e002c1bc43e68f666f828"
    "0bf4e07032f53c847a25039a2efb7c07a27919490c27619ee481bc1662996c489961d01763a776fa45bff6dc226d49aa"
    "b16a601a17fb1036004a2ba18c97bdb294f84b8aa0d328fb5e71ae1f1dc10a942b50407a9aaed600a089091e410bbab9"
    "490e1150304d695ba64d82bd993dcc1282cea86038afbd29ac69eb1a83eb1740b4efc4f39fc79bde3f31ef0ea41d66a2"
    "d5778acee73567301cfc8a3101cb89a81bf97f21410d6939283a927a5046c6d399796650fa5efa7b27f5b29e7e2ac448"
    "b5e7aaf27bdefc23376a34b805453e21566a630117360b8b9cfb5679c8cccfa55a828e0f7b6b2b2c0a44a2b0efb3dddb"
    "0dd2dbcf43de04966a92c404e79f8922e7e51d132b9088b6d1ebc93e2c9ea4951467f2e22c7028c373ca319075521a2b"
    "081d129f92385fa80b898509ee00b15f264d5ca6ab50d43d298ca5502cf4ca709c1e7762bbf66953cbb7b2cdee981b8e"
    "b7d1eef8a8bd5bc3a1b3e493a6b4ef8afcb661b8a4e9805c448391a9fc3a28212a58f78d48cb0addd88d09c40dd06467"
    "15db488f84525e8f74b904b31f086a846368d878ee2b329b17b628d77a4acdda1805c3405fd09e078237d952d5d47681"
    "76be316cc953fe3c86a04268932d7adad45b8006e167ea9cb2bda495cfb2829c0b52c5c6d9bafe87a35305f1e3893f36"
    "a0166e27c2210d3de90db9b33b12b96b5ed0ab75ca8513192ce9c912c8b2ae918214a714e00c5df7eb4e8ada4cf5695a"
    "39e73e8fdd950cd67abbe8a67ac2911c2ae596202c4504fcb1c71450b489a6f222f44763c27bada23f2f0b348e4548e9"
    "23ffdb3b8e1770ff12767470b86d9836fee6e2eeedfbdad3c89ded15712c23021fbe019793abdd3000af44600110ba96"
    "db2eb2cf22c53d3e3fc40d281391e2891041dec4eb4c9798c2c2afd0b44317448187e38415ac06be17e580a43465fb2a"
    "704c33359f8e8a410538c63e6d970ee11a655373ee1027c4bba02d21ac0369aee7ad2f967cd1b3a39045c69811c73cbe"
    "430e8e3c7dd8cd03d7d41acdbfdadb3ec4c196b6c90f24e518c1187602927d54962d06593ca060ac2e185d277a566e22"
    "8ca60cf20b78670274f897b18ff66d1f7231a4968f63b11299d6c1b41a01e44ba1debef4227b72afde6947e38feea302"
    "3330ec2d63adbff779ed2a95b4765fdb3d5773912be2c066f949870031644e06cbd22aed91860999154512463da186d2"
    "3535e3da46811a0f0e4b84047e3f808cd8a03ad4df0b825f921211c10d04fbc7edc9831e88486d69d3cade59467439d5"
    "9dc98b94f655866adf0c2d228b2e0aaeb2f891b897981040dd9fbf8fce7915ba7ceabc7f0a13a63bd172669f2813b343"
    "5eee9387b9e567594661ce1181b3afaae83258f005dd5c93d874677501a3c6b52cc3753814fddbfb9e1734a274e9d362"
    "18b99f37c9e6f08afeeef5a5c21749c3c2d8000d07192ea8e8fb101429579ad627285c72d4d6f32da8bac9f0fb1f616b"
    "79a4e0e8f30d223240637f8dc6d400000000000000000000000000060c1319212a";

} // namespace

bool
stratazip::sel::slftst9(QStringList& log) {
    int bad = 0;
    auto chk = [&](bool c, const QString& n) { log << (c ? "pass  " : "FAIL  ") + n; if (!c) ++bad; };
    auto s3 = [](const quint8* p, size_t n) { quint8 d[32]; s3256(d, p, n); return qb(d, 32); };
    std::mt19937_64 g(20261107);
    namespace dsa = stratazip::crydsa;

    // 1. NIST's ACVP vectors, the cryptography library's carried in: every key generation, and the whole tests
    // but the prehashed one (HashML-DSA, which the seal does not use).
    {
        int ok = 0;
        for (size_t i = 0; i < cryacv::kgnn; ++i) {
            const cryacv::kgn& k = cryacv::kgns[i];
            std::vector<quint8> pk(dsa::pklen), sk(dsa::sklen);
            dsa::key(pk.data(), sk.data(), k.seed);
            ok += s3(pk.data(), pk.size()) == qb(k.pkh, 32) && s3(sk.data(), sk.size()) == qb(k.skh, 32);
        }
        int w = 0, n = 0;
        for (size_t i = 0; i < cryacv::whln; ++i) {
            const cryacv::whl& t = cryacv::whls[i];
            if (t.ifc == 1) continue;
            ++n;
            const QByteArray key = hx(t.key), m = hx(t.msg), c = hx(t.ctx), mu = hx(t.mu), sg = hx(t.sig);
            const QByteArray rn = *t.rnd ? hx(t.rnd) : QByteArray(32, 0);
            if (t.knd == 0) {
                std::vector<quint8> o(dsa::siglen);
                const bool r = t.ifc == 0 ? dsa::sgn(o.data(), u8(key), u8(m), size_t(m.size()), u8(c), size_t(c.size()), u8(rn))
                             : t.ifc == 2 ? dsa::sgnint(o.data(), u8(key), u8(m), size_t(m.size()), u8(rn))
                                          : dsa::sgnmu(o.data(), u8(key), u8(mu), u8(rn));
                w += r && s3(o.data(), o.size()) == sg;
            } else {
                w += dsa::vrf(u8(sg), size_t(sg.size()), u8(key), u8(m), size_t(m.size()), u8(c), size_t(c.size())) == bool(t.pass);
            }
        }
        chk(ok == int(cryacv::kgnn) && w == n, QString("seal: ML-DSA-65 (FIPS 204, the cryptography library's), NIST's ACVP vectors: %1 of %2 key generations, %3 of %4 signing and "
                                                       "verifying tests (pure, internal, from mu; deterministic and hedged; the five answers of verifying)")
                                                   .arg(ok).arg(cryacv::kgnn).arg(w).arg(n));
    }

    // 2. The key set's ML-DSA-65 half, the same as the cryptography library's; it survives the key file and
    // the paper key; hcy4pub keys.
    kys ks, ot;
    {
        quint8 msd[32]; for (int i = 0; i < 32; ++i) msd[i] = quint8(32 + i);
        const bool a = kysfrm(msd, ks).isEmpty() && size_t(ks.dpk_.size()) == dpklen && ks.dsk_.len() == dsa::sklen && dsa::pair(u8(ks.dpk_), ks.dsk_.dat());
        const QByteArray h = a ? s3(u8(ks.dpk_), dpklen).toHex() : QByteArray();
        sbf pw("hunter2", 7);
        QByteArray fil;
        kys r1, r2;
        const bool b = secfil(ks, pw, fil, kdftst).isEmpty() && fil.size() == 111 && secred(fil, pw, r1).isEmpty() && r1.dpk_ == ks.dpk_
                    && pprred(ppr(ks), r2).isEmpty() && r2.dpk_ == ks.dpk_ && kysgen(ot).isEmpty() && ot.dpk_ != ks.dpk_;
        chk(a && h == gold9ks && b, "seal: the key set's ML-DSA-65 half from the master seed, by the cryptography library's label: the same key as the cryptography library's (golden); "
                                    "the key file (still 111 bytes) and the paper key keep it" + (h == gold9ks ? QString() : ": " + QString::fromLatin1(h)));
        QByteArray p, p2;
        const QString t4 = pubtxt(pubof(ks)), t2 = pubtxt(ks.pub_);
        const bool c = t4.startsWith("hcy4pub:") && t4.size() == 8 + 4267 && pubred(t4, p).isEmpty() && p == pubof(ks) && kidof(p) == kidof(ks.pub_)
                    && pubred(t2, p2).isEmpty() && p2 == ks.pub_;
        QByteArray bk = pubof(ks); bk[64] = char(0xff); bk[65] = char(bk[65] | 0x0f);             // an ML-KEM coefficient of q or more
        const bool d = !pubred(t4.left(t4.size() - 3), p).isEmpty() && !pubred(t4 + "AAAA", p).isEmpty() && !pubred("hcy4pub:" + t2.mid(8), p).isEmpty()
                    && !pubred("hcy2pub:" + t4.mid(8), p).isEmpty() && !pubred(pubtxt(bk), p).isEmpty();
        chk(c && d, "seal: hcy4pub keys (v02's 1248 bytes and ML-DSA-65's 1952): written and read back, the key id v02's; an hcy2pub key still read; "
                    "cut, extended, the wrong length for its prefix, a bad ML-KEM half: refused");
        // A lock to an hcy4pub key opens by the key set, as to its hcy2pub key.
        lid arc, lck; lidrnd(arc); lidrnd(lck);
        sbf lk(32); rnd(lk.dat(), 32);
        std::vector<quint8> r; krc k; sbf got; QString why;
        const bool e = krcmak(arc, lck, "x", lk.dat(), {}, {pubof(ks)}, kdftst, r).isEmpty() && krcget(r.data(), r.size(), k).isEmpty()
                    && krcopn(k, nullptr, {&ks}, got, why) && std::memcmp(got.dat(), lk.dat(), 32) == 0 && k.way_.size() == 1 && k.way_[0].kid_ == kidof(ks.pub_);
        chk(e, "seal: a lock to an hcy4pub key: its v02 half takes the key, and the key set opens it");
    }

    // 3. Signature records: both signatures, and every refusal.
    h256 sha{}; for (int i = 0; i < 32; ++i) sha[size_t(i)] = quint8(i * 7);
    std::vector<quint8> rec;
    {
        sgr s; QString why;
        const bool mk = sgrmak(ks, 123456, sha, rec).isEmpty() && rec.size() == 4 + 1 + 8 + 32 + 1 + 2 * (1 + 8 + 2) + 64 + dsa::siglen
                     && sgrget(rec.data(), rec.size(), s).isEmpty() && s.sig_.size() == 2 && s.sig_[0].alg_ == 1 && s.sig_[1].alg_ == 2;
        const bool ok = mk && sgrver(s, pubof(ks), why);
        const bool v2 = mk && !sgrver(s, ks.pub_, why) && why.contains("hcy4pub");
        const bool ok2 = mk && !sgrver(s, pubof(ot), why) && why.contains("no signature");
        sgr e = s; e.sig_[0].sig_[7] = char(e.sig_[0].sig_[7] ^ 1);
        sgr m = s; m.sig_[1].sig_[700] = char(m.sig_[1].sig_[700] ^ 1);
        sgr d1 = s; d1.sig_.pop_back();
        sgr d2 = s; d2.sig_.erase(d2.sig_.begin());
        sgr dup = s; dup.sig_.push_back(s.sig_[1]);
        sgr unk = s; unk.sig_[1].alg_ = 3;
        sgr sh = s; sh.sig_[1].sig_.chop(1);
        QString w1, w2, w3, w4, w5, w6, w7;
        const bool rf = !sgrver(e, pubof(ks), w1) && w1.contains("BAD signature (Ed25519ph)") && !sgrver(m, pubof(ks), w2) && w2.contains("BAD signature (ML-DSA-65)")
                     && !sgrver(d1, pubof(ks), w3) && w3.contains("no ML-DSA-65") && !sgrver(d2, pubof(ks), w4) && w4.contains("no Ed25519ph")
                     && !sgrver(dup, pubof(ks), w5) && w5.contains("two ML-DSA-65") && !sgrver(unk, pubof(ks), w6) && w6.contains("unknown")
                     && !sgrver(sh, pubof(ks), w7) && w7.contains("wrong length");
        chk(mk && ok && v2 && ok2 && rf, QString("seal: a signature record with both signatures (%1 bytes): good by the hcy4pub key; an hcy2pub key refused (it cannot check ML-DSA-65); "
                                                 "another's key; either half changed, either missing, one twice, an unknown algorithm, a short ML-DSA-65 signature: refused, and said why").arg(rec.size()));
    }

    // 4. Records aimed at their own fields (the lesson of): every cut, the count and
    // each length set to what the signer never writes, bytes at random. Nothing may read past, and
    // nothing may verify.
    {
        size_t tried = 0, took = 0;
        auto one = [&](const std::vector<quint8>& q) {
            ++tried; sgr s; QString why;
            if (sgrget(q.data(), q.size(), s).isEmpty() && sgrver(s, pubof(ks), why)) ++took;
        };
        for (size_t n = 0; n < rec.size(); ++n) one(std::vector<quint8>(rec.begin(), rec.begin() + std::ptrdiff_t(n)));
        const size_t at0 = 46, at1 = at0 + 1 + 8 + 2 + 64;      // the two signatures' headers
        for (int ns : {0, 1, 3, 255}) { auto q = rec; q[45] = quint8(ns); one(q); }
        for (size_t at : {at0, at1})
            for (quint32 l : {0u, 1u, 63u, 65u, 3308u, 3310u, 0x7fffu, 0xffffu}) {
                auto q = rec; q[at + 9] = quint8(l); q[at + 10] = quint8(l >> 8); one(q);
            }
        for (int t = 0; t < 3000; ++t) {
            auto q = rec;
            const int k = t % 3;
            if (k == 0) q[size_t(g() % q.size())] = quint8(g());
            else if (k == 1) { for (int i = 0; i < 8; ++i) q[size_t(g() % 60)] = quint8(g()); }
            else { q.resize(size_t(g() % (rec.size() + 100))); for (auto& b : q) b = quint8(g()); }
            if (q == rec) continue;
            one(q);
        }
        chk(took == 0, QString("seal: hostile signature records: %1 refused of %2 (every cut, the count and both lengths set to what the signer never writes, bytes at random)")
                           .arg(tried - took).arg(tried));
    }

    // 5. Golden: the deterministic record made again here; a hedged record made in a second machine, good here.
    {
        std::vector<quint8> d;
        const quint8 z[32] = {};
        const QByteArray h = sgrmak(ks, 123456, sha, d, z).isEmpty() ? s3(d.data(), d.size()).toHex() : QByteArray();
        chk(h == gold9dt, "seal: golden: a signature record with ML-DSA-65 deterministic, the same bytes as a second machine made" + (h == gold9dt ? QString() : ": " + QString::fromLatin1(h)));
        const QByteArray gh = hx(gold9hd);
        sgr s, t; QString why;
        const bool gl = sgrget(u8(gh), size_t(gh.size()), s).isEmpty() && sgrver(s, pubof(ks), why) && (t = s, t.cov_ = 123457, !sgrver(t, pubof(ks), why));
        chk(gl, "seal: golden: a signature record made in a second machine (hedged) verifies here, and not over another length");
    }
    return bad == 0;
}
