//! The multiples of the base point that signing, key derivation and
//! verification read.
//!
//! [`BASE`] is the comb for a secret scalar. The scalar is cut into
//! six blocks, and entry `j - 1` is the sum of the blocks' bases over
//! the set bits of `j`: with `d` the bits in a block, the base of
//! block `i` is `2^(i * d) B`. One pass down the blocks then costs
//! `d` doublings and `d` additions, against a doubling and an
//! addition for every bit of the scalar.
//!
//! [`ODD`] is for a public scalar, written in signed digits that are
//! odd and seven bits wide with at least six zeros between them:
//! entry `i` is `(2i + 1) B`, and a negative digit adds the negated
//! entry.
//!
//! Each entry is affine and kept as `x`, `y` and `d x y`, the values
//! the mixed addition reads. The tables are generated and laid out by
//! hand rather than by `rustfmt`; `base_table_is_multiples_of_b` and
//! `odd_table_is_odd_multiples_of_b` rebuild them from the base point
//! and compare every entry.

use super::Affine;
use crate::math::fe448::Fe;

/// The comb table for edwards448, whose blocks are 75 bits.
#[rustfmt::skip]
pub(super) const BASE: [Affine; 63] = [
    Affine {
        x:
            Fe([0x26a82bc70cc05e, 0x80e18b00938e26, 0xf72ab66511433b,
                0xa3d3a46412ae1a, 0x0f1767ea6de324, 0x36da9e14657047,
                0xed221d15a622bf, 0x4f1970c66bed0d]),
        y:
            Fe([0x08795bf230fa14, 0x132c4ed7c8ad98, 0x1ce67c39c4fdbd,
                0x05a0c2d73ad3ff, 0xa3984087789c1e, 0xc7624bea73736c,
                0x248876203756c9, 0x693f46716eb6bc]),
        dxy:
            Fe([0x6a7c93790d43b1, 0x85ee44c273b40e, 0x961292e5164ae4,
                0xf1ce00e83a6626, 0x11129e5cb41037, 0xf4d1b86e904781,
                0x675b8a5541c3fa, 0x26afa9e48a9aa1]),
    },
    Affine {
        x:
            Fe([0xd24ae1d77e9709, 0x77751dc0047b8a, 0xe325334c6a1593,
                0x9baf962671f86a, 0x425af6ac29a15e, 0x31086002796e33,
                0xb6ea78cfc253a5, 0x4c733e0afae0ea]),
        y:
            Fe([0x4b7443a97c99b9, 0xc14e9e450203a6, 0xd1bb51552680ba,
                0xa56a3efd55533a, 0xa66e38c169e1a0, 0xb3e4df9eed7da0,
                0x022c937ddce3d9, 0x8552089f6e36b4]),
        dxy:
            Fe([0x8105aa3731f0a9, 0xa5792dd9948b05, 0xfbb81b26a19fff,
                0x92ff11e2f0d2c6, 0x58053bfadb9b37, 0x01e7b769c1ccf2,
                0x3b73fd5e7c6341, 0x7ac5889e3a9185]),
    },
    Affine {
        x:
            Fe([0x0410429ac6f00d, 0x2569982f16900b, 0x172e78a05e86e4,
                0xa968c0f89f3755, 0xf4ae947ea276c0, 0x5e8d748e3be9b1,
                0x9d424b51325850, 0x75f391bc4bfe44]),
        y:
            Fe([0x608cec114bda89, 0x966e7465182778, 0x3979e0d2ec4e27,
                0xab3b54b69b6be1, 0xfd056f83124dc2, 0xb5fe60f95c1abf,
                0xf5eae0d7cb8229, 0x8ab20222d5a88f]),
        dxy:
            Fe([0x81ca3f092ba8b6, 0xb848554c616bdd, 0x29295b40341fc1,
                0xc1d6de6e7809ec, 0xcf9e7cec4f1d87, 0xa827665d018cd0,
                0xa5629a219de771, 0x63221f7d81bce8]),
    },
    Affine {
        x:
            Fe([0x972a6c29752104, 0xef49ea94f050ec, 0x8128ae0d916d47,
                0x75147cc3166065, 0x5c867108c39139, 0x96493d77c7d57a,
                0xa2e39558bc78fd, 0x530eee10f9c1c4]),
        y:
            Fe([0x46831f78d76976, 0x72ddf9ed36bc96, 0x9447fcf09218f7,
                0x7d015d9b89897c, 0xa54dff01a9298b, 0xd397c961225897,
                0x593fcc958bb30a, 0x006b04238d404b]),
        dxy:
            Fe([0xfbc91245cd6610, 0xbb97a3b1201de6, 0xfa85964b52452e,
                0x002e1a4156d027, 0x9c5b62e112f664, 0xfba2a4bc7a4c37,
                0xa5e373a09f5fc6, 0xef8737a2b8e73e]),
    },
    Affine {
        x:
            Fe([0x51eb814a1d3a54, 0xa9b5e8855df433, 0x7ac470305dd649,
                0x182dc189a114a8, 0x966a17c0c4c694, 0x43a4813b486ef2,
                0x3dfc3c306f71fe, 0x045621894038af]),
        y:
            Fe([0x3d6365e5135ded, 0x6d85b0009b86a4, 0x4acc0831a2a6a5,
                0xaa5d4fc4a737c0, 0x68c1b293cdd1fc, 0x760b9f3cd1dd26,
                0x05b1ce0708dcfd, 0x8b7ce2c591af36]),
        dxy:
            Fe([0x1726456a00484c, 0x5611853f4fc350, 0x896bf9646fc865,
                0x2f8eae6284b388, 0x51404aa9f804a4, 0x092cca629a31e4,
                0x21c57402f351a5, 0x4d232ec2cd9662]),
    },
    Affine {
        x:
            Fe([0x84b1b5a9a3886f, 0xd6a1d1a7a74828, 0x80a8fcdbf23061,
                0xe61c3660080bdd, 0x4f71d9f14a04c7, 0x95ea2b3a40ca23,
                0xddad2ad500a0bf, 0xf3cfe9d05af1cf]),
        y:
            Fe([0x8cacd0cffefa75, 0x38339a11e16d62, 0x06e7f1624002e3,
                0x1637c54f711bf8, 0x084a5793a7fa59, 0x2a908336d90654,
                0xe8ed51f6c178a2, 0xf140d3d2dd1f7a]),
        dxy:
            Fe([0xa4c26f93c0e82a, 0xd60bab52377e74, 0x8274dea318239d,
                0x6c3c7377df5887, 0x8cbbc1fabb2a22, 0xe1b90a90d7f999,
                0x4e4b4162d8377e, 0xc45764e06f6fb0]),
    },
    Affine {
        x:
            Fe([0x54400cb86e07c8, 0x1d17bf1b621c2e, 0x80786cba2adeeb,
                0xced32cfe278635, 0x23433bd7025ffd, 0x3a4f9641b69ae5,
                0x9a14605f55ef63, 0x58ba682775f083]),
        y:
            Fe([0x0cdb4b58f97bcd, 0x7d091629f2d7ac, 0xd10d02a5fb83d5,
                0xad2826693364e8, 0xf7347224187612, 0x79251c962449d2,
                0x7ff3b9021c7d1a, 0xa1a1d7b8c6eaaa]),
        dxy:
            Fe([0x24ce80e71478cf, 0x70c193641462a2, 0xd1a86bc45978a9,
                0xd16db65d2258fe, 0xd9c7ed69b7aa91, 0x50c4cc530bd1d2,
                0xea32f4f33dab93, 0x568434160c9415]),
    },
    Affine {
        x:
            Fe([0x1d7605c6909ee2, 0xfc4d970995ec8a, 0x2d82e9dcf2b361,
                0x07f0ef61225f55, 0xa240c13aee9c55, 0xd449d1e5627b54,
                0x07164a73a44575, 0x61a15fdbd4bd71]),
        y:
            Fe([0x30696b9d3a9fe4, 0x68308c77e7e326, 0x3ac222bce0b8c8,
                0x83ee319304db8e, 0xeca503b5e5db0b, 0x78a8dceb1c6539,
                0x4a8b05e2d256bc, 0xa1c3cb8bd9fd57]),
        dxy:
            Fe([0xb9057e17e08277, 0x747a65e4ea47c4, 0xf4ab01b1534c8c,
                0x9533327ba33a11, 0xdb43395289d67f, 0xa2a816be033c63,
                0x6b59b3739361b0, 0xb53c0ad0547340]),
    },
    Affine {
        x:
            Fe([0xf867d14e65f8ad, 0x6f15646308b134, 0xec9c1370fdb28a,
                0x3f6e7d65a6a6cd, 0x5c80474b0def48, 0x45c8ac300ddfdd,
                0x29852af5db7b14, 0xdafe18ca5c6a45]),
        y:
            Fe([0x1c3aa4656cfaa8, 0x32a9e536d1b9d3, 0x172511422442f1,
                0xdac1707c90941b, 0xb0da13a52322a3, 0xe149661f0f882e,
                0xd3e6427366c874, 0x9d2f3c42497821]),
        dxy:
            Fe([0x3d0e217222109c, 0x7cb8c57be14f15, 0x6e4c79f57ea30b,
                0x1aa62a11eef1cd, 0xff502b9cd2850a, 0x5b2c1b8044b81d,
                0xc1ada10a437f44, 0xd1f87ea4d59c77]),
    },
    Affine {
        x:
            Fe([0x8b5566205b3dec, 0xdbeb5647a5bd4c, 0x73153c5f394255,
                0x624c243ae45827, 0x3d5c6c64c677f8, 0xb82b6ca818ca17,
                0x3ac91e3c525423, 0x27235f3c4814e8]),
        y:
            Fe([0xebf8878638e7f9, 0xed02ed159f2921, 0x833cd75d08d116,
                0x275d014ed1de82, 0xdb4e9686d33f84, 0x76e8eea89b55cb,
                0xc9d0a17d7072e2, 0x93f13d75d16295]),
        dxy:
            Fe([0x12e3b39442d081, 0x4027fd77716a88, 0x558e73817cfd51,
                0x9263eb817698ca, 0x3a71cfec5bc623, 0x034dc33368df93,
                0xddc3e971ae01bb, 0xa6bd84fc294a48]),
    },
    Affine {
        x:
            Fe([0xf0b4a0a3e1e6c4, 0xc0bb15d726a253, 0xa974296a681de0,
                0xcf4a111be607d0, 0xe6a2b47c3ebf96, 0xc1ff912330041c,
                0x8b1ac0e6b85a7d, 0xbc2088684ac011]),
        y:
            Fe([0xd77a5fd80a66f0, 0xdfbc533486bd93, 0xdbdbe1beeb3373,
                0xc1453608e1cba3, 0x366dea1fb2ec9d, 0xf3a28c9564a2d5,
                0xaf5c20d26b8393, 0xe7a687ac7ba52a]),
        dxy:
            Fe([0x9535ca7e7c6b75, 0x324b4bb246f0af, 0x171741e13a254b,
                0xdeea7da1041e8e, 0x978ab2b605dbb9, 0x3cf87a2d501916,
                0x857ea87227d5bb, 0x40a705cc566a69]),
    },
    Affine {
        x:
            Fe([0xd1efe6578630e6, 0x6da871015bf96d, 0x4130e900775b7f,
                0x34bf18a14c571d, 0x32629ec2c59f85, 0x8223d0f224f33b,
                0x4741cc5b46fa8d, 0x36841992d91f17]),
        y:
            Fe([0x01dca5d5eaae3a, 0xeb3ea9a6c98e81, 0x2e2febe79a6bc9,
                0x3f4a01a0909384, 0x610dc3243c938b, 0x8abe64f305643f,
                0x612ab424bcc522, 0xeae2ca2170547f]),
        dxy:
            Fe([0x92d4150f426518, 0x5c62e4af12dde3, 0xdd8955fb3c0314,
                0x98e72dde71608a, 0xd797c83ca0c3a6, 0x901150514be1f9,
                0x3fcdd1be78b7ae, 0xcf88dd717ef3b8]),
    },
    Affine {
        x:
            Fe([0x86c1961e2a7e79, 0x75939bab0e791f, 0x58fd7dd7ef6c3c,
                0x47257f9fb8298d, 0x322060159cce80, 0xa62a3ce31c2dcc,
                0x6a0156fdee2ec5, 0x83d0737f825fb0]),
        y:
            Fe([0x7da0a417c41827, 0x31c273c8a9badd, 0xecfd1c11e53fd9,
                0x7fbe2e5e703e77, 0x3f2f1e2e1d9ad9, 0xba512aa73fb0c0,
                0xaa760008fa60f3, 0x188554f25a5d7c]),
        dxy:
            Fe([0x727aaa4576deec, 0x66c8469dd2c277, 0xa147469257b9f3,
                0xefc3d17aede6de, 0xa50dbb7d2a5dc8, 0xa8fec9d32b3013,
                0x8a177895210edb, 0x7d914237ab8459]),
    },
    Affine {
        x:
            Fe([0xe25d698d0f2fe6, 0xb668df856e484b, 0x03f438bd59f02e,
                0x13ada0687a6e6b, 0x1f24123e1605c3, 0x81cd234f0030ad,
                0xc2e0d6f3d3c048, 0x0fd09d267a91e9]),
        y:
            Fe([0xb6300758c207fe, 0x091f1d3c616450, 0x29f43d2a3ab4d0,
                0x64484cf1d1888e, 0x0a15a3b29f2d5b, 0x56895d15764bcd,
                0xeedf8a3d9c9fab, 0x3dd1f38d9d110e]),
        dxy:
            Fe([0x01f4d374cd9214, 0x26437be0d44b96, 0x297cba58d7abf3,
                0xc32e3a9d6981fb, 0x2126169fae08f2, 0x23c045019e2a3e,
                0x5b264d9b51e99f, 0xe461fea50afe93]),
    },
    Affine {
        x:
            Fe([0x305f73da62af93, 0x11221f9ed452e4, 0xa136c3af9cbcd4,
                0x0004a4d3a324c8, 0x491f713e3598d6, 0x92b23d7735f26e,
                0xee344c9a496523, 0x1841a77c95a211]),
        y:
            Fe([0x249db1d9b80a6a, 0xa3c0840cd1f714, 0xd04fc1835fd61b,
                0x6c8d838010849d, 0xf4b0ac306d35ea, 0x55201f76029537,
                0xd2a5db2eb0192c, 0x00c37946cae9b3]),
        dxy:
            Fe([0xaf89dc2f0f0dd3, 0x8298e0fa9860cb, 0x0c7f61dedb2c6c,
                0xa82824170b8218, 0xb3a430a76eda0d, 0x93329f5fa3024f,
                0x9c18f0a347e567, 0x9ad3ed65e2fb3b]),
    },
    Affine {
        x:
            Fe([0x34dd6c87fc13a6, 0x295148f07612f8, 0x4842aac3968483,
                0xaa247db3e334ff, 0x064d57115bcf46, 0x0bef8e5346c6db,
                0x796b84fd21c04f, 0xcb30b2dfe34ff4]),
        y:
            Fe([0xe7b762a9de4308, 0x57f4aac8c7ec6a, 0xec0ec43caa8a1f,
                0xa1024a71e4e73d, 0xb45187a91f5bc4, 0xd7d8d0a393aedb,
                0x87fb17361e9926, 0x6bcb8351a68ad2]),
        dxy:
            Fe([0xf3f7d78dd386e6, 0x40f51bd459641c, 0xde8cfe254bc422,
                0xdffc51d137e91a, 0x8a2f208afd7384, 0x5f47e9317a7586,
                0x921ce40062fcc6, 0x630df0517b9c3e]),
    },
    Affine {
        x:
            Fe([0x66c838294eb2be, 0xea02783bbe33f7, 0x070010f187223f,
                0x1d2a99d18b9f72, 0x536540b46d707f, 0xb889b5f6105ba3,
                0x7dbaeee1e853ba, 0x7125c1732485f6]),
        y:
            Fe([0xc557fc2a21323b, 0xd1bc2098be06ac, 0xbeecd4a3f83004,
                0x1aa57e1ff7b9a0, 0xb9f3bf413e8815, 0x74a6755a106710,
                0x1a3fe121e5f26c, 0xcc705454dc4b41]),
        dxy:
            Fe([0x03232b90f53806, 0xf4d1e9c490a597, 0x4c14e9ecfae6a7,
                0xf8d5d57303cf39, 0x7d07d8171447d0, 0x816cfd5f01b412,
                0xe529691e14ba33, 0xd741ea16dadb07]),
    },
    Affine {
        x:
            Fe([0x9a44770a5c28f1, 0x8de755523dfef0, 0x1e515adbe3a439,
                0xe13693c4898e5a, 0xe89771f1615226, 0xff8cfd627cf376,
                0xa8e884c9f125c0, 0xb9365488636671]),
        y:
            Fe([0x58d3b336224121, 0x411b94877e2058, 0xcf2de9a14b7332,
                0x836f775c99344a, 0xfdf38209bc6e6d, 0x850e0382564f22,
                0xe260755ccb49e6, 0xa139f7e8fd8272]),
        dxy:
            Fe([0x7c772c9c73b64f, 0xfc2c8e29554788, 0x4e12c10ef8c4b5,
                0x2ecc319334de32, 0x052c3740011a73, 0x0cdc15603bb673,
                0x5e2dba4afba682, 0x25347b1321a887]),
    },
    Affine {
        x:
            Fe([0x11d6c160f07b54, 0x8ad6681b21bc67, 0xdf08c006ee30d0,
                0x99aa44801be260, 0x4079e2d2c9eda1, 0x07f287db12f258,
                0xf610c18ebe8c42, 0x68158a84a8fca3]),
        y:
            Fe([0x89714b0892dbae, 0x8baf4e6224f368, 0xf389add52ac89a,
                0xfe0de8f3369aeb, 0x7ed9d0f92b4b2c, 0xe104c4485dce2b,
                0xf227fc9fe533c5, 0x331809709ea33f]),
        dxy:
            Fe([0x50a6fd923b33d2, 0x0ce5bafd0875e7, 0xec086862a3ac18,
                0x5eebf0a361038b, 0x923c2142ab130d, 0x80fa6b8c643796,
                0x1480ad6bad9088, 0x2060ce0977c31e]),
    },
    Affine {
        x:
            Fe([0x8092814ff2c7ea, 0xf73a0b0943e99f, 0x639b61f9ae1f35,
                0xfeb287f5b000c7, 0x156011c330d185, 0x0946d39e199bb6,
                0x7b8af0d6efdc47, 0x2aeed74b2111b2]),
        y:
            Fe([0xe8f8b3ef1eb6fc, 0x992737561b3b5c, 0x863b0fdbece349,
                0xf26a6359fed54a, 0x2e3e6078e89b8f, 0x575349631effea,
                0xaa09f4be7c8400, 0x49a2f09860edb4]),
        dxy:
            Fe([0x2083440e97d8df, 0x7476a260474e23, 0xdefee6eb9376b3,
                0xf5aa7c8fb62415, 0xca01c686b635dc, 0x4ee47d15e5fed7,
                0x8000c974012d16, 0x67ab1ee9d89f8d]),
    },
    Affine {
        x:
            Fe([0x758511394aa795, 0x9cc4f8087425d1, 0x7168c6e49704ee,
                0x5c428b2761fc28, 0x8ad46d3251ab8f, 0x201ea5f55c5ec7,
                0x974012bde9b71e, 0x29102fd2f5af0b]),
        y:
            Fe([0xbf77c23f1143e1, 0x2e22c2bf0c4cac, 0x197240ad26b5c5,
                0x347bab549e00a5, 0x9c9170d6679467, 0x26da92694bef50,
                0x31c6969c8a69ab, 0xbf909a3b2d3e97]),
        dxy:
            Fe([0x8c4854bd41a369, 0x97a2d0a0ae5d4f, 0x5ecdfe5766dd11,
                0xbbe270c16a262b, 0x3f83a745eef0d4, 0x101398814cdf2d,
                0x269ff50e680461, 0x8fe17755e38791]),
    },
    Affine {
        x:
            Fe([0x821ee5766d3265, 0x41f9165d04eae9, 0x74faaeb3a8e940,
                0x51025f1923f2f7, 0x7c90b86e588c08, 0xf807dd90619e22,
                0x82d1fb97a41d89, 0x07ace4614356e2]),
        y:
            Fe([0x35f9a161be1186, 0xef43dbc70a4aab, 0xaabace041d597d,
                0x77b4cea111b1b3, 0xf8c4e701d8f63b, 0x39bac522581343,
                0x158d3d29885c6f, 0xcaa4d3a3c1ce10]),
        dxy:
            Fe([0x25db836a91db60, 0x0a9aeb9f7a7c2f, 0xda43f16f4fb3e1,
                0x91e25e8b2bc482, 0xf57b65efaba64b, 0x8b918479d9e026,
                0x476e7dbefb298a, 0x529c015eb6bf33]),
    },
    Affine {
        x:
            Fe([0xfd70f3a8207c0f, 0x68bfeed7fc28d8, 0x9cbc9af365a662,
                0xd692be5f2d4fab, 0x8d993d52216864, 0x8936ea79ed2459,
                0x6206ca70189b1b, 0x9d7a7fa0ebeca2]),
        y:
            Fe([0xc089fa5871a88e, 0xa59b2a1e6ad55a, 0xe4e3333da13985,
                0x196beb5f020bdd, 0x12a6beb43f1bb5, 0x24bd4dccd37e7b,
                0xcd6a6429ba8a0e, 0x399b4d073d1b50]),
        dxy:
            Fe([0xdd01d2a2133287, 0x1919455625b7b8, 0xab1239bd2e3b77,
                0x81bbd9ac0caa0a, 0xfcbc929d8014e1, 0x9ff9ea8c281ad6,
                0xd0a250f5ab7504, 0x94f691d1bfc1a0]),
    },
    Affine {
        x:
            Fe([0x82110da83e9377, 0x6452bf207ab57c, 0x3b4c4f3c719e63,
                0xb31f1ecfdb8515, 0x8b43c312f77062, 0xa4dbaa70d55895,
                0x478b966f2191db, 0x5e827040d708d6]),
        y:
            Fe([0x5a88f7f2f3a1a5, 0x4856a66db2e026, 0x2b7d61bf562ead,
                0x8889aa3700cae2, 0x6d923291e20496, 0x2df7b76616f3fd,
                0x6f086a7a57159c, 0xe709e6ec3fe4b2]),
        dxy:
            Fe([0x6050a7c3495fc6, 0x5fb5b1122d464a, 0xba802c8bbfba41,
                0xe3dc5ea36a2c36, 0xf62d06483dfeb8, 0x47416f46f0a375,
                0x45e2f90bbd262a, 0xc6baf751dca580]),
    },
    Affine {
        x:
            Fe([0x6a1965f8e71cd5, 0xce28bff5de09d6, 0xcf38ba74408e09,
                0xad11b8c18e1952, 0x49fdfde80cba85, 0x42beb29bd1d6bc,
                0xc223c06b8d1653, 0xc4c5ba7ca7954b]),
        y:
            Fe([0x9c5fa127db0b03, 0x6057cb618d9710, 0x5c93a6109a5dcb,
                0x1caf29812d6f6e, 0xffe48774ed405e, 0xceb8e75ee4a033,
                0x3cb9dfe5849bfc, 0xc2745641249d38]),
        dxy:
            Fe([0xf7e57e6340ca3d, 0x1797acdfd53876, 0xd19f8a7918a404,
                0xaa6385f5781871, 0x1eb421b5452e82, 0xd36d11197f52d8,
                0x81349340c042d6, 0x2f41d3434fa5c3]),
    },
    Affine {
        x:
            Fe([0x9d6d76867988fc, 0x790c014a7b3232, 0xbb3eec3c3e0e92,
                0x52b96681b209fd, 0x82f058045156df, 0x7a1114fa0a0ae6,
                0xb441e47e8f129d, 0x6954c8b2c48184]),
        y:
            Fe([0x9e4f8b7a763085, 0xe85f1a432161de, 0x3b636e19f1c05c,
                0xae4a9f23f71bdb, 0x15a0cedce08e0f, 0x71a002c060d755,
                0x3a8acfb6eb8bcc, 0x402e4a4e876f6b]),
        dxy:
            Fe([0x4af56acea5e84d, 0x94264fb6a35a69, 0x28abfe0195850d,
                0x46b3593e5b13aa, 0xab27f44842c1af, 0x40e6c473cff0ca,
                0x7a49208633b62c, 0x68a11eb5a5c2a8]),
    },
    Affine {
        x:
            Fe([0xa5f398e3a161aa, 0x32530eece383ae, 0x19ee3edb5a2c3f,
                0xffa9c863ef9495, 0xc7223d4ac970fc, 0x8c1fb9e0032b4c,
                0xfc25fa13962270, 0x3a4ac56571ece9]),
        y:
            Fe([0x0052a896af4b2a, 0x87ceffb6cd1d8b, 0x1ec30bf1be6933,
                0x68ee3dd8d0fd32, 0x9f7ba7c4f7785e, 0x69f90dd1ce0d6e,
                0x1532ea7667d9b3, 0x07da1a61012899]),
        dxy:
            Fe([0xa6e5dbb4494a05, 0x75e2e7142610ad, 0x0004e4f52871e3,
                0x346dd0bbbe9df5, 0xbafd4d0d79e7d2, 0xd5ef5676a4b93f,
                0xf9832effd49c43, 0x0c928e57605927]),
    },
    Affine {
        x:
            Fe([0x7a426232a45a44, 0xadea010bdab511, 0xe6fdbd66c36781,
                0x7cbf577a0618f4, 0x16d51288d3e785, 0x7b6ebf1dbe7fcc,
                0xddeb157601eb07, 0x1711b99dbd64dc]),
        y:
            Fe([0x0d11fdd78eda5c, 0xc6e92523e3b683, 0xb5af4c63641e3b,
                0x372ef98ce2dae6, 0xf7c92710130335, 0x999be1e19650a1,
                0x7e0e30e92c6b03, 0x87aac29f8fbe01]),
        dxy:
            Fe([0x2fa216e3970aec, 0xdc559af7bbbcb8, 0xf68c71bebe83b7,
                0x782c0f19056b0b, 0x5e9b424d48cd8c, 0xe196d4e4895306,
                0x93dedfad3b7269, 0xe309634c06bc8d]),
    },
    Affine {
        x:
            Fe([0x0332294c5f8c8c, 0xbf28858561519b, 0xabd9409ab91869,
                0xad31605d4efe24, 0xc5e5757a7c51c1, 0xa040d339920c1e,
                0x0a0231f5aac744, 0xca4931245c94e1]),
        y:
            Fe([0x6d4784a7893af5, 0x5d982105d21e88, 0xa119c0f0a22fb3,
                0xcae4fa08d9104a, 0x90b3e44aa0f9cf, 0xc4c1c15e80b087,
                0xc0360e313a1975, 0x51859bd4192ffb]),
        dxy:
            Fe([0xf44273aeaf3b40, 0x8e4e467e1213e0, 0xd1941f2021b58d,
                0x06a2a0a84fa853, 0x2e456825e4b894, 0xe89452c17bb8e5,
                0xb196a17a689783, 0xd9836a052d80d5]),
    },
    Affine {
        x:
            Fe([0xf662d1f7c66cb6, 0x3ae5c92d5d7ea4, 0x242283adf1e823,
                0x1f34260efce582, 0x76f49330c18946, 0xa2865cf86a1825,
                0x153aa0675ea9a1, 0x8c7e9fd01f3824]),
        y:
            Fe([0x3609c775b7c530, 0xdccb31daafb2ff, 0x6ef2a979042a21,
                0xf335ec028cafa2, 0xde7119b62da8d0, 0xc090974e66a1ce,
                0x2ac00755210ab0, 0xad0a28d0441b13]),
        dxy:
            Fe([0xbfd9ec3b9007f4, 0xa34726ef0b9ab7, 0x5be884c7168f50,
                0x4bdb236f5de79f, 0xe3a4e1836f9b60, 0x4c55bf28f895f1,
                0xfddd0101528ff0, 0x0af528d02e15be]),
    },
    Affine {
        x:
            Fe([0x97ce2592334c2f, 0x923d496740c45b, 0x65ae865a109ce7,
                0x507379df4b4524, 0x63427ce059b24c, 0xf3e259820ed05f,
                0x0ed69022cdcc04, 0xf06437360221d7]),
        y:
            Fe([0x766c79e3d6f1fd, 0x0cd9598b227861, 0xface1ea1ce408a,
                0x53dfe3a0321d00, 0x02cca165a534ae, 0xdebf998dd83705,
                0xabb1533c5e2eb2, 0x192ff0b2a17c7f]),
        dxy:
            Fe([0x86012257d9236e, 0xd6c86fd80af860, 0xf89d64283fa1ed,
                0x6381b00efc252c, 0x91ca156ef1a1b4, 0x6e64a9b2a16e87,
                0xb4aaf9a1d550e4, 0xa0db084cc90ed0]),
    },
    Affine {
        x:
            Fe([0x161d66ec4bd38d, 0x4cee65250b9e03, 0x4df414eaf595d9,
                0x56f7ea03223e4d, 0xf9bf595e97b53b, 0x5d862f3160947f,
                0x1d69cb97c650b2, 0xf903d37923d983]),
        y:
            Fe([0x49b5476b786836, 0xcf9c667496e84f, 0x354a3e4119d2c6,
                0x31863cf362cf43, 0xb8946d58314ce9, 0x6e0d0e4d86dd0d,
                0x5d0d7e7195400b, 0x977b45653d87fd]),
        dxy:
            Fe([0xca61b788b29bde, 0x90c78dddc5a89c, 0x968506d633d12b,
                0x3c4f7cde1c6db2, 0xe07cbbc0e879ff, 0xd0f29a815981e5,
                0x5cf86bcd5b9f80, 0xc2261eacf0fcaa]),
    },
    Affine {
        x:
            Fe([0x3f3a8de0a2e45d, 0x7bf52ceff8896d, 0xcd7fc1e5c08608,
                0x2556067a5eeb37, 0x1234b23e1ee565, 0x6a0575cfc9032d,
                0xf24a403bba9043, 0x0189f684e1e66f]),
        y:
            Fe([0x1d3917c2705caf, 0x41368490aecca4, 0x99e8205ead8dcc,
                0x0bcac94f3bde5b, 0x505e927b5ef8b3, 0x0b2ada944b2e6b,
                0xb762f59cea1c27, 0x4dbebb47181ab4]),
        dxy:
            Fe([0x01acd1565a5997, 0xee26926a2359f9, 0x3d7560b30d4213,
                0x35a039110c57bb, 0x7ef2b520bda8b3, 0x40b3fbe23d21c6,
                0x1447494bc1e2e5, 0x4998f42d4c8717]),
    },
    Affine {
        x:
            Fe([0x8386b25b30fbce, 0xbe121333e92c53, 0x1959ea0fa69bae,
                0xe5bba72b7f6357, 0xb4a79703f1c6f1, 0xf7a42f029f0c87,
                0x5fe71a9a4ec4f4, 0xbc69a2fe81e7a5]),
        y:
            Fe([0xf806f3f5960a22, 0x343c8e9f5cbecf, 0x74616355ad32eb,
                0x3faf1233d19084, 0x65eefbb2d0c87c, 0x88f24b3561a941,
                0x9e48c6a45eb9ae, 0x58617933cb8b50]),
        dxy:
            Fe([0x448ffc9bfb6aa8, 0xac1481f9ab43aa, 0xbd9359f990baa1,
                0xc94847f11e9c5a, 0x45b2e1daa6a02b, 0x511af5205eed7e,
                0x078b1975c05d11, 0x036e4b1691c01d]),
    },
    Affine {
        x:
            Fe([0x87f90acc04fb1d, 0x8b516f12375660, 0x9afab34c963c22,
                0x4825a6ee2beaea, 0x492bb8cd87dc57, 0x135bc10b9fb736,
                0x9bfb907815b246, 0xfe659e1ed7d9c1]),
        y:
            Fe([0x2e3d8b58df8ef8, 0xf20784446813f3, 0x4ed617b5ab9673,
                0x39f8ff86816a01, 0x5ec4db49743c02, 0x89fe7b3dd27c9e,
                0xbadbe07f6a4f74, 0x60d4e109ec81f3]),
        dxy:
            Fe([0x98e48a6a901e33, 0x3b6774d68d8040, 0x1821ee5dbca55e,
                0xe24e5628184e18, 0x72a57093406963, 0xa3ed43b876927f,
                0x516fad0de5d2a7, 0x206d112508c9f0]),
    },
    Affine {
        x:
            Fe([0x4f01a35f07cb66, 0xc084740a606ed0, 0x78bf9fd6b3b9c2,
                0x1eaa1d8c16411c, 0x898cc7ea896957, 0x036fc445eef3da,
                0xe026413acae5be, 0xb4b49d5ea2d206]),
        y:
            Fe([0x3f74b0bec40261, 0x427fb12ce598c1, 0x67ec88950b2911,
                0x9664281b098049, 0x7164513594c6cc, 0x785567555c20ae,
                0xe32659b5c7f4dd, 0x470cac06015443]),
        dxy:
            Fe([0x73ab151f401c37, 0xca0d06acbc7c05, 0xfdc5f58be113ac,
                0xfe0a028808a8df, 0x3c82bc82b92ca3, 0x233d790115c12f,
                0x7c66becf1d1f5d, 0x276040016df4b4]),
    },
    Affine {
        x:
            Fe([0xd90b31264ae4e7, 0xe8046990f8b10a, 0xa8839f9c7a2b21,
                0x2d00a9067db0a8, 0x4eae5640aceb76, 0x48591ab90118e9,
                0xdf716be8b2bdf0, 0x3baf1c61fb6763]),
        y:
            Fe([0x27a84c259c9a2a, 0xfa25fc29deb11a, 0xf5e518a0fe34c5,
                0x1cb039cb066768, 0xb35daabdc91d43, 0x401bd1ad7aa8b6,
                0xe427096d29570f, 0x45b84ab0727267]),
        dxy:
            Fe([0xfd7139ba2e9691, 0xf1c978c76703bd, 0x1f4c6d701fe8b9,
                0x28e58e3d536597, 0xc16b63a750f033, 0x142233da6b7db3,
                0xd19f8863b2e605, 0xd77d75cb4f3f8f]),
    },
    Affine {
        x:
            Fe([0xd9f424f4afec86, 0xdec3db5a4e13fa, 0x5f17d3d6cf065f,
                0x176df60c356d83, 0xac6b8b6f2d0674, 0xeec2a15aa62105,
                0xec82432d4b905c, 0xcbb2de946438b1]),
        y:
            Fe([0x8f341c7569dafa, 0xa0b904c5f8fe03, 0xd3761a536c844a,
                0xce58929a95a527, 0xe293d6ab4bd296, 0xb907021e150044,
                0x4e70cf189e41a6, 0xd4178bb8fa8de4]),
        dxy:
            Fe([0x8d262363ac1635, 0x2582643a5b8bc5, 0x4d5a350f5675a0,
                0x6d650d225457c7, 0xe27cd9919e7a60, 0x069ba378aec4c6,
                0x896754986a8d0c, 0x77224cd91fc5fc]),
    },
    Affine {
        x:
            Fe([0xe42cdfecd4c402, 0xb26df97a57ef17, 0x1d1f4984606743,
                0x27b77b3df95f0e, 0x557fbfa730d69d, 0x28b86479788f21,
                0x18d856736ce201, 0xb7aed8c3b0c56e]),
        y:
            Fe([0x84163203dae725, 0x5a7289ced855b1, 0xc4ea601d088090,
                0xa624c3ae951635, 0xa99af1b1312c70, 0x54c0fee7b9c570,
                0xf1f31d46264ac9, 0x834244b2d63bcc]),
        dxy:
            Fe([0x2023c3d538f511, 0x7944a802eaaf83, 0x9271d171b4dc04,
                0xb32ea143b623b1, 0xe2274923cf589e, 0x84749215235f4a,
                0x39b3a9edea9907, 0x65b76c86ed885a]),
    },
    Affine {
        x:
            Fe([0xcf95e93c186263, 0x70ece97152c673, 0xafdae13e227f5f,
                0xaad34dab63af27, 0xc29ecd7588123f, 0x07545bf74bd11f,
                0x9d5d3f87779c80, 0x0d476142156c2a]),
        y:
            Fe([0xedcbd1ff486065, 0xc11d989d517e27, 0x4fe995c73fadf7,
                0xd9922e41ccf4e9, 0x91a52435184f21, 0x16ff5aea857708,
                0x6b6354a063dcfa, 0xc05afb08dd8fe0]),
        dxy:
            Fe([0x2702cafdffb163, 0x4b1dd84a9006e3, 0x73e4b463cdfc17,
                0x8fdaa7e6aa4687, 0x8c6ad8612b0a8d, 0x616bf64dc5283b,
                0xec4607deb43dda, 0x96418bf6f446aa]),
    },
    Affine {
        x:
            Fe([0xbd9a367f793bb7, 0x32a08399b7f565, 0x1a3d0d12eabfc7,
                0x9cac0f54241c91, 0xd9bfd845ac9bdc, 0xd5499d908216fb,
                0xb7cd949cb7f264, 0xde9b8fe87c1e8a]),
        y:
            Fe([0xee078de9cedf95, 0x11a38488e9fc0a, 0x69c103da858557,
                0xf8ec8bc4a417bd, 0x923dfd0eeca2ab, 0x96551848a95fdc,
                0x16609d243d4784, 0x0ff30f224ec1bc]),
        dxy:
            Fe([0x21ccc41b9b63fc, 0x15f3bdda8d0cc7, 0x5793c1988c9113,
                0xb7aefda93810ff, 0x0a821fa9f60a0c, 0x24414b1fbd5c37,
                0xd258371567c3da, 0xb4576206857787]),
    },
    Affine {
        x:
            Fe([0x4a916a58f04261, 0xd46f1d06a61f4c, 0xf6bbd7ccfb0acc,
                0x614536a6af7bb6, 0xf6f7ea71f7e3c8, 0xaa8c5da158d5da,
                0x231787b956f94d, 0xafa3b766cac5e7]),
        y:
            Fe([0xaf4d2cc8681d73, 0xe30ad87a1e5466, 0xf1aea935d0d8f8,
                0x7c6fb14e4ceac9, 0x7aab4ee19e9e5e, 0xe6d2fbf530684a,
                0x1ae48278f7cbce, 0xd38ab9b9105e60]),
        dxy:
            Fe([0xd76a888106e2b4, 0x22bab934a0a924, 0xc1c8ea015036d6,
                0x89042bd2d242b4, 0x1d9e6144c06a55, 0x4a8a23f74c79f2,
                0x4aba3252e4fa47, 0x17344060db0188]),
    },
    Affine {
        x:
            Fe([0x8850b3396394a8, 0xf334b1ba35a0f5, 0x7bcc79d3bf2851,
                0xc675a85f682801, 0x85161a7ce995cc, 0xfa4b9340ace8a1,
                0x5c586a55e9792b, 0xb5a2b8623fbbc0]),
        y:
            Fe([0x390bd447dc5fdf, 0x488422cd024d88, 0xa44eaa7ef0a8e3,
                0x90e0fa13b5f1d5, 0x8b12dd77582487, 0x7b173d46793fa9,
                0x0929caee555c03, 0x2621324eb0a2bf]),
        dxy:
            Fe([0x5e646969ec9757, 0x5bcb810dfd90d1, 0xf901ea62bbeae6,
                0x70c1e950340895, 0xabbf9c6a09b67a, 0xe2d75f3e396f98,
                0x10f266283a0c48, 0x8a6556e002a1c2]),
    },
    Affine {
        x:
            Fe([0xc2725390d35505, 0x7d8fb20e7d6179, 0x9a3dd7c0789f1d,
                0x1cda222b1f9bd1, 0xe990b44b15273a, 0xa0c5ba410c9bac,
                0x7196da0eca2d06, 0x7d6ed9f8530755]),
        y:
            Fe([0x8a798d3808ada6, 0x29252937b2230b, 0x1d21b93b38646c,
                0x0cf409ba06ec22, 0xcac1fe26d8875e, 0xa8de7c1d9dfc4c,
                0x3e3a1063a9f88b, 0x7294918ffacb1b]),
        dxy:
            Fe([0x112196d5b9a633, 0x85f099a1ec92eb, 0x9cb78f653f95e1,
                0xf06424d3ed317c, 0xf5adaac7b17cd6, 0x1535a2f15cd858,
                0xcfea7e84b72b66, 0xa6a8805608f021]),
    },
    Affine {
        x:
            Fe([0x931b68162e2531, 0x43905c85b82fec, 0x0532b5c2cb3aa6,
                0x25be338b278765, 0x06dbbd6a846733, 0xfd08949453fb0f,
                0xe9b2a61f508a3c, 0x53be1718c61ff6]),
        y:
            Fe([0x80037ebe26d515, 0xfe4b617e58395d, 0x0d26d40947e0ee,
                0x57789d1a167f21, 0x99c871cc35afb3, 0x29471bfce0f4ad,
                0xd79c885355f61f, 0x1d432ad74d21ef]),
        dxy:
            Fe([0xadf36042e393b9, 0x5e1645375eab2e, 0x80d6123aaf1c1b,
                0x39838ea57534ab, 0x033ca3a91d6a99, 0x99d3647e868174,
                0x60259be3f8aa81, 0x782f84d06078e1]),
    },
    Affine {
        x:
            Fe([0x2f3954fbae7725, 0xb6fd494571f31a, 0xb16880ddea7682,
                0xb01a4bb7836fa2, 0x2207017ddfb5a9, 0x984831bf93fa05,
                0xb6f685cd685467, 0x822e5d3302a0bc]),
        y:
            Fe([0x5729cecdde55ca, 0x8ac6ba92c3da8a, 0x8f97d6ecb02ba7,
                0xe50b9d84655adc, 0xc9d6e9edd434f6, 0xdddb0d855b166b,
                0x4af3d88a939462, 0xd5c3a88bbe074a]),
        dxy:
            Fe([0x582878fad2de2a, 0x1b43877d6088d2, 0xcf8ea56a43ba5e,
                0x406e43d7b2104e, 0x90a8b78a6065e6, 0xb66ef49e300d36,
                0x382db34bc05cf1, 0x14372095e1f68b]),
    },
    Affine {
        x:
            Fe([0x2d0bb63a82ff2e, 0x119aa2bbc02ea1, 0xddac74a93c493a,
                0xa6a97664650725, 0x97989df4c6102a, 0x2672cfcd434b6a,
                0x423f1e88c9befb, 0x217c65948cf2e7]),
        y:
            Fe([0x758e33624171ae, 0xcd904a16cdfc86, 0x16d7471763d0c6,
                0xa5aadec84deb5f, 0xad262a22fd11c2, 0xc1e2b732e9bc36,
                0x339659af73d9fb, 0xe010f2b14febc5]),
        dxy:
            Fe([0x24468b41e89cf8, 0xefe40355a55834, 0x4b629983951580,
                0xe985a3ea7daee4, 0x54a1b8445bc8b2, 0x440e2fe9eae885,
                0xdc69c99675052b, 0x9be060ac369f9e]),
    },
    Affine {
        x:
            Fe([0xa1d032b94ed889, 0xc70b3abe4cc46a, 0xd9e6e10ba972f7,
                0x2347be388041d5, 0xc714cebaa99cd5, 0x82a5e792732fad,
                0xdc1fa56878e34b, 0xbe2f04ad371908]),
        y:
            Fe([0xb69b0250b19cac, 0x1e7b3407a0baa3, 0xf9ec268c2ba97d,
                0x37a0915feb31d8, 0x2d33e94f8a6e91, 0xc17f6ceaecfa3a,
                0xdc550aa72068ab, 0x8e83527e3678d8]),
        dxy:
            Fe([0x1e0a1f173b2abb, 0x7dd61512152e98, 0x9092b12a1c9e7e,
                0xdb08f4f5431249, 0x1d972ea8b9a895, 0xb68018d9064393,
                0x7db0c04e0b9d62, 0x63a0371ba8b324]),
    },
    Affine {
        x:
            Fe([0xea49b5b34eb3d0, 0x518c0e5c887f53, 0x49d56bd920755e,
                0xdb4e66971aad08, 0x41697a75a5c5c8, 0x621c0a1c717cba,
                0x9038dff01e187f, 0xa068365fb9fad3]),
        y:
            Fe([0x0072d7a6d2b11e, 0x8f8d443528df4c, 0x820953849998a3,
                0xb655d7ce912482, 0xe9a3d75d732224, 0x40170513e02d77,
                0xace164b77ab494, 0xf479f3d5980a07]),
        dxy:
            Fe([0xcc1510e6004667, 0x0d1b5cf7240949, 0x465c728ea5404d,
                0xb09f0590e6942b, 0x23a2517934002f, 0xbcd57dee9c900d,
                0xfd34952625fc5d, 0x92480eeb3805c2]),
    },
    Affine {
        x:
            Fe([0xba10badb15c3fe, 0xc23fd01d788088, 0x0d497c09409c77,
                0xa7c94d8cbfb3b4, 0xa3443a798814f9, 0xe9ef404bf28eec,
                0x4c66bd910af553, 0x6cbc28cbb92c66]),
        y:
            Fe([0x332584a57e5abb, 0xa4ffd901feb698, 0x184df1c99ad307,
                0x6b85309abfd40a, 0x08293594c49915, 0xc6acd6a9545e94,
                0x1d6c8e43b0290b, 0x719c11db419961]),
        dxy:
            Fe([0x4c0ced610ed5e9, 0xbee1c80780e5d2, 0x61e4412de8486c,
                0x635930f2e4b9a2, 0x9c6ce6184ff472, 0x72d2eb81d29431,
                0x60a6726884cb79, 0xdba0774eb68275]),
    },
    Affine {
        x:
            Fe([0x3ef5b31e08f588, 0x0ce2bf814b080e, 0x5a1b6cdffad5b3,
                0x1c325804d4485b, 0x9d4bf152eff0f1, 0xee1cd33f8e7cc8,
                0x1b426813216f1b, 0x68d87ef53ecc94]),
        y:
            Fe([0x9630f4df043248, 0xfc726779425b69, 0xd328fbcd90049a,
                0xd29cd3bda08208, 0xaace4a4a95019f, 0x8d80a6c5a3b9a7,
                0x088d5d36f93947, 0xd66f6010aa935a]),
        dxy:
            Fe([0x8a73be015707f6, 0x99121dd9865897, 0xbbe9a24623e0f0,
                0xfaeb16d107f9f3, 0xd2c035e8a5212b, 0x1f5c39f4e20fbe,
                0x30eb401613e633, 0xde27401deda433]),
    },
    Affine {
        x:
            Fe([0x63dfd559e5dfe1, 0x02f74efc17e62a, 0x0c4f34e4a90135,
                0x0dc6ba02c1d288, 0x0d276e38c30d0e, 0x4fd02d021060a9,
                0xef1e9aaafb9408, 0x01a9e27ffbf26d]),
        y:
            Fe([0x4374e1f0761125, 0x98cbf5b483663d, 0x0eb145a6584a9c,
                0xf01ba6e144fc2e, 0x3d5c6b57d059dc, 0x29654c2b3f128f,
                0x3e8dc73aa68c89, 0xe7e1fce821b355]),
        dxy:
            Fe([0xe9d96e9f7ec532, 0x6c544e6df810ab, 0xd13c747358d330,
                0xf369c3116fb08b, 0x001dfd46f60afb, 0x75d8fa1ad80cae,
                0x9f38518ddc5d20, 0x5e8265e56d7397]),
    },
    Affine {
        x:
            Fe([0xd73ca548e6bb1c, 0x023d483e359a91, 0x8f18c2be8b9ed4,
                0x21c9f7dc689ab3, 0x9de2bc80d39a61, 0x4fdbf4037c9fe5,
                0xc862dfe567d754, 0xd755b743e6126f]),
        y:
            Fe([0xd26e21497e3df3, 0x64cf917d3eee6e, 0x96c17978d33bb8,
                0x9fbef7e098d3dc, 0xcfb5b76dfdced5, 0x09422e09f1af6b,
                0xe70097738fd55f, 0x989e1f6383a18b]),
        dxy:
            Fe([0x72318e538cb32a, 0xd967f89aa0cd7e, 0x47e1c1b2e0af01,
                0x4422df079060e8, 0x18eb8a86c1d8b3, 0x5534d64718be8b,
                0x782e83e4bfadbe, 0xafd9eb8bb32642]),
    },
    Affine {
        x:
            Fe([0x6b06f5374183d3, 0x23e7668a1e622d, 0x5d9a1dbe5078aa,
                0xa42acb42385abf, 0x742f9309c9f1fb, 0x1bc88dc7d794b2,
                0xbf86e5781d2125, 0xfd30f23431bf0c]),
        y:
            Fe([0x0a5bfee5bff8d9, 0x7de81488050246, 0xcabae8cab3a05b,
                0xf8662aac0f0e78, 0xa8e7a539ae6ee6, 0xa2b80812d5e795,
                0xfaa72eaa3bdbd6, 0x2d0a9b30127fce]),
        dxy:
            Fe([0x5002c4cfedf838, 0xa9e3239d6da598, 0x37817a6cd28d12,
                0xf8d4eafd3f5692, 0x8b8d41de17afe2, 0xa215968f010ac3,
                0xe1a4ffaefecf43, 0x500159c54f4ef3]),
    },
    Affine {
        x:
            Fe([0xfca72cc87d5e08, 0xa5527bbc68daed, 0x25b21ec76c0102,
                0x517d7f8e8f4ffd, 0x46e45ce3834d9d, 0xcfafab4efbd1a7,
                0x435f92d2dd0ff1, 0x39b2dab2ccb926]),
        y:
            Fe([0x358022b819bd40, 0xd099538448162d, 0xdf5beeb368888a,
                0x4f05c394e1ce38, 0x00219ec9a58dac, 0xf53a4c41079b28,
                0xc3bdbaf0c91b3f, 0xd11f533b8db40b]),
        dxy:
            Fe([0x039004f45f047d, 0xd66321e6459254, 0xd9fb7a9fbe2d9a,
                0x9957c004f4c83a, 0xc26add8200bc25, 0x48e8d8704b1dc8,
                0xc5ea9131dfb953, 0x4f92d7da423c3c]),
    },
    Affine {
        x:
            Fe([0x8f644e0e47a686, 0x564b9f071864c2, 0xfe723228440f45,
                0x614b358ab65d98, 0xfbe7f401c3604d, 0xdb243c043845d8,
                0x89bbd45678b648, 0xa5072866144fa6]),
        y:
            Fe([0xd53f6c9b4b7ea0, 0x665d5dcfef51f5, 0x33f7f91ed9ee7d,
                0xe10b201101b599, 0x74ed1fd4058370, 0x247fcc93418bd3,
                0x657cac72daa774, 0xfc45811d2ea291]),
        dxy:
            Fe([0xec1a95219187a6, 0x58930b50507e43, 0xaf2c30203e9858,
                0x8f7d135bf6ddf7, 0xd162edcc87b3bc, 0xdbafdb7696135c,
                0x50ffbbcddeb6f3, 0x53b51d6e88434d]),
    },
    Affine {
        x:
            Fe([0x215fdf0ef37fa8, 0x0f713880be630a, 0xc6afcfcfdf53f5,
                0x175f6ad289daed, 0xaf6d861ad0f357, 0x007652b472c86c,
                0xc438485fe495e4, 0xd05b56c4046303]),
        y:
            Fe([0x4322eb9e3af569, 0x92bfbe6f1668a2, 0xdddc18351d2518,
                0x7fe0e653aa9c27, 0x5e231910cc667b, 0x3421cb9b5d4263,
                0x018660fa0dcad0, 0x1640e6d0a83bbb]),
        dxy:
            Fe([0x92d5d7cfbb191d, 0x46a3e7b985c83e, 0x07f765315fa965,
                0xbefba6ec9ec7ae, 0x52b8e920f0fceb, 0xc979165f7724ac,
                0x1738d2d28e26da, 0x524279a8607c89]),
    },
    Affine {
        x:
            Fe([0x1525bd043563bf, 0xa581438253afae, 0xfa8371ce2c31e4,
                0x89fd5e86825787, 0x200913b703d15c, 0xedfb7b6896c58a,
                0x9b1698f381b504, 0x68d1d84c05a2b8]),
        y:
            Fe([0xb4f175840267d2, 0xc04fdc854b7df9, 0x4e8ccaf9be9b08,
                0x2e9ffa6f733255, 0x8309e94bcc500a, 0x2706de467dba5d,
                0x955a660fb47570, 0xa9d859731f170b]),
        dxy:
            Fe([0x2ffc7abb80d636, 0xf695cee6fe7b55, 0xfe039cf6ca0621,
                0xa46e2ec0c67452, 0xddfd8b9ff67f55, 0x136bf879f4f048,
                0x83743e238d9f7e, 0x7f7d5e0c3930c1]),
    },
    Affine {
        x:
            Fe([0x671a6ca21b3052, 0x72d54fc84f09b9, 0x93dc20af2183ba,
                0x75569b5b6ddf3c, 0xc7c5a0adf14a40, 0x8e0650ccd87baa,
                0x107916f1adafde, 0x90b20913c7551e]),
        y:
            Fe([0x9b412639d4ca69, 0x5187c1b349910b, 0x145a6974e12030,
                0x90831066edb041, 0x7f704bac9c8068, 0x65debb81b934b7,
                0xf43c2f27ef8c17, 0xc162616ba8d6f9]),
        dxy:
            Fe([0xa45d4b18181272, 0x529f54ac2e8afc, 0x53dbc5bf7d664f,
                0x11a4417271f78b, 0x9786129f404690, 0xad42724eaf3d68,
                0xa6148b688c5c11, 0x72d7e9daa2465e]),
    },
    Affine {
        x:
            Fe([0x07cae5a100cb82, 0x14ddcb20c21df9, 0x34097da5df3a0a,
                0x3b9ffe83698455, 0x400a184e9d6ee3, 0xba78430ce12354,
                0x3eb4c1257e6ce6, 0xa84d49cfd043df]),
        y:
            Fe([0xe9d9f2e55a355e, 0x223d8e0ca7884e, 0xa52b5ff649a87a,
                0x62ec5adcbf1f78, 0x02044fa17c9108, 0x63f3e18339d31b,
                0x7294efbfa59c3d, 0x7d2191d8d7fbbb]),
        dxy:
            Fe([0x45c0e1de1e242a, 0x42b0491ce4489a, 0x2e6ff9071843c5,
                0xb7274cae16d33b, 0x0d9f77c618af8d, 0x6202dd05cff54d,
                0x4b3fe0684fc551, 0x740ff0027cf779]),
    },
    Affine {
        x:
            Fe([0xfa87df7e2b1a27, 0x67578b710b9447, 0x0c600a6faa23ba,
                0xa55317581c8725, 0xdb301264cc313e, 0x6d114df5a123c5,
                0x5c5c02013a5f76, 0xc3798f4399cdf5]),
        y:
            Fe([0xc7d0eda6363c33, 0xc73499a7437e06, 0x54150dfc1e76fc,
                0xeb03f10b39ea5f, 0x72c23a096c36c2, 0xdc8a40ccaf4cad,
                0x68ffaba7ef62a0, 0x5eaab0486fdd7c]),
        dxy:
            Fe([0xf5791f44ca779e, 0xccbb07a1051a59, 0xe44f3d0e547e03,
                0x7a0686042b82a8, 0xbbf18439a22d51, 0x487ff76bf0a914,
                0xc1f3025ab1c6ee, 0xb893ef7c27d018]),
    },
    Affine {
        x:
            Fe([0xe01ce4c01f77bb, 0x079cf33b26053c, 0x28c6594e0dd9e5,
                0xd12ec730ead4a8, 0x870f40f7f16ae7, 0x02dfc9f7bbe2d9,
                0x4df444600dd7fa, 0x51197a1d569239]),
        y:
            Fe([0xfbfdb853340c25, 0xf8421b4f7e29d6, 0x6ac5fcee8688c9,
                0x106723f7ff4e96, 0x265519263bf77f, 0xbc95788a5a41cc,
                0x0a11891479815e, 0x07761bc4c9df13]),
        dxy:
            Fe([0x21519397827082, 0xd50adb6729c8a2, 0x9aa5f44a40428c,
                0xa7b06ec4a59d74, 0xb824eefeb12927, 0x72e0d2159bc4ac,
                0x3c03db56bfc0d2, 0xca6c044dee11fe]),
    },
    Affine {
        x:
            Fe([0xcbdbee8018024d, 0x14ae8c0b5460ca, 0x8daf77418a22df,
                0x2aef7a5f86363b, 0x6c0986f68068ca, 0x6e071dc4818fc5,
                0x8cb49cf56843dc, 0xd2d3b5ed3a206f]),
        y:
            Fe([0x64410ea454c610, 0x705147a9c13778, 0x484b9cab2d5ac2,
                0x6eda06c546c9c8, 0xef3709b4fdac87, 0xf64b614ade72f6,
                0x9a62a37396d685, 0x569981560c972a]),
        dxy:
            Fe([0x9a72429e8f9d0d, 0x794c610be24965, 0x29302e9d6162ae,
                0xe534e801c3953f, 0x03ea6c83eb837e, 0x91adbdf1a19fee,
                0x64389184d86fde, 0xcefd0a2672b65a]),
    },
];

/// The odd multiples B, 3B, ..., 63B.
#[rustfmt::skip]
pub(super) const ODD: [Affine; 32] = [
    Affine {
        x:
            Fe([0x26a82bc70cc05e, 0x80e18b00938e26, 0xf72ab66511433b,
                0xa3d3a46412ae1a, 0x0f1767ea6de324, 0x36da9e14657047,
                0xed221d15a622bf, 0x4f1970c66bed0d]),
        y:
            Fe([0x08795bf230fa14, 0x132c4ed7c8ad98, 0x1ce67c39c4fdbd,
                0x05a0c2d73ad3ff, 0xa3984087789c1e, 0xc7624bea73736c,
                0x248876203756c9, 0x693f46716eb6bc]),
        dxy:
            Fe([0x6a7c93790d43b1, 0x85ee44c273b40e, 0x961292e5164ae4,
                0xf1ce00e83a6626, 0x11129e5cb41037, 0xf4d1b86e904781,
                0x675b8a5541c3fa, 0x26afa9e48a9aa1]),
    },
    Affine {
        x:
            Fe([0x28173286ff2f8f, 0xb769465da85757, 0xf7f6271fd6e862,
                0x4a3fcfe8daa9cb, 0xda82c7e2ba077a, 0x943332241b8b8c,
                0x6455bd64316cb6, 0x0865886b9108af]),
        y:
            Fe([0x22ac13588ed6fc, 0x9a68fed02dafb8, 0x1bdb6767f0bffa,
                0xec4e1d58bb3a33, 0x56c3b9fce43c82, 0xa6449a4a8d9523,
                0xf706cbda7ad43a, 0xe005a8dbd5125c]),
        dxy:
            Fe([0xcd3a416e267a3a, 0x884610e5c7d816, 0x7e3e42f4031129,
                0x0d31d305649240, 0xacf4198379c2b4, 0xc41bda309ec353,
                0x10037a60e8dfc2, 0x4f44d997609bbb]),
    },
    Affine {
        x:
            Fe([0xa99d1092030034, 0x2d8cefc6f950d0, 0x7a920c3c96f07b,
                0x958812808bc0d5, 0x62ada756d761e8, 0x0def80cbcf7285,
                0x0e2ba7601eedb5, 0x7a9f9335a48dcb]),
        y:
            Fe([0xb4731472f435eb, 0x5512881f225443, 0xee59d2b33c5840,
                0xb698017127d7a4, 0xb18fced86551f7, 0x0ade260ca1823a,
                0xd3b9109ce4fd58, 0xadfd751a2517ed]),
        dxy:
            Fe([0x6c3e8e1f5bb305, 0x7034f02b36b2e0, 0x2d67133823c705,
                0x3ae3e790f84b33, 0xe6491f542ca451, 0x4b251a66a8a9db,
                0x7aae0cf80dce8e, 0x67fe268fc13b32]),
    },
    Affine {
        x:
            Fe([0xdf9567ceb5eaf7, 0x110a6b478ac7d7, 0x2d335014706e0b,
                0x0df9c7b0b5a209, 0xba4223d568e684, 0xd78af2d8c3719b,
                0x77467b9a5291b6, 0x079748e5c89bef]),
        y:
            Fe([0xe20d3fadac377f, 0x34e866972b5c09, 0xd8687a3c40bbb7,
                0x7b3946fd2f84c9, 0xd00e40ca78f50e, 0xb87594417e7179,
                0x9c7373bcb23583, 0x7ddeda3c90fd69]),
        dxy:
            Fe([0xfae64438edf0d0, 0x25186aa89f8084, 0xb4bbc907a54de8,
                0xe1e5f106f60ee2, 0xdae6ce2338fdd5, 0x340f5f4bcf6588,
                0x796abe2815418a, 0x6b8be3ae56f3ca]),
    },
    Affine {
        x:
            Fe([0x3d0def76ab686b, 0x1a467ec49f7c79, 0x3e53f4fc8989ed,
                0x101e344430a0d9, 0xa3ae7318ad44ee, 0xaefa6cdae1d134,
                0xaa8cd7d824ad4d, 0xef1650ced584fc]),
        y:
            Fe([0xa74df674f4754f, 0xf52cea8ef3fb8b, 0x47c32d42971140,
                0x391c15da256fbb, 0xc165faba605671, 0xf2518c687993b9,
                0x2daf7acbd5a84d, 0x1560b6298f12ae]),
        dxy:
            Fe([0xb1f14701b36165, 0x221c7d6637dd60, 0x41228a0d3d6770,
                0xe7afa4b2c05d30, 0x7a3dac09c3da0e, 0x38174ec8dff1a7,
                0xfebc126c03f1fe, 0x25e7aaa8ab328f]),
    },
    Affine {
        x:
            Fe([0xef4da0254dc10a, 0x63118655940db8, 0xe20b14982f2948,
                0x67b93775581dba, 0x422ee7104f5029, 0x5d440db5122d34,
                0xb1e56d71a4c640, 0xbf12abbc2408ee]),
        y:
            Fe([0x0cc9f86016af01, 0x88366abf3d8cab, 0x85dda13a2efe12,
                0x390df605d00674, 0xf18f5806d187f7, 0x28c900ff0c5d20,
                0xad308123e01733, 0x42d35b554bf2fd]),
        dxy:
            Fe([0x3d0b9089f16d84, 0x86a8fcd5d6631b, 0x66d095f43e566d,
                0x6a227455a5e307, 0x5be52de8d4c06d, 0x7fba0112453f9c,
                0xd34b8d0c0726d9, 0xbf233049e130fc]),
    },
    Affine {
        x:
            Fe([0x009135f2ffb1f1, 0x099fc7e8f9c605, 0xcc67da626bfa5a,
                0xc186d12344552b, 0xb5232501b339e1, 0x70a544fc9708c5,
                0x06baaec1e928e7, 0x0baedd2ef0f50f]),
        y:
            Fe([0x535d6d8bf479e5, 0x156e536e4ec3e9, 0x3165741ddb9be2,
                0x988af7159fd736, 0x13d8a782e33ddd, 0x54604214e69002,
                0x34d56e0804a268, 0xc59b84f0e52a4c]),
        dxy:
            Fe([0x2589550573fa9f, 0x0ca8f32a4e2d3c, 0x94668cded1429f,
                0x64da4a881285b4, 0x472f79ff2c3830, 0x9ec7af724a1439,
                0xab3e221cfde20d, 0x5a5aa306a43ff3]),
    },
    Affine {
        x:
            Fe([0x525d45f24729d9, 0x5768aba8712327, 0xa25e43b43035db,
                0x15a1ee8927ef21, 0xa785d216056112, 0x45e2fbfd508af9,
                0xb6f721a37ba969, 0x30d6d8c216d8d3]),
        y:
            Fe([0x3065e0852074c3, 0xfa40b4a2a0684e, 0x851325a763f955,
                0xd4ef19c9f25900, 0x799c869f665756, 0x7b052223312990,
                0xc986c2b28db802, 0xf48fb8f28ade0a]),
        dxy:
            Fe([0x5f3c04dcf5e88e, 0x914d896e4eb0ea, 0x6a53e17ac9ef1e,
                0xfc9849c2f49da0, 0xeafc74b5b564c6, 0x47422705f183f3,
                0x15c3619c2a76fb, 0x30ffa3268750bb]),
    },
    Affine {
        x:
            Fe([0x1e461731649b68, 0xa96e5d65beb9dc, 0x765ddff481935d,
                0x6cf132c9f3bf2a, 0x9f6c5c97c35658, 0x99cd1394696e60,
                0x99fa9249c0d5e4, 0x1acd0638845a95]),
        y:
            Fe([0x0b065413636087, 0xea20e78ea17b7f, 0x20afc5f6161967,
                0xfd6c8a2dc81028, 0x4ef1357e32c8fd, 0x8aa400400e4a88,
                0xd6fcaef48cb82f, 0x7ba7c6db3cd4fa]),
        dxy:
            Fe([0x22e32644f7ab67, 0xd46236a6e7892a, 0x2317a18055d318,
                0x2c7e77deb6f9a4, 0x670503362f5ad4, 0xb084e681980175,
                0x60311f518227bc, 0x8301487e64f361]),
    },
    Affine {
        x:
            Fe([0xf843473d19c7ab, 0x968e76dc655c4d, 0x52c87d9c4b9c2f,
                0x65f641ae4aa082, 0x491a39733c3603, 0xa606ffe5810098,
                0x09920e68bf8ad4, 0x691a0c86db7882]),
        y:
            Fe([0x5205883a4d3ef5, 0xee839b7acf2efe, 0x4b78e2ac00ca66,
                0xbe3f071f9fcb91, 0x61e66c9bf6943a, 0xe9b4e57061b79d,
                0x8d1b01b56c06bd, 0x0dfa315df76ae5]),
        dxy:
            Fe([0x859854d74126a2, 0x6ffaac6e5b9176, 0xcfd26c8d65bf6c,
                0xbda60569230bf3, 0x1bb15f503565dd, 0xd3d9b86412da57,
                0xc9d8fcd1768b5a, 0x2b8a6b978e2866]),
    },
    Affine {
        x:
            Fe([0x803df65f1fd093, 0x1cd6523489b77e, 0x2cd2e15c20e295,
                0xcd490be9b912d1, 0xdd9a2ff2e886d2, 0xa3c836dfe9d72a,
                0xfcad5f2298e0c1, 0xed126e24bcf067]),
        y:
            Fe([0x1e339533dc81bc, 0xbea4d76ece6a08, 0x1d15de3991b252,
                0x74cc5cfe6daf97, 0x5ad343f0826493, 0x2d38a471064049,
                0xf7f47b9ffcfa4d, 0xef14490418066c]),
        dxy:
            Fe([0x224ac48e9604d6, 0xfa9cd56fefd1b1, 0x05068f5acc111f,
                0x1fcfd0f80f5887, 0x96253f72e8f81a, 0xc078e6092bd63a,
                0x9a0fde6afbd73c, 0x3287d217218a51]),
    },
    Affine {
        x:
            Fe([0x4e7f86b9bb55ab, 0x310d7853f496a3, 0xbd682fc0dec42c,
                0xbde047a411d32a, 0xea639b4c5a5ea2, 0x5052078ba08fa1,
                0xc968b2307729f2, 0x567b5a623d3e28]),
        y:
            Fe([0x171e825977fbf7, 0x0319c70be990aa, 0x8f65023e12cd69,
                0x1fb9b19f5015e6, 0x0083f603568a7c, 0xba3d30b1f3c5ac,
                0xe7b509d3d7a988, 0x2318b99cd0f6b6]),
        dxy:
            Fe([0xbc458864775926, 0xb8d5aa373c17d1, 0x642859a3656660,
                0x2e39e16f0e09f9, 0x8be000b69fac69, 0x0d3bdcea0da5c7,
                0xcec468f21b6ac0, 0xb2323ae35fe3b8]),
    },
    Affine {
        x:
            Fe([0x54d3b8793ab2cf, 0x366abead2d8306, 0x66e8eb6d7a4977,
                0xa61888cae0072e, 0x9eeeef5dbc3315, 0x93f09db163e7f5,
                0xee9095959ade9a, 0xaf7f578ce59be0]),
        y:
            Fe([0x24bfd8d5ece59e, 0x8aa698b3689523, 0xa9a65de2de92cf,
                0xec11dbca6ad300, 0x217f3fa09f88ca, 0xf6c33e3b4d6af7,
                0xcd3bfa21d86d2d, 0x1497f835f13f25]),
        dxy:
            Fe([0x4d6d5b5d82a175, 0xa3df933803b017, 0x6a7ea028b677bc,
                0xb85b73558f1039, 0x5018b68653933e, 0x513d8bfd43533f,
                0xe7ef245f92f57c, 0x42a88d0089c768]),
    },
    Affine {
        x:
            Fe([0xa579568cd03d1d, 0xd717cdae158af6, 0x59eda97389a19f,
                0xb32c370099e99c, 0xa2dba91dabb591, 0x6d697d577c2c97,
                0x5423fc2d43fa6d, 0x56ea8a50b382bf]),
        y:
            Fe([0x4a987bad80c11a, 0xe4cde217d590a5, 0x3dd8860f97e559,
                0xff45e2543b593c, 0x00eb4535343cb5, 0x06b9b997bbfbdd,
                0x4da36b716aea24, 0x247651757a624e]),
        dxy:
            Fe([0x6041be82e08b08, 0xe615965b274181, 0x9030c446c78f1a,
                0x67e3ae5166db35, 0xac4f1732ab7922, 0x638b00f37f1b00,
                0x7d743f9391411d, 0x32301a15159b6f]),
    },
    Affine {
        x:
            Fe([0x32207d03474e0d, 0x3ffbf04b41cc73, 0x5c4dc45319eb39,
                0xfee29be758b463, 0xcc8a381c30c7a7, 0x147f4e49fe0e53,
                0x05b2e26e35a2de, 0x4362f0292f3666]),
        y:
            Fe([0x0476d0c8474b85, 0x9d8c65fccaf108, 0xf58d4041d54b6a,
                0x3ee6862f38e4b0, 0x7c7c9d53b44f54, 0x36a3fd80fb0db5,
                0xfcd94ba18a8ac8, 0xc1b1d568f35c05]),
        dxy:
            Fe([0xff2fa41b3c9465, 0xba99725e890c94, 0xcfc83ced0ee62c,
                0x1b7cd289d67670, 0xffed769f6d60e6, 0xb628230ff6ce11,
                0xbed12d87ae9228, 0x6e38f5c3a64bfc]),
    },
    Affine {
        x:
            Fe([0x16539fc1bdd30d, 0x1356e538df4afb, 0xc0545d85a1aedb,
                0xeb2037a489396b, 0x897fcbd5660894, 0x02a58a9b7d104a,
                0x57fa24cc96b980, 0xf6448e35bd8946]),
        y:
            Fe([0xee727418805c83, 0x10fa274992cfc6, 0x95141939e66b21,
                0xe0ffa44bd08009, 0x174332220da22b, 0x4891ff359e6831,
                0x407ed73a7d687b, 0x2fb4e0751d99cf]),
        dxy:
            Fe([0x2c5231921b3943, 0xd324d5e5e27106, 0x8675389c370119,
                0xcb2dc4613725a6, 0xf8c7ffaeed73d3, 0x75f566b1a0a6a3,
                0x4df7efe5e0ff1e, 0x21b7f2716d6038]),
    },
    Affine {
        x:
            Fe([0x28fe9a19fddd5c, 0x97465a7806e585, 0x7664623b1f2b32,
                0xd039042595afb8, 0x2bb046211b3e22, 0x9e85c2c408d2a7,
                0x344e49517df43a, 0xaf43becc7ff796]),
        y:
            Fe([0xdc0a8bcd4ebc11, 0x4fc7aaf16ed146, 0xe6a0b13ff05f9b,
                0x43576142f3d6db, 0x981a64decbb562, 0xeef29d40f4b1d8,
                0xdb70deb638afa8, 0xd24e162932cfa4]),
        dxy:
            Fe([0x0e472b2067a2cb, 0x5c76c001b1c3a7, 0x891df119b1763f,
                0x0a2b2e627b1826, 0x5bcfea60be72a1, 0x1457073c458572,
                0x21b08b8226a659, 0x0ecf376f68de6a]),
    },
    Affine {
        x:
            Fe([0x0b042893594dbc, 0xe77c26ebb2748d, 0x21dfad2eaad3f6,
                0xcfd0d30f9ccf65, 0xf788803e0a87e1, 0x771179c2a1d36e,
                0xb2540021df6dde, 0x38b1101fe169d9]),
        y:
            Fe([0x3e35031020e6d5, 0xbe9da3e3ad034c, 0xc1b838132076fa,
                0xfaa7e368e528fd, 0xb0a24e3ed08943, 0x530e806f928cf3,
                0x822ad94c532216, 0xceec2542a16f7d]),
        dxy:
            Fe([0x2d68d3bc707c0c, 0xee9d60c7584d0e, 0x6dc970878c11af,
                0xb3b5bf0f045d7b, 0x21c32c7efe1f61, 0x681eee78d1d080,
                0xf8120ffae6a0ac, 0x89bb1891d9125c]),
    },
    Affine {
        x:
            Fe([0xa5f90cb22fe0e3, 0xd7745d47cbcc76, 0x632c369e3cd3a0,
                0x62a3d19b0e4964, 0x2be16a878cedf0, 0xfb9fc428e89e37,
                0x3ea4386f5ba770, 0x8e29fa077d892f]),
        y:
            Fe([0x73f37081796a3f, 0xbc891f73265b11, 0x95f99c09062029,
                0x2f0f8ac2b5c099, 0xd2e662dbf07d3c, 0xb2fe0dcced00c2,
                0x61c9877329acd1, 0x25745a1868751e]),
        dxy:
            Fe([0x14e6baf1205ede, 0x5f1841eb17c5a0, 0x487f0aba3fed1e,
                0x6f6f722f855b86, 0x31598b2fea923b, 0xdb2383c68f87c6,
                0x7f19a4b87ece09, 0xe4a4e1a9712bf8]),
    },
    Affine {
        x:
            Fe([0xdbd3f50e6d5715, 0x06f28cefd63beb, 0x26c18cafeaaab6,
                0x25095d89223968, 0xb0663afcb3db71, 0x584777bd49b672,
                0xdf8f32ca7bfbfb, 0x345d827608a6f7]),
        y:
            Fe([0xbc8f551eaa2d6f, 0xd87733f9f97519, 0x49796e72d5aa4c,
                0xca71088b56aed4, 0xdb2559c58fbc88, 0x15c2809d88c39b,
                0x7d82238655c425, 0x03a7ddd0efea59]),
        dxy:
            Fe([0x7ef254047f30b0, 0x43d2dfe3d09a94, 0xd451f2bb72c93e,
                0xe960c6d4767197, 0x8d2b9e429370a2, 0x566a98db8ad8e1,
                0xef13aea99b6814, 0xc82559816d8c6a]),
    },
    Affine {
        x:
            Fe([0xb4b57d8534b2dc, 0xe1ed5cda4a100f, 0x31113bb3e5339c,
                0x164cf57325cabf, 0xcb03b33d90dd61, 0x418d6e8433c1d9,
                0x87ea17315d2171, 0xf58639927b199d]),
        y:
            Fe([0x983df6472fe75f, 0xd74d3b3143c792, 0x0515ff15ac1194,
                0xc81fd36be998ab, 0x394ce30274523a, 0x6f2db56ee878b5,
                0x7095c78c079ba0, 0xf4d9b63d883a8b]),
        dxy:
            Fe([0x08390435511afe, 0xe8b09a9d0ee40e, 0xad122289960606,
                0xfdaa3473ae2c04, 0x966035de8946c9, 0x4ca6cae89b2ef8,
                0x0827ecb285fe94, 0x1e328769fe63bf]),
    },
    Affine {
        x:
            Fe([0x2ce1ceec68b381, 0x2bbc4dd7ed6a06, 0xcb1fa4f5098e1b,
                0xe3efa096b49dbe, 0xb26f08321635e2, 0x874aa7f5482b24,
                0x8e09b7c43d8adf, 0x82cec9e535be31]),
        y:
            Fe([0x89867c5762ef27, 0x45308341da8d9f, 0xc134a3256b5057,
                0xe7ffcc79bbfee7, 0x9ead533fb87aed, 0x609bc810a8670a,
                0x6d47c9578c2f92, 0x610106c3a23b2f]),
        dxy:
            Fe([0x06afe833f5aad1, 0xf5ca87bbd68709, 0x450b66dda23f26,
                0x8dc89eb78e6636, 0xf2887d12a37e6e, 0xd30996b4ac01b7,
                0x2767879395d00d, 0x2160332bc81554]),
    },
    Affine {
        x:
            Fe([0x0fb2915a8f9b51, 0x57246409bbc1b6, 0x248692879b1ab9,
                0xb6e0e7e10bb783, 0x33d08dcfc00cf5, 0xf86216d661df90,
                0x42aca489867cdd, 0x4493669d991307]),
        y:
            Fe([0x290cee1d3883e5, 0x0d10fd9081ba17, 0x74873045609777,
                0xd86e08c4617716, 0xa751fe6ef0b9ee, 0x39f297e8778124,
                0xe335ac2a5edc1c, 0x3835340df3953c]),
        dxy:
            Fe([0x41e35e1dcae6c5, 0x0e3de2055b0c71, 0xb52bdb5270614a,
                0xa21de8b27c60ff, 0xad06ae192c8709, 0x2468680d7641dd,
                0x8ac4ad3427e371, 0xec9c72f124bc05]),
    },
    Affine {
        x:
            Fe([0x9723e5612fb476, 0xa318339953e8d4, 0x99e1cfba3081aa,
                0xd73d42559f50ea, 0x2233db5ca03062, 0xdd22a3cf8dd1a5,
                0x9fb95897477ab5, 0x8d8ee4d5730939]),
        y:
            Fe([0x3bd8cc78e124e7, 0xc354b8be52e91c, 0xe817bde21989e7,
                0x45ae87523415ae, 0x86796c01e858ef, 0xb52b74d91de477,
                0x36fcb34b71ca3b, 0xff919b179ac5af]),
        dxy:
            Fe([0xb62fc27a368fd1, 0x0a95b8c4af6979, 0x8f4dcd6bdf4b63,
                0x381305f6a51353, 0x17e1e03bf1e755, 0x8debefe7b54504,
                0x753a0bb7dd7f6c, 0x4634c16a924b47]),
    },
    Affine {
        x:
            Fe([0x988777c589f23f, 0x7e03ebb38e5f60, 0xa8395343ef1bc3,
                0x05927a20a5b151, 0x6674c1506a8be1, 0x22a0f830ff621f,
                0xdcc8c98017ce5c, 0x7e67d43be1f8b8]),
        y:
            Fe([0x47f225e6a75022, 0x0e24bfcdd139a5, 0x5240cc49468acf,
                0x150e1112505c52, 0x040a3cd1f01a3f, 0x88f99331c59f67,
                0x38a1f6232c28dc, 0xddd051d9bd21e7]),
        dxy:
            Fe([0x809ce9974609b2, 0xbde30e4c120092, 0x5c1792921af3de,
                0xa4a1ead810b707, 0xe7bad29644b2b1, 0x34bfe010a31205,
                0xd5d62ac74bda44, 0xc6434ea01912a4]),
    },
    Affine {
        x:
            Fe([0x9450cf29ad359b, 0x2ddb90aa9b0d51, 0xf02751201ae17e,
                0x7193dfeb00a82d, 0x17e7bc0acc3ab3, 0xee5d4718e5ecfb,
                0x27c3515b8270d1, 0x0de63ae99bd14e]),
        y:
            Fe([0x4a598f28249e44, 0x49d7ebdaf223d7, 0x2ab103069d296f,
                0x8320e007ad3c1d, 0x7183549516e3f2, 0x16e55c3a61ea38,
                0xc53e1dafd9c257, 0xb2f724bcc555a2]),
        dxy:
            Fe([0x152f0bba6f2261, 0xe93914ffeeac33, 0xe366f2f0d229a7,
                0xaad26e14dc2ed2, 0x44309e7d49489f, 0x335c3976cfbfd0,
                0xf67e148ff6ce5a, 0xcc4c5945c05b5b]),
    },
    Affine {
        x:
            Fe([0x0c71e4c119cafe, 0xe3124c0967c7e2, 0x3c3c4ead7a64f6,
                0xa762eadbeb0a92, 0x53a7b04dea0340, 0x610c73053626ec,
                0x561020263a7599, 0x347f4a6f21338d]),
        y:
            Fe([0x0cde258e05fe41, 0xf39fcfe4573fa8, 0x8d99e1b21d37de,
                0xa5324747fabdc7, 0x7a86bee510f5fe, 0x7c69a8d639e204,
                0xfc46fa75b59d4f, 0x2d7eca208b38de]),
        dxy:
            Fe([0x2cf1d74e03e300, 0xab5bcbc5bf50fe, 0xda5e86c6d75ef0,
                0xa8e63cbe559098, 0x39778e4b91fb51, 0xf0f5802f7729e2,
                0xd065dbf0b6198c, 0x6f5ed2970dc3dc]),
    },
    Affine {
        x:
            Fe([0xf09d3f9778807a, 0x3c6fa9c7dd55e8, 0xfaf6594671e65e,
                0x5462bd46fd032e, 0x2ba7d8212bef7c, 0xc59b7305f14acc,
                0x587214106d1812, 0xccba96bd1ba70e]),
        y:
            Fe([0xa761542aed44ea, 0x39463b24bef73c, 0x9991265ea5732e,
                0x5325946db19f30, 0xb8a36168dd0a2d, 0x91f519db0c5995,
                0x53db6e99820e65, 0x2d6c8245ade621]),
        dxy:
            Fe([0x1296e126ca13ad, 0x0e3bd8214df1a0, 0x4bbb12e863175c,
                0x006089e7e990fe, 0x63c0d27e9e4b77, 0x83e23d87789c69,
                0x3236a6696991bf, 0x8d00094ff9d0d4]),
    },
    Affine {
        x:
            Fe([0x4eb9ed57f228ac, 0x1b715a16330d77, 0xe65c6d512dba51,
                0xed2975ca2513d9, 0xaabad5af19ae56, 0xdb9922086d15eb,
                0xbbe60e9e6bd689, 0x32c9dc27c15e6d]),
        y:
            Fe([0xd9d801a15f74ac, 0x5f5c914a207d53, 0xd59fae8a61244f,
                0x3ac755ff21511d, 0x8c5717ba3346d6, 0xf32d3941b5590a,
                0x28b836528b5c46, 0xa46ff5121b4be3]),
        dxy:
            Fe([0xa0768e9002fe73, 0xeb6d5c6d7ed4a3, 0x2b8599fe5363b2,
                0x5299a3a3471a8b, 0x3dda2a7a4b0219, 0xc2f69e7a3255e8,
                0xe02b7cccdcc749, 0x603d342bbd6e48]),
    },
    Affine {
        x:
            Fe([0xd503ec291a6344, 0x1d7a800adc5405, 0xe76a71296fd5df,
                0x4125f3feba9ed9, 0x445b1ead4b236a, 0x52dd82265857fc,
                0x885f4b0b42e30f, 0x823d8b938cdb17]),
        y:
            Fe([0x585b31cf15fc92, 0x58c4c3e8e2ff75, 0x9513e1952e643f,
                0xd1c810bea83c83, 0x0440d9501effe1, 0xcc0dcb1084a258,
                0x0af1171d2db8f0, 0xe4776d9572e689]),
        dxy:
            Fe([0x7bc507cc21cc80, 0x3ba5ca12664374, 0x2e7637246b83fa,
                0x26decdf33fcf7f, 0x88df2008db1a8a, 0x9fff633281a993,
                0x01cae9ab892a0d, 0x0a0192bb59f0e7]),
    },
    Affine {
        x:
            Fe([0x3d7c2fa081f089, 0x77f9758e350512, 0x66f11142f1b3e8,
                0xc522f2eb75b61a, 0xba4324a24bf948, 0x1d7bdc193b4483,
                0xddcdf0697a9530, 0x53e5b08548db2d]),
        y:
            Fe([0xc4db59da1e20c8, 0xe5fbf1c92baacd, 0x087365edf49c3b,
                0x63abfb3f97a2cd, 0x53fca78bfeac94, 0x1e22ca7325fec7,
                0xd44ebc893ba993, 0x9184a24f36231e]),
        dxy:
            Fe([0x05dc9eecc11fa6, 0xf2535d107ab993, 0x834663b9258118,
                0xb3e78b6207aabc, 0x252b01d2cf5a8e, 0x74b610b66696ef,
                0x0891ebfdac226c, 0x0c0fc9c70af10b]),
    },
    Affine {
        x:
            Fe([0xf0980efb11b585, 0x4ae326bbe3da69, 0xebdf13c1385a47,
                0x2f0fc0c1805e54, 0xecbb2a7a1316d8, 0x78889268830e5d,
                0xc5c8c7474190cf, 0xed2b6bcd3363d8]),
        y:
            Fe([0x3d9b2a7a5e38da, 0x4ff4c8e952b915, 0x75e15c45616b5e,
                0x7fd8157bc8cf8e, 0x8e560d471d4374, 0x37c2a777924db7,
                0xd290ab6aff28bc, 0x900bd03032885e]),
        dxy:
            Fe([0x8c4a73eea4d518, 0x295782c2d7dcd7, 0x0b6f167f2fffe2,
                0xc5d56694308422, 0x7e88b9afcff0bf, 0x0fdc5c6aaf4408,
                0xab8ca5df2dc546, 0x031793cc4da5aa]),
    },
];
