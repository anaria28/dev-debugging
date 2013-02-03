#define NOR_FILE_SIZE         0x1000000

#define NB_MAX_FILE_ROS       30

#define MIN00                 3083652
#define MAX00                 4867070
#define MINFF                 1748186
#define MAXFF                 1758252
#define MAXOTHERS             83886
// Liste of structures used in NOR Dump Tool code and its includes

struct DatabaseMD5 {
    char       *Type;
    char       *Version;
    char       *MD5;
};

struct Sections {
    char       *name;
    uint32_t   Offset;
    uint32_t   Size;
    int        DisplayType;
    int        Check;
    char       *Pattern;
};

struct IndividualSystemData {
    char *IDPSTargetID;     // 0x02F077 (NOR) 0x80877 (NAND)
    char *SKU;              //
    char *metldrOffset0;    // 0x081E (NOR) 0x4081E (NAND)
    char *metldrOffset1;    // 0x0842 (NOR) 0x40842 (NAND)
    uint32_t bootldrSize;
    char *bootldrOffset0;   // 0xFC0002 (NOR) 0x02 (NAND)
    char *bootldrOffset1;   // 0xFC0012 (NOR) 0x12 (NAND)
    char *MinFW;
};

// http://www.ps3devwiki.com/wiki/Talk:Revokation
static struct DatabaseMD5 RevokationMD5[] = {
    {"trvk_prg", "4.31",       "7B84CFFB3DB4DB6C4F2ED264C5C413B0"},
    {"trvk_prg", "4.3",        "38F41739F715A890598F3523FB56130C"},
    {"trvk_prg", "4.25_DEX",   "7543C580101650016F52D921BB3D9C4E"},
    {"trvk_prg", "4.25",       "7251547BB7C1F60F211FF991BF88083F"},
    {"trvk_prg", "4.21",       "D27D88B0FA283458896439924C1364D1"},
    {"trvk_prg", "4.2",        "06B819050E072F00E1CFBADA14D11042"},
    {"trvk_prg", "4.10/4.11",  "1D364CE8487B2398A9E895C5C87748D9"},
    {"trvk_prg", "4",          "A30722F12FA0872D87A156F85424013E"},
    {"trvk_prg", "3.73",       "7342AFF50A0CE981DFFB07ABA742CC38"},
    {"trvk_prg", "3.72",       "D2BE1629D2EB07F540A6735824B73537"},
    {"trvk_prg", "3.7",        "59FBBD39CC17406E34F19C09F3DD9D64"},
    {"trvk_prg", "3.66/3.66_DEX","AEEEF0B234E004DA7B9F10B80D51C137"},
    {"trvk_prg", "3.65",       "E6C2B57E1BC810A9473448971775AF78"},
    {"trvk_prg", "3.61",       "969702263EF47B8CAA3745FE1BF9B22D"},
    {"trvk_prg", "3.60/3.60_DEX","38F60E2302C0ABEB88EF8058FBF45480"},
    {"trvk_prg", "3.56_2",     "3369B79830062846EAD00BA82546C06C"},
    {"trvk_prg", "3.56_1",     "B89DB85F620A44535B874744F5823CE1"},
    {"trvk_prg", "3.55/3.55_DEX","9A3060D30A25DCE7686AA415A1857319"},
    {"trvk_prg", "3.50_DEX",   "D7B99A10B7968C2E9710ABAE2CC765DD"},
    {"trvk_prg", "3.5",        "C67C0E8750BE22D781C5168FE631145F"},
    {"trvk_prg", "3.42",       "15C630F1EF0F70F968829783F34BBB4F"},
    {"trvk_prg", "3.41_2/3.41_DEX","B9FA9B2128677D0A0147BB1779A846AC"},
    {"trvk_prg", "3.4",        "7B558127CCA04DC3031453AEAEA36066"},
    {"trvk_prg", "3.3",        "E4B49673D8DFCFB8D1004D65F25E9A95"},
    {"trvk_prg", "3.21",       "006CF0D4FA748A746B0FB2EF8B9F4462"},
    {"trvk_prg", "3.15/3.15_DEX","B3D7874BF265BEA925531D4B6FD84575"},
    {"trvk_prg", "3.1",        "D80CBA5A722EA10BD1EE452BBB9DE7C6"},
    {"trvk_prg", "3.01",       "05029C4F31921A5B1E5199F586AC0099"},
    {"trvk_prg", "3",          "EED1F52FEE408C5E9AAFA6797DC6C1EA"},
    {"trvk_prg", "2.8",        "7C25D70ADE0FD709D182A9E07445E4EB"},
    {"trvk_prg", "2.76",       "9E0C34B1C6DFCF85E86C254249F222FA"},
    {"trvk_prg", "2.7",        "3534B73AD8417A35D5DC8B371B45A171"},
    {"trvk_prg", "2.6",        "A34DB715070E75B3F7A76B48D7F3939D"},
    {"trvk_prg", "2.53",       "EEBBAE430CE7A723C1769F77914FFC75"},
    {"trvk_prg", "2.52",       "63E0721BD4C712738B8CFDEFE7A16D6D"},
    {"trvk_prg", "2.5",        "AE6BD7BCAE934DF1D4A0364E8FFD8D2C"},
    {"trvk_prg", "2.43",       "784C73FCA1FB0BBB9162585586701895"},
    {"trvk_prg", "2.42",       "E73F305D7386AD65ECA1737DDB20C212"},
    {"trvk_prg", "2.41",       "AF62192A127780A7F3FF74F497F2166B"},
    {"trvk_prg", "2.4",        "592085BF608BA98CDCD97F83D0585D8B"},
    {"trvk_prg", "2.36",       "30AEEDE2A064039CA6523CB81897ABB9"},
    {"trvk_prg", "2.35",       "53FDFB27E75A071DA477E4E23BF5D95D"},
    {"trvk_prg", "2.3",        "1DA4956E0716A221770700910B326DB6"},
    {"trvk_prg", "2.2",        "6EC24DA67B34757552536F5A64031DE3"},
    {"trvk_prg", "2.17",       "EBBEA9B7483468A5651E85508E6F9DDE"},
    {"trvk_prg", "2.1",        "E5C8EF3D07917BC13C7E25BFB3181E22"},
    {"trvk_prg", "2.01",       "0EF35CA6AE3B364CD43FBA5F7832B8D1"},
    {"trvk_prg", "2",          "FC8C4389D17004220F2EB30909608066"},
    {"trvk_prg", "1.93",       "0928C14E96D725C2FB161A42A3F44428"},
    {"trvk_prg", "1.92",       "F06A8BBFBA08A4C648C8DA67DB4A4B36"},
    {"trvk_prg", "1.9",        "9362B499D8FC74972E2C0CB401E85526"},
    {"trvk_prg", "1.82",       "2C16DDCF3F130295DA202E6DDCC2A224"},
    {"trvk_prg", "1.81",       "FAD825B3EEF1BDD213C74B58E8D695B8"},
    {"trvk_prg", "1.8",        "C22F1C41342904C33A93B2BCC7A9514B"},
    {"trvk_prg", "1.7",        "A039F8EBDC1993860EEA11B126377EAF"},
    {"trvk_prg", "1.6",        "CAAC5DE89DAA2D79DB60F5972F2D7805"},
    {"trvk_prg", "1.54",       "CB006FCF62FA064254E877F2BDEB463D"},
    {"trvk_prg", "1.51",       "2643A3185DEFACC75F5C410BFDBFBA26"},
    {"trvk_prg", "1.5",        "905694B5FFA1F0E49E4860E581B5653E"},
    {"trvk_prg", "1.32",       "E86E439B43E079DBC6759638A9B84891"},
    {"trvk_prg", "1.31",       "88D6850F99F3BA51FA6BB37FABC1A800"},
    {"trvk_prg", "1.3",        "0DB00E61FA8134640800F2EFBCE6F8F9"},
    {"trvk_prg", "1.11",       "410451085E6305BABE8D94FFF89F6C5C"},
    {"trvk_prg", "1.1",        "FC0D846FD88982FB81564D7475590716"},
    {"trvk_prg", "1.02",       "60A4B20FB5B6E09E700E799244C1BC46"},
    {"trvk_pkg", "4.25_DEX",                    "6AB35C1F02B584AE84474D7ABECD6BDA"},
    {"trvk_pkg", "4.20/4.21/4.25/4.30/4.31",    "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.10/4.11",                   "B73491D0783489FEE31847261364ED41"},
    {"trvk_pkg", "4",                           "BCBBD3B8F0D6F50AE45B06EC53E1DF3F"},
    {"trvk_pkg", "3.70/3.72/3.73",              "3947F77FD2E2F997E1E03823C446FB60"},
    {"trvk_pkg", "3.66/3.66_DEX",               "DE8E6C172782047479638C1EFEAF0F51"},
    {"trvk_pkg", "3.65",                        "EA38E7F4598F5A20F3D5CBA0114AC727"},
    {"trvk_pkg", "3.61",                        "16ADE352DAEDDA3FA63A202C767B4C7A"},
    {"trvk_pkg", "3.60/3.60_DEX",               "FF273E1B10617FA053435672844A229D"},
    {"trvk_pkg", "3.56_2",                      "A38264BAF9A6BDA0E5B1B2E32E2B6A28"},
    {"trvk_pkg", "3.56_1",                      "E93A19A2DFE59DDA3C299EA3B9A7F045"},
    {"trvk_pkg", "3.55_DEX",                    "3F807A034B6DCB21F53929B5D0570541"},
    {"trvk_pkg", "3.50_DEX",                    "27B27ACD2075A04CF277C0335538157D"},
    {"trvk_pkg", "3.50/3.55","9C050BB7146E394413804E9E1E9F7FA6"},
    {"trvk_pkg", "3.41_DEX","89B8674638DD06611C3D6946CC0231AE"},
    {"trvk_pkg", "3.40/3.41_2/3.42","E080E353F2D9A1548E3014D2DC6B4BBD"},
    {"trvk_pkg", "3.3","BC3A89D6F7D66B64376C0DFF13D6B867"},
    {"trvk_pkg", "3.21","7BCF9B229FD7AF99F7AF955243129354"},
    {"trvk_pkg", "3.15/3.15_DEX","9589EB7F93B5371E0CB60D454C67ADFA"},
    {"trvk_pkg", "3.1","EC0945F3AEA4A71A2E5E43C5A8ECD594"},
    {"trvk_pkg", "3.01","A7826026D5403024810EDC1E4DD77A52"},
    {"trvk_pkg", "3","95108E059B65E5C1CE6A4A8089089A60"},
    {"trvk_pkg", "2.8","32F5E69E8DE7B87DACC84A92E7025559"},
    {"trvk_pkg", "2.76","CDF88CA39FA271D25C18A2FBE5F9F7BE"},
    {"trvk_pkg", "2.7",             "22E2A99BA76E56F0957A7CF9FB145978"},
    {"trvk_pkg", "2.6",             "F36B3654D90C1578362A8A1510D0BBDD"},
    {"trvk_pkg", "2.53",            "DC0D0B66621C6DFB6704DBF28C58352C"},
    {"trvk_pkg", "2.52",            "26401229922C74D4C87D0DF003D235F1"},
    {"trvk_pkg", "2.5",             "22EFAB44D5CC3D7BA3AF05A4C283E1DA"},
    {"trvk_pkg", "2.43_LEAKED_JIG", "50AF53AF6D53F84D6D92EA6EFC5671DD"},
    {"trvk_pkg", "2.43",            "98BCA0307B2843A815176804947B68E0"},
    {"trvk_pkg", "2.42",            "93B7BE6B8302848FA27EBB8C3E01AE4B"},
    {"trvk_pkg", "2.41",            "505D3CFFFEA7E6085DB5A92C08BFD9BC"},
    {"trvk_pkg", "2.4",             "8DA31A5EDBE973EF0B054E34304F3BC4"},
    {"trvk_pkg", "2.36","FFD0D46F1B1675DA9A5A9E00AF5D71DD"},
    {"trvk_pkg", "2.35","B6E9AB2CCE06F244FE6BFED3C8244082"},
    {"trvk_pkg", "2.3","95CF8B4D7C88396AD71B2837909DD847"},
    {"trvk_pkg", "2.2","02DB8CA8361CEC854DFB339644A5D997"},
    {"trvk_pkg", "2.17","EC9DD3B077A4F42B42AF20A82E07A1EB"},
    {"trvk_pkg", "2.1","EBDB8D9CF82DC1F53ED1EAAC39851F6F"},
    {"trvk_pkg", "2.01","18B410877F6F962E92B7AECD91B1CF0C"},
    {"trvk_pkg", "2","4FCEFA3CFB8D731E90B53FC949151C91"},
    {"trvk_pkg", "1.93","36AD871B0BB839C02CB4BDDBE52FEFEA"},
    {"trvk_pkg", "1.92","B594EA4DB3B3A3D1FB02E0B2B6EE2201"},
    {"trvk_pkg", "1.9","A11A6F728B0086E9082BAD0506C58B94"},
    {"trvk_pkg", "1.82","653434FF27E82FAA04FFA038784A1E7B"},
    {"trvk_pkg", "1.81","C03376C49B7D028094C340E7369CE912"},
    {"trvk_pkg", "1.8","A17466375FC6B6E2E8D8B0F223012F85"},
    {"trvk_pkg", "1.7","3FAB9C9B2C13DAD1D634493F04C60609"},
    {"trvk_pkg", "1.6","29B657AB7327CD1F00B701AE6B7BC179"},
    {"trvk_pkg", "1.54","5D2516B29A9C2E56C3E1C5F2F5883FF0"},
    {"trvk_pkg", "1.51","39BB79DED88187372F06B2F5D393D777"},
    {"trvk_pkg", "1.5","847F9F54A392BCC3F059F2352F4E844C"},
    {"trvk_pkg", "1.32","D08A3FD2C5B8468C4980BCA014EAA47A"},
    {"trvk_pkg", "1.31","C01D8294B4F319DF0CD1CA6CC4480826"},
    {"trvk_pkg", "1.3","7111A00520ACE60D17BB23709F5EC4EC"},
    {"trvk_pkg", "1.11","6D49077177812D9D6FCD289FD1EDED90"},
    {"trvk_pkg", "1.1","EA03F7AC248C5B5228D8B40B13A27AE8"},
    {"trvk_pkg", "1.02","B7829DD4B09C25B6918BA78BDEACF07F"},
    {NULL, NULL, NULL}
};
/*

{"emer_init.self" , "3.55","ca9bbc99c645173e1f98aa66c47a4500"},
{"isoldr" , "3.55","5c7436bffc7e8d0a8e210bd0ca83cdf2"},
{"manu_info_spu_module.self" , "3.55","09a1d434dbd7197e7c3af8a7c28ca38b"},
{"aim_spu_module.self" ,"3.55", "b0ad88ee637311ae5196f1b11d43be0a"},
{"appldr" , "9d670b662be696c8460449b7efdd803e"},
{"mc_iso_spu_module.self" ,"3.55", "b5f54d9a11d1eae71f35b5907c6b9d3a"},
{"creserved_0" ,"3.55", "c1dc055ef0d6082580ac066e2b0a3c38"},
{"sb_iso_spu_module.self" ,"3.55", "811329ecdb677181b9fc5cc3564d9047"},
{"sv_iso_spu_module.self" ,"3.55", "ff6753184d15f45508c5330a6144a4d9"},
{"sc_iso.self" ,"3.55", "bc6b000f5ac5db94daee47720d0bfe6b"},
{"spu_pkg_rvk_verifier.self" ,"3.55", "e9ae2a62b4cc31750d4e56c7d5ffdd6f"},
{"lv2ldr" ,"3.55", "a597aa3d8101674856eef83ac1d0ef28"},
{"eurus_fw.bin" ,"3.55", "413b0666736e87929b346ca2b712284d"},
{"lv1.self" ,"3.55", "65a3eee4c48716674cb1c29609b5f54d"},
{"spp_verifier.self" ,"3.55", "5ffb33a6cecb99081e54a0e36e3c61af"},
{"lv2_kernel.self" ,"3.55", "3b15c14770d654fef9987e2517616d89"},
{"spu_token_processor.self" ,"3.55", "b39e13fbd6b07f65616a0355ef5cb262"},
{"me_iso_spu_module.self" ,"3.55", "d7edca0ed3749f11ee34f0f532cf5aa7"},
{"lv1ldr" ,"3.55", "3da12e2cb472eb8193309b663d7c913a"},
{"hdd_copy.self" , "90d1c8a45f6fee52219e1b14ff8c9765"},
{"spu_utoken_processor.self" ,"3.55", "b76b7244b19032a9518787d9ec827f3c"},
{"default.spp" ,"3.55", "22ababcfc027f892ad2cf4e1c9fd925c"},
{"sdk_version" ,"3.55", "0e5a2e8a68fe09481d728c227dc5a165"},
{"lv0" ,"3.55", "368f2d290c00f3cb3c5a5c8cfe584534"},

{"creserved_0" , "3.66" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
{"sdk_version" , "3.66" , "9c11d208d5f051f0ad762a526b8a1669"},
{"spu_pkg_rvk_verifier.self" , "3.66" , "532bfab841fc4f5211b3ccba997f78e4"},
{"spu_token_processor.self" , "3.66" , "fa31caf6e79ae3529d27d4ab02ecfc39"},
{"spu_utoken_processor.self" , "3.66" , "65131ce2d51ac27cb0f438bdf950e00b"},
{"sc_iso.self" , "3.66" , "4a12608f5b84a9c3d894c48284231239"},
{"aim_spu_module.self" , "3.66" , "9ea38d368571d18d5256f6bbb2d116d4"},
{"spp_verifier.self" , "3.66" , "33161737ceb7d0a93a8752211345a8f1"},
{"mc_iso_spu_module.self" , "3.66" , "f861d45ef9af1b30fa0cd653e7b15132"},
{"me_iso_spu_module.self" , "3.66" , "ef6a516f902a30e56c47273c2f78839f"},
{"sv_iso_spu_module.self" , "3.66" , "75d6f2004d87c3d964e9da5b10a843d1"},
{"sb_iso_spu_module.self" , "3.66" , "b3adb8a7d3d7b9ecf0aa10dc5e0ec902"},
{"default.spp" , "3.66" , "2cebe1ace63a58a900c1b41cd12b3913"},
{"lv1.self" , "3.66" , "0d2ffedebf016a152df44ff415706ba6"},
{"lv0" , "3.66" , "17f859229c4cf88bebbfbf4d67c6e61c"},
{"lv0.2" , "3.66" , "a89b8c89772625139a5998505e025141"},
{"lv2_kernel.self" , "3.66" , "d0be539836f60724b12381879bff5f9e"},
{"eurus_fw.bin" , "3.66" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
{"emer_init.self" , "3.66" , "6e075ac06fa824661bed8e920b78bce1"},
{"hdd_copy.self" , "3.66" , "158028b2b6fd360a4f6256d6af901298"},
{"manu_info_spu_module.self" , "3.66" , "85f37e7534c1f1a13d979393a8831b48"},
{"prog.srvk" , "3.66" , "35dd53916cf44721c0ce9179bc27b367"},
{"pkg.srvk" , "3.66" , "b50d9e45e8fc42aacdda82ec93edc11a"},
{"creserved_0" , "3.66" , "d41d8cd98f00b204e9800998ecf8427e"},

{"creserved_0","4.00","09a1d434dbd7197e7c3af8a7c28ca38b"},
{"sdk_version","4.00","e67a4d209bbdee902e8e7a3f48931b71"},
{"spu_pkg_rvk_verifier.self","4.00","7fb7b15f9a1e7bf735f6b23edde2a0ee"},
{"spu_token_processor.self","4.00","ef9c94719c4d6734603c6cda456c15f0"},
{"spu_utoken_processor.self","4.00","3864fd2937e166d9c5506f231049fc58"},
{"sc_iso.self","4.00","97170ae9accd8c5f963f7a95aeeae89b"},
{"aim_spu_module.self","4.00","1473acf31ef71b111f8563218e08d2b3"},
{"spp_verifier.self","4.00","f53b9fba1c4663c2d65715705b7e3a98"},
{"mc_iso_spu_module.self","4.00","3744b53626c0b7dac84e0331f1fc9211"},
{"me_iso_spu_module.self","4.00","b0f0daaf7acc37031a640e70e40dbab2"},
{"sv_iso_spu_module.self","4.00","6307e959ccc862298033a28e96dfcd27"},
{"sb_iso_spu_module.self","4.00","a89fdb4dabbcf2e3cbfa0585eddce370"},
{"me_iso_for_ps2emu.self","4.00","e59a8048346506c8c94165704bf086e1"},
{"sv_iso_for_ps2emu.self","4.00","c57067f62bb5ead2175062f0ffd373ab"},
{"default.spp","4.00","559a9eb15641989adb22c1a3b017dce2"},
{"lv1.self","4.00","ea98b19492ca78e9dd9cfe9b26a3f66a"},
{"lv0","4.00","c38ac278229f0b678b300e711fc79efd"},
{"lv0.2","4.00","0ff7584f806a4d89780e3c489713489a"},
{"lv2_kernel.self","4.00","91132793ef9e11693109cbb110ac4aa2"},
{"eurus_fw.bin","4.00","b5f54d9a11d1eae71f35b5907c6b9d3a"},
{"emer_init.self","4.00","634690713f08d6352dae111e938fdb64"},
{"hdd_copy.self","4.00","40a867a0c19e04bfcebf53dcb335c7a6"},
{"manu_info_spu_module.self","4.00","19102d74d8388b80c05fdd5cb384b02f"},
{"prog.srvk","4.00","a4ca1ad225c64055fba3ccd6518701a6"},
{"pkg.srvk","4.00","cae7968c1cf9f7a8d01ad60c58535c67"},

 {"creserved_0","4.10","09a1d434dbd7197e7c3af8a7c28ca38b"},
 {"sdk_version","4.10","0d9cd8e0e43f23e31d441b22bf46ef08"},
 {"spu_pkg_rvk_verifier.self","4.10","22234913192677d47fa0e2be8f0c92d4"},
 {"spu_token_processor.self","4.10","ca65a513f5ef6386cec04f8905887c76"},
 {"spu_utoken_processor.self","4.10","cdb8132dfbc00b4ad4e71a24c6e2e819"},
 {"sc_iso.self","4.10","a793201762a3fe35dec4a5f702d9f2dc"},
 {"aim_spu_module.self","4.10","ebbd103489ac59e25625c30de3146eda"},
 {"spp_verifier.self","4.10","173e958b5d8e8dcead291367d98b30b3"},
 {"mc_iso_spu_module.self","4.10","61eaf194b1b8f3bba8bbc95365107f43"},
 {"me_iso_spu_module.self","4.10","ee554afad3e3977c45162859e83b58a5"},
 {"sv_iso_spu_module.self","4.10","0120379b8a947ab676646cc8e4247734"},
 {"sb_iso_spu_module.self","4.10","88634125e5f3f65c949372a9369d2b74"},
 {"me_iso_for_ps2emu.self","4.10","cb23375ab6ea359b2b4b35ee8b9b76d4"},
 {"sv_iso_for_ps2emu.self","4.10","d63c82f101b17e131a522ee4fce9bacd"},
 {"default.spp","4.10","d8816389c27ec666558b712b7b1d5726"},
 {"lv1.self","4.10","a768a6096afe1012bc0976b4ef1be62e"},
 {"lv0","4.10","e69d27ee63acacb0ab925e4f1073e18e"},
 {"lv0.2","4.10","6ab2f344eedab7d6c2a25ab36777f096"},
 {"lv2_kernel.self","4.10","1f0a9474293a9671c054c106a71329e5"},
 {"eurus_fw.bin","4.10","fde1f0429ac816635656a71b2f2a95c7"},
 {"emer_init.self","4.10","edf767a4d8a77d30350d4296345817a9"},
 {"hdd_copy.self","4.10","bd823871906c3b0315e8553b2735b4c7"},
 {"manu_info_spu_module.self","4.10","39928662e23c332453aeaae176cc8b5c"},
 {"prog.srvk","4.10","8642c7891ea6a3d906619ee0e68cbd9a"},
 {"pkg.srvk","4.10","06e8a27f3ca603e686b0bb0c03830d70"},

*/

enum TOCnames {
    asecure_loader = 0,
    eEID,
    cISD,
    cCSD,
    trvk_prg0,
    trvk_prg1,
    trvk_pkg0,
    trvk_pkg1,
    ros0,
    ros1,
    cvtrm,
    CELL_EXTNOR_AREA,
    CRL1,
    DRL1,
    CRL2,
    DRL2,
    bootldr,
    FlashStart,
    FlashFormat,
    FlashRegion,
    TotalSections
};

static struct Sections SectionTOC[] = {
    { "asecure_loader"  , 0x000800, 0x02E800, 0, 0, NULL }, // per console
    { "eEID"            , 0x02F000, 0x010000, 0, 0, NULL }, // per console
    { "cISD"            , 0x03F000, 0x0800  , 0, 0, NULL }, // per console
    { "cCSD"            , 0x03F800, 0x0800  , 0, 0, NULL }, // per console
    { "trvk_prg0"       , 0x040000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_prg1"       , 0x060000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_pkg0"       , 0x080000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_pkg1"       , 0x0A0000, 0x020000, 0, 0, NULL }, // per firmware
    { "ros0"            , 0x0C0000, 0x700000, 0, 0, NULL }, // per firmware
    { "ros1"            , 0x7C0000, 0x700000, 0, 0, NULL }, // per firmware
    { "cvtrm"           , 0xEC0000, 0x040000, 0, 0, NULL }, // per console
    { "CELL_EXTNOR_AREA", 0xF20000, 0x020000, 0, 0, NULL }, // generic
    { "CRL1"            , 0xF40000, 0x020000, 0, 0, NULL }, // generic
    { "DRL1"            , 0xF60000, 0x020000, 0, 0, NULL }, // generic
    { "CRL2"            , 0xF80000, 0x020000, 0, 0, NULL }, // generic
    { "DRL2"            , 0xFA0000, 0x020000, 0, 0, NULL }, // generic
    { "bootldr"         , 0xFC0000, 0x040000, 0, 0, NULL }, // per console
    { "FlashStart"      , 0x000000, 0x0200  , 0, 0, NULL }, // generic
    { "FlashFormat"     , 0x000200, 0x0200  , 0, 0, NULL }, // generic
    { "FlashRegion"     , 0x000400, 0x0400  , 0, 0, NULL }, // generic
    { NULL, 0, 0, 0, 0, NULL }
};

static struct IndividualSystemData CheckPerSKU[] = {
    { "01", "DEH-Z1010",                                       "1420", "113E", 0x2D020, "2CFE", "2CFE", "<= 0.80.004" },
    { "01", "DECR-1000",                                       "EC40", "0EC0", 0x2A840, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1001-D?",                                    "EC40", "0EC0", 0x2A830, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1000A-E (COK-001) DEX",                      "EC70", "0EC3", 0x2A1E0, "2A1A", "2A1A", "< 095.001" },
    { "01", "CECHAxx (COK-001)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1" },
    { "01", "CECHAxx (COK-001) factory FW 1.00",               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "01", "CECHAxx (COK-001)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1" },
    { "01", "DECHAxx (COK-001) DEX",                           "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "02", "CECHBxx (COK-001)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "03", "CECHCxx (COK-002)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "03", "CECHCxx (COK-002) factory FW 1.00",               "EBF0", "0EBB", 0x30480, "3044", "3044", "1" },
    { "03", "CECHCxx (COK-002)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1" },
    { "03", "CECHExx (COK-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", NULL },
    { "04", "Namco System 357 (COK-002) ARC",                  "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.90?" },
    { "04", "CECHExx (COK-002)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.9" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3" },
    { "05", "CECHGxx (SEM-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "1.97" },
    { "06", "CECHHxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "06", "CECHMxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "07", "CECHJxx (DIA-002) factory FW 2.30 - datecode 8B", "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "07", "CECHJxx (DIA-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3" },
    { "07", "CECHKxx (DIA-002) datecode 8C",                   "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3" },
    { "07", "DECHJxx (DIA-002) DEX",                           "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.16" },
    { "08", "Namco System 357 (VER-001) ARC",                  "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45?" },
    { "08", "CECHLxx/CECHPxx (VER-001) ",                      "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45" },
    { "08", "CECHLxx (VER-001)",                               "E8D0", "0E89", 0x2EB70, "2EB3", "2EB3", "2.45" },
    { "08", "CECHLxx (VER-001) factory FW 2.30",               "E890", "0E85", 0x2F170, "2F13", "2F13", "2.3" },
    { "09", "CECH-20xx (DYN-001) factory FW 2.76",             "E890", "0E85", 0x2F170, "2F13", "2F13", "2.7" },
    { "09", "DECR-1400 (DEB-001) DECR factory FW 2.60",        "E890", "0E85", 0x2F170, "2F13", "2F13", "2.6" },
    { "09", "CECH-20xx (DYN-001)",                             "E920", "0E8E", 0x2F3F0, "2F3B", "2F3B", "2.7" },
    { "0A", "CECH-21xx (SUR-001)",                             "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.2" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.40 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.41 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 0D", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.60 datecode 1B", "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.60",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0C", "CECH-30xx (KTE-001) factory FW 3.65",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0D", "CECH-40xx (MSX-001 or MPX-001)",                  "F9B0", "0F97", 0x301F0, "301B", "301B", "4.20" },
    { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL}
};