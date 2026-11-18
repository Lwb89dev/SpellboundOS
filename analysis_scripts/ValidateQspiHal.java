// Actual QSPI HAL with authored MMIO, timestamps and DMA services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import com.google.gson.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateQspiHal extends GhidraScript {
    private static final String CONFIG="{\"init\":2162135584,\"command\":2162135692,\"receive\":2162136004,\"receive_dma\":2162136252,\"transmit\":2162136348,\"transmit_dma\":2162136588,\"pack\":2162134840,\"complete\":2162135040,\"wait_receive\":2162135192,\"wait_transmit\":2162135352,\"tx_count\":2162135512,\"rx_count\":2162135548,\"clock\":2162139008,\"tick\":2160140824,\"frequency\":2160140844,\"dma_setup\":2160141864,\"dma_wait\":2160142048,\"bus\":2160133872,\"feature_read\":2160229608,\"feature_write\":2160229704,\"cache_read\":2160230000,\"cache_write\":2160230508,\"write_enable\":2160229808,\"version\":2160140952,\"logger\":2160184698,\"diagnostic\":2160132868,\"assertion\":2160157974,\"ranges\":[[2162135584,108],[2162135692,204],[2162136004,248],[2162136252,96],[2162136348,240],[2162136588,88],[2162134840,100],[2162135040,152],[2162135192,160],[2162135352,160],[2162135512,36],[2162135548,36],[2162139008,52],[2160133872,886],[2160229608,96],[2160229704,104],[2160230000,102],[2160230508,100],[2160229808,94]],\"guards\":[{\"address\":2162135584,\"size\":108,\"sha256\":\"00754e5d66f0e683b7574bfe16e58619d92ad41b9f5860c63ed5741d81bea4c3\"},{\"address\":2162135692,\"size\":204,\"sha256\":\"a1c08672020fd6b42ac6d1b852bf1fa25324b51155195b8874ac50355029cf6e\"},{\"address\":2162136004,\"size\":248,\"sha256\":\"cf0b858c19fc1abe1f9dd971a2092a1f70f34cf1d891b875ab3778953e5f6ca0\"},{\"address\":2162136252,\"size\":96,\"sha256\":\"9133bab78dc6a4b3a1bdd3c931eaab7d8cee2ccd15a659bc2dd9123b8758f24f\"},{\"address\":2162136348,\"size\":240,\"sha256\":\"0966f523fba54b2ecace5a0ea517192f39af5b05ba6447e0c35db03513b4a4b2\"},{\"address\":2162136588,\"size\":88,\"sha256\":\"96431deb8412fc45a4b405daa5936f73444e1f1c86df52a40f599e02af01f631\"},{\"address\":2162134840,\"size\":100,\"sha256\":\"d81728d94ec968a8022bdf7cd2c799cdd65fdbe9c81fe3e8279b0f1750187ca8\"},{\"address\":2162135040,\"size\":152,\"sha256\":\"5e3259ee308e7647a7df2e3cb4a472029fd2f49be162466fa3e7a823f8f9f694\"},{\"address\":2162135192,\"size\":160,\"sha256\":\"6aa9e076be56cc89f1917b42a275a6e4ac4d20a23e43bb88ebed2030ffd8c046\"},{\"address\":2162135352,\"size\":160,\"sha256\":\"084d605e2524d044a2b4c98514598e0a7dfe3e8286dd2af6eb0c8bbea6a88662\"},{\"address\":2162135512,\"size\":36,\"sha256\":\"23f0432a05059b34c075ae3b853d8042bb22a71cd30f0ee056f8eff3f02b715e\"},{\"address\":2162135548,\"size\":36,\"sha256\":\"42c4cd8a20418deeb8f7f9c7568c4df0993e9e95ff0957530f69f313c01f79e8\"},{\"address\":2162139008,\"size\":52,\"sha256\":\"da2211e78c9062b051bb9a378882c767596ec7f01c5b6c470bee83ddad1e207a\"},{\"address\":2160133872,\"size\":886,\"sha256\":\"e2ae939cfa8cdeefa0e0672c87e9fb5894fa6fc1d65507d305239a7bd054ab59\"},{\"address\":2160229608,\"size\":96,\"sha256\":\"2fec1eff293a04a76ac7b393c32edfa35c907acfceb78ad3b8d200a5100c1afe\"},{\"address\":2160229704,\"size\":104,\"sha256\":\"db25a8f625930987d4de9167e93c764a9d7bc8d50be4fdd13f84f3e61fda4274\"},{\"address\":2160230000,\"size\":102,\"sha256\":\"083d5c97de97dfdffc36089019e1f5f6851ff794d94c547ff6abcd4ff9d20345\"},{\"address\":2160230508,\"size\":100,\"sha256\":\"daf0b6127f69fa6583f5afe6dcfe20f0081bfca1fd68983192c4334bc5847302\"},{\"address\":2160229808,\"size\":94,\"sha256\":\"d52e2947976b3c2b24f6fafa40ecedd9ef3a2f533374ec97374d57b893a5a57a\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"}],\"dma_init\":2160141228,\"dma_tick\":2160140772,\"dma_prepare\":2160141044,\"dma_finish\":2160141136,\"cache_read_bounce\":2160230206,\"cache_write_bounce\":2160230608,\"copy\":2160254520,\"native_dma_ranges\":[[2160141228,408],[2160141864,150],[2160142048,186],[2160230206,106],[2160230608,102]],\"native_dma_guards\":[{\"address\":2160141228,\"size\":408,\"sha256\":\"015a3c0dd1dc248097d4e49c2b79ff045025b7d67506449b160083c7201f5f43\"},{\"address\":2160141864,\"size\":150,\"sha256\":\"f0b33f8e12dc67cc8fe23b42a8c4da3aded10baf6449775b8e6627e09937fbdf\"},{\"address\":2160142048,\"size\":186,\"sha256\":\"24642ea6a207babf06794ea2be566e59972a8d51d0d500871222a85feb57e128\"},{\"address\":2160230206,\"size\":106,\"sha256\":\"e0ba22b249a1572b27516b1b17c0f97527330ae00521c4dea6a888a3a9986ce7\"},{\"address\":2160230608,\"size\":102,\"sha256\":\"3a2f774dc1ddb356b498444480ddf4f938170c4c48a8d93ca7b254028a114cf2\"}],\"platform_init\":2160133504,\"pinmux\":2160145416,\"pin_function\":2162134676,\"platform_ranges\":[[2160133504,366],[2160145416,646],[2162134676,164],[2162134420,144]],\"platform_guards\":[{\"address\":2160133504,\"size\":366,\"sha256\":\"69fd28f411b9e8f4e447870d0b38a1cc677c4811aa5ac73bf06cf85abef7706e\"},{\"address\":2160145416,\"size\":646,\"sha256\":\"6a455fa5a9c95b43cec588b9ac0ab405faa2b5a6f5d00047562028beb3ce6e94\"},{\"address\":2162134676,\"size\":164,\"sha256\":\"987ded0cdd1149b3a7ea09d452d91ff35c4dc25c9b5454a06bfc41a2a512edde\"},{\"address\":2162134420,\"size\":144,\"sha256\":\"8f37b4147dc0ae556fff5af91e9f625ca69f31d50a55d9f0b322e9123e87f3ac\"},{\"address\":2161646640,\"size\":184,\"sha256\":\"17b573beccd13a7fbabc3c12675435de2add3e8aa8d9d8e0ee1bf97eedc00620\"},{\"address\":2160067204,\"size\":8,\"sha256\":\"9d6c527a6a93b654949c546a06a2fdb93abeb0b230e88a67d53aae8b57d2ef12\"}],\"page_read\":2160233112,\"remap_page\":2160228888,\"remap_block\":2160228824,\"page_delay\":2160140628,\"page_compare\":2160256488,\"page_ranges\":[[2160233112,366],[2160228824,64],[2160228888,96],[2160229902,98],[2160231278,180],[2160132848,20],[2160230102,104],[2160238190,238],[2160237900,72]],\"page_guards\":[{\"address\":2160233112,\"size\":366,\"sha256\":\"21fe4647132a935ccaedfab627ff2c61d6429bfc6850afd0e1ce641c2911a16b\"},{\"address\":2160228824,\"size\":64,\"sha256\":\"2ce1d78c21e8c515ae5cecc8cde1e2d792ef3d10a8043712d76171be680039f6\"},{\"address\":2160228888,\"size\":96,\"sha256\":\"e3a36c868b1c4e9ab4247450a8e552beebdfffbdfc75749fd718d3e578331223\"},{\"address\":2160229902,\"size\":98,\"sha256\":\"46e9abe616332fcdbfc12b6d60f23bd021543b3762f7234b90a30984ebbc9c1d\"},{\"address\":2160231278,\"size\":180,\"sha256\":\"c23248ed66048f16a449b0a16bac624f9da5bb43ac00fa3fca9d97e72d519836\"},{\"address\":2160132848,\"size\":20,\"sha256\":\"088330a65e8b216c30d4a672c74d98806b12f38cc51620ec322280add4cc5ecd\"},{\"address\":2160230102,\"size\":104,\"sha256\":\"c63146f005884eca61348d6b26e26ab65a0b1f52d92c908341233d1b078f098e\"},{\"address\":2160238190,\"size\":238,\"sha256\":\"c97829ee76b97c4ee9c40c2c017a018183b2f6a0ce506bcb64ecf195c313aa22\"},{\"address\":2160237900,\"size\":72,\"sha256\":\"04093b1b9d368004296b8da508d08bfe9242d1c2ced22bac32bc0e67db03569f\"},{\"address\":2160319952,\"size\":20,\"sha256\":\"878c2808d3decb4cd6ba7ff75b2f04f8ccc928f24062efd4d529d009caf3d0fe\"},{\"address\":2160322660,\"size\":20,\"sha256\":\"0eee04242e68d13a4a8d4618a7a4e22b57d00a9541d8a8ec1ff0b396077e1d19\"},{\"address\":2160319740,\"size\":20,\"sha256\":\"ec2eec5e971cc1add06ef5f5a34bd159ea6c850d7292b3ca479d171cfa50fb84\"}],\"page_write\":2160233478,\"program_ranges\":[[2160233478,372],[2160230312,98]],\"program_guards\":[{\"address\":2160233478,\"size\":372,\"sha256\":\"206bc02f96f0b59bbb21a908ae2a50cb60a1404307c45593179040c00d03896a\"},{\"address\":2160230312,\"size\":98,\"sha256\":\"0ca2b00fa3eb68273c3c640455eca08be20ce6b66a55a03d30827fb8deb10b4a\"}],\"erase\":2160234982,\"copy_page\":2160233850,\"copy_oob\":2160234180,\"maintenance_sleep\":2160158852,\"maintenance_ranges\":[[2160234982,264],[2160233850,330],[2160234180,382],[2160230710,104],[2160232114,152],[2160230410,98]],\"maintenance_guards\":[{\"address\":2160234982,\"size\":264,\"sha256\":\"94a755e20b330b1f93e678e2e3f83e57e4238a6fed2499f5dd34520ac23ee52c\"},{\"address\":2160233850,\"size\":330,\"sha256\":\"8d311b41c9557e9c6c45fd718a8945d5bc707a419998804515bfa2eeb9c9a16e\"},{\"address\":2160234180,\"size\":382,\"sha256\":\"53828d54bddaf8ad89283fe08e600376845d710bea0099950336b7a4b397aa98\"},{\"address\":2160230710,\"size\":104,\"sha256\":\"ac2a060dff15bde10a546abff681df1b4a9e13dea9afbc7a0834d0a3b76bd2ff\"},{\"address\":2160232114,\"size\":152,\"sha256\":\"eb07a88e83d912f61370824888d06cb00252e8c3987e56c54bf4dc746df9e739\"},{\"address\":2160230410,\"size\":98,\"sha256\":\"302022a1363436da0e40d2c08abc49f960745ed12eda8d4fb56f8cde99e78ca4\"}],\"identity_compat\":2160237900,\"identity_level\":2160237972,\"identity_retry\":2160238190,\"identity_check\":2160238428,\"identity_uid\":2160231458,\"identity_ioctl\":2160235246,\"identity_zero\":2160254996,\"identity_format\":2160255464,\"identity_ranges\":[[2160237972,218],[2160238428,234],[2160231458,656],[2160231002,94],[2160231096,94],[2160235246,394],[2160072778,4]],\"identity_guards\":[{\"address\":2160237972,\"size\":218,\"sha256\":\"41fb19b785d644fcec82cd273d1e76ec51fbeff374c8e826aef5c5a6f43c7be7\"},{\"address\":2160238428,\"size\":234,\"sha256\":\"bb717b8e710397e05e10d809559f612365d053f7b043dcf64d538bec73d12d80\"},{\"address\":2160231458,\"size\":656,\"sha256\":\"dcc7ef5a870427061ec6b74e32a8d3cf89b5126f796f44d42fa75a282f09395b\"},{\"address\":2160231002,\"size\":94,\"sha256\":\"35294017e76703e315f97a3ba06fe6720fb971ac232c7e22db0ad32d7802a2e0\"},{\"address\":2160231096,\"size\":94,\"sha256\":\"f3c33e88c08da69a41ca885c76e9399c08550d6912e5111eab7d29211cc3f63f\"},{\"address\":2160235246,\"size\":394,\"sha256\":\"b6e52b407b668858305eb17bad9d83913f542daafec867d12a6cc69b56202fbe\"},{\"address\":2160072778,\"size\":4,\"sha256\":\"47e47d166a72630fbde2886201a0384899a89ace1574465a679cebdb1bbde755\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"},{\"address\":2161646640,\"size\":184,\"sha256\":\"17b573beccd13a7fbabc3c12675435de2add3e8aa8d9d8e0ee1bf97eedc00620\"},{\"address\":2160067204,\"size\":8,\"sha256\":\"9d6c527a6a93b654949c546a06a2fdb93abeb0b230e88a67d53aae8b57d2ef12\"},{\"address\":2160319952,\"size\":20,\"sha256\":\"878c2808d3decb4cd6ba7ff75b2f04f8ccc928f24062efd4d529d009caf3d0fe\"},{\"address\":2160322660,\"size\":20,\"sha256\":\"0eee04242e68d13a4a8d4618a7a4e22b57d00a9541d8a8ec1ff0b396077e1d19\"},{\"address\":2160319740,\"size\":20,\"sha256\":\"ec2eec5e971cc1add06ef5f5a34bd159ea6c850d7292b3ca479d171cfa50fb84\"},{\"address\":2161646628,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160320160,\"size\":184,\"sha256\":\"7175b7e125deb627582a1beee00cd1bcc4168e590971c49cd22ab9a4fe208d93\"},{\"address\":2160319764,\"size\":20,\"sha256\":\"891248cc6a539af518e01584874385993631c818d5f336eaedba8c6566491fe5\"},{\"address\":2161646532,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160321632,\"size\":184,\"sha256\":\"8dd50ee3bb75385762aa6890f8b9a04f52a6d54108559db974f3337351b1f15f\"},{\"address\":2160319932,\"size\":20,\"sha256\":\"eef068ae5f7113835d540d682d2ea405eaf3c5cb8de6c97ecdc6762badc35e83\"},{\"address\":2161646620,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160319976,\"size\":184,\"sha256\":\"193b85a675d2b4c0b76cbc9beb2e056de4c6f3baeaa3c26dec242d6d4b2b7e3a\"},{\"address\":2161646520,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160321448,\"size\":184,\"sha256\":\"68946a6d5a5bee0b008272b662d12e3e1f192b78fe447fdacef00191c8ba740a\"},{\"address\":2160319912,\"size\":20,\"sha256\":\"5aab06602d4f96f78ebe1fb79ab46389a24bedcd0c2c3929087d8a8c55a142aa\"},{\"address\":2161646608,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160321264,\"size\":184,\"sha256\":\"f59a823e03510ca26c047fb238360371aa48c79d8bca71bcaefc95d91c426ee1\"},{\"address\":2160319892,\"size\":20,\"sha256\":\"cf697432d7af3966dd6c9ba5d6f8b0b121403850d748272a61664f9ba2ebb231\"},{\"address\":2161646596,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160321080,\"size\":184,\"sha256\":\"75adff4405bb06df5d88fc8b3af00bcc29c7835b7226bf39cf6a89ea379f9650\"},{\"address\":2160319872,\"size\":20,\"sha256\":\"f4421810a9f5d4450b38c826cea5401e9d929fadd67fb12132991a6fb1b1a84c\"},{\"address\":2161646584,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320896,\"size\":184,\"sha256\":\"a3cc301704a8f284867767c9c2df18153ae3f0c13d4dd1af8713b0030787eb0d\"},{\"address\":2160319852,\"size\":20,\"sha256\":\"dae66e35d4d156879ed458330d25f498868a5fc4091f27e74c4f429c7d19cdc5\"},{\"address\":2161646572,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320528,\"size\":184,\"sha256\":\"cb5291eae91d18b933717c3c2addb946e1294c67e7f42bd3ea2c7e58f3038619\"},{\"address\":2160319812,\"size\":20,\"sha256\":\"00e78286c9753480b1ef41dcd8f744df9cc53e35ddd49bce9e969881dd7c3145\"},{\"address\":2161646552,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320344,\"size\":184,\"sha256\":\"8492de115fd544467b2edae9a1802a9b9613b31b521e57c3037b6e7ba0a65a7e\"},{\"address\":2160319788,\"size\":20,\"sha256\":\"620617da650a259c62cf22e25fcba21e8d587f56d74c32053571363aeefc4fd7\"},{\"address\":2161646540,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320712,\"size\":184,\"sha256\":\"4daf962fb2a03da7544821b50f47bd0668b18df8a443f6d26075fba491199af3\"},{\"address\":2160319836,\"size\":20,\"sha256\":\"deeb0df2c7f13735a90a6f979b1d5cb6d8665357206fa33ce24878caf557c77c\"},{\"address\":2161646564,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160319000,\"size\":5,\"sha256\":\"6591ccd67a1fb2749ff086c1db91e89e58b2c8763c03d7807cab6dd7d98d0f61\"}],\"partition_read\":2160235826,\"dispatch_read\":2160227790,\"partition_ioctl\":2160236108,\"dispatch_ioctl\":2160227910,\"driver_read\":2160229488,\"driver_ioctl\":2160229220,\"dispatch_irq\":2160160980,\"dispatch_scheduler\":2160160998,\"dispatch_acquire\":2160159622,\"dispatch_release\":2160159786,\"dispatch_ranges\":[[2160235826,68],[2160227790,32],[2160236108,270],[2160227910,28],[2160229488,80],[2160229220,64],[2160229008,28],[2160229106,58],[2160229164,56],[2160235246,394]],\"dispatch_guards\":[{\"address\":2160235826,\"size\":68,\"sha256\":\"2fd8036a571a295969f38a803aa4cfca4eb680336381c8d6cf69ab942374453a\"},{\"address\":2160227790,\"size\":32,\"sha256\":\"13d584453632685dfd15c10eab70e4f47079811deccb7c75846001cc480fe75b\"},{\"address\":2160236108,\"size\":270,\"sha256\":\"ec5f1d25374014f7a999a83a1f3a9cdf1c3ed702b6f8406c4bcdb45c7428dccc\"},{\"address\":2160227910,\"size\":28,\"sha256\":\"ca379288a9d8a6f2f461d381fa773047cb92d44b49943507362da124b514b481\"},{\"address\":2160229488,\"size\":80,\"sha256\":\"ed1c4a361bf69ca203982e1726d6f19db43e3f968e28552afb97d89e134538cf\"},{\"address\":2160229220,\"size\":64,\"sha256\":\"15e7ad10fda45342ab1046e86fb98aead161726191c92a5fe46c4d4ecb313719\"},{\"address\":2160229008,\"size\":28,\"sha256\":\"64db8dd35b2e4415839b506ac49ce7fddb741ad71c25b01ee1664da62d5cd562\"},{\"address\":2160229106,\"size\":58,\"sha256\":\"d3c17d09fc92ff53cf71722c1b9b7f000bf4a1fe282e01240319bbfbefff9b27\"},{\"address\":2160229164,\"size\":56,\"sha256\":\"48128deb4a935799552752d8f6659d22c16a88c742816f248a9071e58d9880a2\"},{\"address\":2160235246,\"size\":394,\"sha256\":\"b6e52b407b668858305eb17bad9d83913f542daafec867d12a6cc69b56202fbe\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"},{\"address\":2161646640,\"size\":184,\"sha256\":\"17b573beccd13a7fbabc3c12675435de2add3e8aa8d9d8e0ee1bf97eedc00620\"},{\"address\":2160067204,\"size\":8,\"sha256\":\"9d6c527a6a93b654949c546a06a2fdb93abeb0b230e88a67d53aae8b57d2ef12\"},{\"address\":2160319952,\"size\":20,\"sha256\":\"878c2808d3decb4cd6ba7ff75b2f04f8ccc928f24062efd4d529d009caf3d0fe\"},{\"address\":2160322660,\"size\":20,\"sha256\":\"0eee04242e68d13a4a8d4618a7a4e22b57d00a9541d8a8ec1ff0b396077e1d19\"},{\"address\":2160319740,\"size\":20,\"sha256\":\"ec2eec5e971cc1add06ef5f5a34bd159ea6c850d7292b3ca479d171cfa50fb84\"},{\"address\":2161646376,\"size\":4,\"sha256\":\"9bf63af6cbff5ce124b48e8c0dac87207f793024477779fea9087d082856ff08\"},{\"address\":2161644020,\"size\":28,\"sha256\":\"f14265a78e0caeeb80f018db41022e6a5267a49016c4d6d24ebf9878d706612d\"}],\"eftl_map\":2160075162,\"eftl_wrapper\":2160210514,\"eftl_page\":2160076682,\"eftl_oob\":2160076720,\"eftl_extract\":2160076244,\"eftl_ranges\":[[2160075162,254],[2160210514,78],[2160076682,38],[2160076720,86],[2160076244,210]],\"eftl_guards\":[{\"address\":2160075162,\"size\":254,\"sha256\":\"3298dbbdd33a76b06d90a940376431281bf0fefe6149262226156ff6f90d16dc\"},{\"address\":2160210514,\"size\":78,\"sha256\":\"0a69990c6e1b2273d246d277c1302ce0e2366d79fccd911e4768241fc991d972\"},{\"address\":2160076682,\"size\":38,\"sha256\":\"25ac27a5214407304c10fe7fa30a50d0e2ca097172c8c30b6aebf28228338f4b\"},{\"address\":2160076720,\"size\":86,\"sha256\":\"a91470da9ce883ab4e387ecc84745b11489a1d67edac99de4089d793d366da5c\"},{\"address\":2160076244,\"size\":210,\"sha256\":\"55342ac4d4119a5165c9a24946539d283cc7975d92929a6d3ad72c3d5658def2\"}],\"storage_read\":2160215110,\"storage_bounds\":2160214552,\"storage_warning\":2160250318,\"storage_ranges\":[[2160215110,188],[2160214552,296]],\"storage_guards\":[{\"address\":2160215110,\"size\":188,\"sha256\":\"13434f14c283f807e38f2153ce0af201ce637769534ce859f9ab8f70cd97870f\"},{\"address\":2160214552,\"size\":296,\"sha256\":\"25764c77509df0079587be8c6742de190d986123d25bc6d51f147b976e944097\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"},{\"address\":2161646640,\"size\":184,\"sha256\":\"17b573beccd13a7fbabc3c12675435de2add3e8aa8d9d8e0ee1bf97eedc00620\"},{\"address\":2160067204,\"size\":8,\"sha256\":\"9d6c527a6a93b654949c546a06a2fdb93abeb0b230e88a67d53aae8b57d2ef12\"},{\"address\":2160319952,\"size\":20,\"sha256\":\"878c2808d3decb4cd6ba7ff75b2f04f8ccc928f24062efd4d529d009caf3d0fe\"},{\"address\":2160322660,\"size\":20,\"sha256\":\"0eee04242e68d13a4a8d4618a7a4e22b57d00a9541d8a8ec1ff0b396077e1d19\"},{\"address\":2160319740,\"size\":20,\"sha256\":\"ec2eec5e971cc1add06ef5f5a34bd159ea6c850d7292b3ca479d171cfa50fb84\"},{\"address\":2161646376,\"size\":4,\"sha256\":\"9bf63af6cbff5ce124b48e8c0dac87207f793024477779fea9087d082856ff08\"},{\"address\":2161644020,\"size\":28,\"sha256\":\"f14265a78e0caeeb80f018db41022e6a5267a49016c4d6d24ebf9878d706612d\"},{\"address\":2160278072,\"size\":960,\"sha256\":\"1d0947000cbb1831ffabda18da3a2ec4b99a175228a1d83e7e82b56ca6f12ad7\"},{\"address\":2161643448,\"size\":76,\"sha256\":\"23c023a72327347e66875b4a7a29d03f75432ca34ffa69c1896631579567c03b\"}],\"storage_program\":2160215298,\"storage_erase\":2160215486,\"storage_rewrite\":2160215634,\"mutation_backend_program\":2160210742,\"mutation_backend_erase\":2160210592,\"driver_program\":2160229408,\"mutation_remainder\":2160253332,\"mutation_ranges\":[[2160074474,688],[2160073306,276],[2160076454,228],[2160076806,36],[2160076842,48],[2160235894,68],[2160227822,32],[2160229408,80],[2160210592,150],[2160210742,78],[2160210820,4],[2160215298,188],[2160215486,148],[2160215634,204]],\"mutation_guards\":[{\"address\":2160074474,\"size\":688,\"sha256\":\"48fbf40fbc10908d01c7adc1bac5d2533cdf476b52b51e10678f15bc9a50fa5e\"},{\"address\":2160073306,\"size\":276,\"sha256\":\"5172beb542d316a5f4321b8505d2101b7834cd32d4ff59eaf55dd4aa0d27f90a\"},{\"address\":2160076454,\"size\":228,\"sha256\":\"0983deee294c69c7ac10c388dc593b2424d00e2dc887f22fa16918fa192a3a76\"},{\"address\":2160076806,\"size\":36,\"sha256\":\"3196002ea6e4eb79de403b1e6813fef90721c08f646876f41c3edc01b76b058d\"},{\"address\":2160076842,\"size\":48,\"sha256\":\"daf9f0d9c7dab126a377e862b79a1c4eb485464da008171971eec47a44dc741e\"},{\"address\":2160235894,\"size\":68,\"sha256\":\"f78370295dfe02b3359d6d8586e59b6f5101a1fc14fcc8548e03984ce18ad2b1\"},{\"address\":2160227822,\"size\":32,\"sha256\":\"4a5a85be0da9d868d49288f4421beb96149cc61adcf8a2141c6c471b5b9be702\"},{\"address\":2160229408,\"size\":80,\"sha256\":\"58dd765375c842efb45277df56df1140cef347f4892bebbdcf9af8391e7a53a4\"},{\"address\":2160210592,\"size\":150,\"sha256\":\"abf30658c1ac2b3fa0b71a811d74035e92835ed0d6a0fb7d6ac88e80baa79165\"},{\"address\":2160210742,\"size\":78,\"sha256\":\"ae4c7842c0e9ccafe844bb7ac2ac6e4b60985e6892550ede7659c2dcb56cb7d6\"},{\"address\":2160210820,\"size\":4,\"sha256\":\"090a4b722bd19a657e12b7885e576fd2b88f2868b94e09621bbf077186ffbd6a\"},{\"address\":2160215298,\"size\":188,\"sha256\":\"6f647486e40f4d7c319dfb1f3aa4d7c2221f25f33f909e3132e01b8f818f5dad\"},{\"address\":2160215486,\"size\":148,\"sha256\":\"6257c34c1209319991af78984bf127a96a48234d4ee3feeb778d7ad02dd5bfa6\"},{\"address\":2160215634,\"size\":204,\"sha256\":\"be3b394ea977bbd7789d9be77d793db8b5ed6cf7654d630c2be7fc3cb04a1f9b\"}],\"readback_checksum\":2160073226,\"readback_ranges\":[[2160073226,80]],\"readback_guards\":[{\"address\":2160073226,\"size\":80,\"sha256\":\"eae8f359810bcc1382c84110bb2c4b4ee0b893a9a279491618fd314994a019be\"}]}";
    private static final long END=0x70000000L,CTRL=0x80dfb880L,BUFFER=0x81301000L,FRAME=0x81302000L,
        DMA0=0x81304000L,DMA1=0x81305000L,CLOCK=0x9a000024L,SHADOW=0x80de67dcL,BOUNCE=0x80dfb8c0L,TABLE=0x80de65ecL;
    private int executionBound=100000;
    private boolean nativeReadback(){return c.has("native_readback")&&c.get("native_readback").getAsBoolean();}
    private boolean nativeMutation(){return c.has("native_mutation")&&c.get("native_mutation").getAsBoolean();}
    private boolean dmaReceive;
    private boolean nativeStorage(){return c.has("native_storage")&&c.get("native_storage").getAsBoolean();}
    private boolean nativeEftl(){return c.has("native_eftl")&&c.get("native_eftl").getAsBoolean();}
    private boolean nativeDispatch(){return c.has("native_dispatch")&&c.get("native_dispatch").getAsBoolean();}
    private boolean nativeIdentity(){return c.has("native_identity")&&c.get("native_identity").getAsBoolean();}
    private boolean nativeMaintenance(){return c.has("native_maintenance")&&c.get("native_maintenance").getAsBoolean();}
    private boolean nativeProgram(){return c.has("native_program")&&c.get("native_program").getAsBoolean();}
    private boolean nativePage(){return c.has("native_page")&&c.get("native_page").getAsBoolean();}
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,ticks,chunks,dmaTicks,driverCalls,storageCalls;private Io io;
    private boolean nativeDma(){return c.has("native_dma")&&c.get("native_dma").getAsBoolean();}
    private boolean nativePlatform(){return c.has("native_platform")&&c.get("native_platform").getAsBoolean();}
    private boolean fullPlatform(){return nativePlatform()&&c.get("full_platform").getAsBoolean();}
    private long dmaPointer(int i){return fullPlatform()?(i==0?0x80de64a0L:0x80de645cL):(i==0?DMA0:DMA1);}
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p){super(p);}
        @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
        void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
    }
    private class Io extends MemoryAccessFilter {
        int readbackIndex=-1,readbackAt;
        boolean active,reset;int rx,featureReads,payloadRx,statusReads,e0Reads,uidRx;long base,clock;
        TreeMap<Long,Long> regs=new TreeMap<>();Map<String,Integer> indices=new HashMap<>();
        TreeMap<Long,Long> dmaRegs=new TreeMap<>();Map<String,Integer> dmaIndices=new HashMap<>();long dmaBase;
        TreeMap<Long,Long> boardRegs=new TreeMap<>(),featureRegs=new TreeMap<>();
        ByteArrayOutputStream tx=new ByteArrayOutputStream();
        long next(String key){JsonArray values=c.getAsJsonArray(key);int i=indices.getOrDefault(key,0);indices.put(key,i+1);return values.get(Math.min(i,values.size()-1)).getAsLong();}
        long decode(byte[] data){long v=0;for(int i=0;i<data.length;i++)v|=(data[i]&255L)<<(8*i);return v;}
        @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){
            if(!active||!space.getName().equals("ram"))return;long value;
            if(nativePlatform()&&boardRegs.containsKey(offset)){if(size!=4)throw new IllegalStateException("Board read width");value=boardRegs.get(offset);actions.add("board_r:"+offset+":"+value);}
            else if(nativeDma()&&offset>=dmaBase&&offset<dmaBase+0x200){
                long at=offset-dmaBase;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Unexpected connected DMA read");value=dmaRegs.get(at);
                if(at==20||at==24){String key=at==20?"status_a":"status_b";JsonObject p=c.getAsJsonObject((nativeMutation()?dmaReceive:nativeDispatch()||c.get("mode").getAsString().contains("receive")||c.get("mode").getAsString().contains("read"))?"dma_rx":"dma_tx");JsonArray values=p.getAsJsonArray(key);int i=dmaIndices.getOrDefault(key,0);dmaIndices.put(key,i+1);value=values.get(Math.min(i,values.size()-1)).getAsLong();dmaRegs.put(at,value);}
                actions.add("dma_r:"+at+":"+value);
            }else if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock read width");value=clock;actions.add("clock_read:"+value);}
            else if(offset>=base&&offset<base+0x104){
                long at=offset-base;
                if(at==0x100){if(size!=1&&size!=4||rx+size>(nativePage()?4096:512))throw new IllegalStateException("FIFO read bound");value=0;
                    if(nativePage()&&(regs.get(12L)>>>24)==0x0f){
                        if(size!=1)throw new IllegalStateException("Status FIFO width");
                        if(nativeIdentity()){
                            long reg=regs.get(0L);featureReads++;
                            if(reg==192){JsonArray values=c.getAsJsonArray("responses");value=values.get(Math.min(statusReads++,values.size()-1)).getAsLong();}
                            else if(reg==224){JsonArray values=c.getAsJsonArray("e0_reads");value=e0Reads<values.size()?values.get(e0Reads).getAsLong():featureRegs.get(224L);e0Reads++;}
                            else value=featureRegs.getOrDefault(reg,0L)^(c.get("uid_mismatch").getAsBoolean()?1:0);
                        }else{JsonArray values=c.getAsJsonArray("responses");value=values.get(Math.min(featureReads++,values.size()-1)).getAsLong();}
                    }else if(nativeReadback()&&(regs.get(12L)>>>24)==0x6b){JsonArray values=c.getAsJsonArray("cache_payloads");byte[] b=HexFormat.of().parseHex(values.get(Math.min(readbackIndex,values.size()-1)).getAsString());if(readbackAt+size>b.length)throw new IllegalStateException("Readback FIFO bound");for(int i=0;i<size;i++)value|=(b[readbackAt+i]&255L)<<(8*i);readbackAt+=size;
                    }else if(nativeIdentity()&&(regs.get(12L)>>>24)==3){
                        long index=regs.get(0L)/32;if(uidRx+size>32)throw new IllegalStateException("UID FIFO bound");
                        for(int i=0;i<size;i++){int uidAt=uidRx+i;long b=((uidAt%16)*7+index*13+1)&255;if(uidAt>=16)b^=255;if(uidAt==31&&index!=c.get("first_good").getAsInt())b^=1;value|=b<<(8*i);}uidRx+=size;
                    }else{for(int i=0;i<size;i++)value|=((0x5a+((nativePage()?payloadRx:rx)+i)*7)&255L)<<(8*i);payloadRx+=size;}rx+=size;}
                else{
                    if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unknown QSPI read "+Long.toHexString(offset));
                    if(at==0x10&&reset){value=next("reset_reads");regs.put(at,value);if((value&0x100)==0)reset=false;}
                    else if(at==0x18){value=next("ready");regs.put(at,value);}
                    else if(at==0x24){value=next("done");regs.put(at,value);}
                    else value=regs.get(at);
                }actions.add("r:"+at+":"+size+":"+value);
            }else return;
            for(int i=0;i<size;i++)data[i]=(byte)(value>>>(8*i));
        }
        @Override protected void processWrite(AddressSpace space,long offset,int size,byte[] data){
            if(!active||!space.getName().equals("ram"))return;long value=decode(data);
            if(nativePlatform()&&boardRegs.containsKey(offset)){if(size!=4)throw new IllegalStateException("Board write width");boardRegs.put(offset,value);actions.add("board_w:"+offset+":"+value);return;}
            if(nativeDma()&&offset>=dmaBase&&offset<dmaBase+0x200){long at=offset-dmaBase;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Unexpected connected DMA write");dmaRegs.put(at,value);actions.add("dma_w:"+at+":"+value);return;}
            if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock write width");clock=value;actions.add("clock_write:"+value);return;}
            if(offset>=base&&offset<base+0x104){
                long at=offset-base;
                if(at==0x100){if(size!=1&&size!=4)throw new IllegalStateException("FIFO write width");tx.writeBytes(data);if(nativeIdentity()&&(regs.get(12L)>>>24)==31){if(size!=1||regs.get(0L)>255)throw new IllegalStateException("Feature FIFO write");long reg=regs.get(0L);if(reg!=224||c.get("apply_writes").getAsBoolean())featureRegs.put(reg,value&255);}}
                else{
                    if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unknown QSPI write "+Long.toHexString(offset));
                    if(nativeReadback()&&at==12&&(value>>>24)==0x6b){readbackIndex++;readbackAt=0;}if(nativeIdentity()&&at==12&&(value>>>24)==3)uidRx=0;regs.put(at,at==0x24&&value==1?0:value);if(at==0x10&&(value&0x100)!=0)reset=true;
                }actions.add("w:"+at+":"+size+":"+value);
            }
        }
    }
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(Helper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(Helper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(Helper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long word(Helper e,long at){byte[] b=mem(e,at,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(Helper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(Helper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(Helper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>executionBound)throw new IllegalStateException("Execution bound");
            if((pc==a("wait_receive")||pc==a("wait_transmit"))&&c.get("stop_chunks").getAsInt()>0&&++chunks>c.get("stop_chunks").getAsInt()){
                actions.add("stop_no_progress:"+(chunks-1));stopped=new JsonObject();stopped.addProperty("kind","bounded_prefix");stopped.addProperty("chunks",chunks-1);return;
            }
            if(nativePage()&&(pc==a("remap_page")||pc==a("remap_block")))actions.add((pc==a("remap_page")?"native_remap_page:":"native_remap_block:")+r(e,0));
            if(nativePage()&&pc==a("page_delay")){long n=r(e,0);if(n!=5&&(!nativeIdentity()||n!=1000&&n!=5000))throw new IllegalStateException("Page delay argument");actions.add("delay:"+n);ret(e,0);continue;}
            if(nativeMaintenance()&&pc==a("maintenance_sleep")){if(r(e,0)!=1)throw new IllegalStateException("Erase sleep argument");actions.add("sleep:1");ret(e,0);continue;}
            if(nativePage()&&pc==a("page_compare")){
                if(r(e,0)!=(nativeIdentity()?word(e,0x81306038L):0x80c3ddd0L)||(r(e,1)!=0x80c3e864L&&r(e,1)!=0x80c3dcfcL)||r(e,2)!=20)throw new IllegalStateException("Read retry comparison arguments");
                byte[] left=mem(e,r(e,0),20),right=mem(e,r(e,1),20);int v=0;for(int i=0;i<20;i++){int x=left[i]&255,y=right[i]&255;if(x!=y){v=x<y?-1:1;break;}if(x==0)break;}actions.add("compare20:"+v);ret(e,v);continue;
            }
            if(nativeIdentity()&&pc==a("identity_zero")){
                long out=r(e,0),n=r(e,2);if(r(e,1)!=0||!(out>=0x81000000L&&out+n<=0x81001000L&&n<=252||out==0x80df4370L&&n<=128))throw new IllegalStateException("Identity zero bound");
                if(n>0)e.writeMemory(toAddr(out),new byte[(int)n]);if(out==0x80df4370L)actions.add("zero_uid:"+n);ret(e,out);continue;
            }
            if(nativeIdentity()&&pc==a("identity_format")){
                long out=r(e,0),n=r(e,1),value=r(e,3);if(out<0x81000000L||out+3>0x81001000L||n<3||n>256||value>255||r(e,2)!=0x80c3da18L)throw new IllegalStateException("Identity format arguments");
                byte[] b=String.format(java.util.Locale.ROOT,"%02X",value).getBytes(java.nio.charset.StandardCharsets.US_ASCII);e.writeMemory(toAddr(out),Arrays.copyOf(b,3));actions.add("format:"+value);ret(e,2);continue;
            }
            if(nativeDispatch()&&(pc==a("driver_read")||pc==a("driver_ioctl"))){driverCalls++;actions.add(pc==a("driver_read")?"driver_read:"+r(e,1)+":"+r(e,2)+":"+r(e,3):"driver_ioctl:"+r(e,0));}
            if(nativeDispatch()&&pc==0x80c292eeL)actions.add("chip_ioctl:"+r(e,0));
            if(nativeDispatch()&&(pc==a("dispatch_irq")||pc==a("dispatch_scheduler"))){boolean irq=pc==a("dispatch_irq");if(!irq&&r(e,0)!=1)throw new IllegalStateException("Scheduler query argument");long value=c.get(irq?"irq_context":"scheduler_context").getAsLong();actions.add((irq?"irq_context:":"scheduler_context:")+value);ret(e,value);continue;}
            if(nativeDispatch()&&(pc==a("dispatch_acquire")||pc==a("dispatch_release"))){boolean release=pc==a("dispatch_release");if(r(e,0)!=0x81308400L||!release&&r(e,1)!=0xffffffffL)throw new IllegalStateException("Mutex arguments");long value=c.get(release?"release_status":"acquire_status").getAsLong();actions.add((release?"mutex_release:":"mutex_acquire:")+value);ret(e,value);continue;}
            if(nativeMutation()&&pc==0x80c2e014L&&r(e,0)>=0x8130a000L&&r(e,0)+r(e,2)<=0x8130a840L){long out=r(e,0),n=r(e,2);if(r(e,1)!=255||n>2112)throw new IllegalStateException("Write scratch fill bound");byte[] b=new byte[(int)n];Arrays.fill(b,(byte)255);if(n>0)e.writeMemory(toAddr(out),b);actions.add("write_fill:"+(out-0x8130a000L)+":"+n);ret(e,out);continue;}
            if(nativeEftl()&&pc==0x80c2e014L){long out=r(e,0),n=r(e,2);if(r(e,1)!=255||out<BUFFER||out+n>BUFFER+512||n>64)throw new IllegalStateException("EFTL gap fill bound");byte[] b=new byte[(int)n];Arrays.fill(b,(byte)255);if(n>0)e.writeMemory(toAddr(out),b);ret(e,out);continue;}
            if(nativeStorage()&&pc==a("eftl_wrapper")){storageCalls++;actions.add("storage_backend_read:"+r(e,0)+":"+r(e,2));}
            if(nativeStorage()&&pc==a("storage_warning")){actions.add("storage_diagnostic:"+r(e,2));ret(e,0);continue;}
            if(nativeMutation()&&pc==a("dma_setup")){long descriptor=r(e,0);if(descriptor!=dmaPointer(0)&&descriptor!=dmaPointer(1))throw new IllegalStateException("Mutation DMA descriptor");dmaReceive=descriptor==dmaPointer(1);}
            if(nativeMutation()&&pc==a("driver_program")){driverCalls++;actions.add("driver_program:"+r(e,1)+":"+r(e,2)+":"+r(e,3));}
            if(nativeMutation()&&(pc==a("mutation_backend_program")||pc==a("mutation_backend_erase"))){boolean erase=pc==a("mutation_backend_erase");storageCalls++;actions.add("storage_backend_"+(erase?"erase:":"program:")+r(e,0)+":"+r(e,erase?1:2));}
            if(nativeMutation()&&pc==a("mutation_remainder")){long value=r(e,0);if(r(e,1)!=0||r(e,2)!=131072||r(e,3)!=0)throw new IllegalStateException("Bounded erase remainder arguments");long result=value%131072;actions.add("erase_remainder:"+value+":"+result);ret(e,result);e.writeRegister("a1",0);continue;}
            if(nativeReadback()&&pc==a("readback_checksum")){long p=r(e,0);if(p<0x81000000L||p+4>0x81001000L)throw new IllegalStateException("Readback checksum pointer");actions.add("readback_checksum:"+HexFormat.of().formatHex(mem(e,p,4)));}
            if(pc==a("tick")){
                JsonArray values=c.getAsJsonArray("ticks");long v=values.get(Math.min(ticks++,values.size()-1)).getAsLong();actions.add("tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(pc==a("frequency")){long v=c.get("frequency").getAsLong();actions.add("frequency:"+v);ret(e,v);continue;}
            if(nativeDma()&&pc==a("dma_tick")){
                JsonObject p=c.getAsJsonObject((nativeMutation()?dmaReceive:nativeDispatch()||c.get("mode").getAsString().contains("receive")||c.get("mode").getAsString().contains("read"))?"dma_rx":"dma_tx");JsonArray values=p.getAsJsonArray("ticks");long v=values.get(Math.min(dmaTicks++,values.size()-1)).getAsLong();actions.add("dma_tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(nativeDma()&&(pc==a("dma_prepare")||pc==a("dma_finish"))){
                long p=r(e,0),n=r(e,1);if(n>(nativeMutation()?2112:64)||!(p==0||p==BOUNCE||p==BUFFER||p==BUFFER+1||p==io.base+0x100))throw new IllegalStateException("Connected DMA cache arguments");
                actions.add((pc==a("dma_prepare")?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);ret(e,0);continue;
            }
            if(nativeDma()&&pc==a("copy")){
                long out=r(e,0),in=r(e,1);int n=(int)r(e,2);
                if(nativeMutation()){
                    if(out==0x8130a000L&&n>=0&&n<=64&&(in>=BUFFER&&in+n<=BUFFER+512||n==1&&in>=0x81000000L&&in+1<=0x81001000L)){byte[] b=mem(e,in,n);if(n>0)e.writeMemory(toAddr(out),b);actions.add("write_input:"+n+":"+hash(b));ret(e,out);continue;}
                    if(out==BOUNCE&&in==0x8130a000L&&n==2112){e.writeMemory(toAddr(out),mem(e,in,n));actions.add("copy_to_bounce:"+n);ret(e,out);continue;}
                }
                if(nativeEftl()){
                    if(n>=0&&n<=64&&in==BOUNCE&&(out>=BUFFER&&out+n<=BUFFER+512||out==0x8130a800L&&n<=64)){if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));actions.add("copy_from_bounce:"+n);ret(e,out);continue;}
                    if(n>=0&&n<=4&&out>=BUFFER&&out+n<=BUFFER+4&&in>=0x8130a800L&&in+n<=0x8130a840L){if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));actions.add("oob_copy:"+(out-BUFFER)+":"+(in-0x8130a800L)+":"+n);ret(e,out);continue;}
                }
                if(nativeIdentity()&&out==BUFFER+1&&in==0x80df4370L){if(n<0||n>128||n!=(mem(e,0x80d81f24L,1)[0]&255))throw new IllegalStateException("UID export size");if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));actions.add("copy_uid:"+n);ret(e,out);continue;}
                if(n<0||n>64||!((out==BOUNCE&&in==BUFFER)||(out==BUFFER&&in==BOUNCE)))throw new IllegalStateException("Private-buffer copy arguments");
                if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));actions.add((out==BOUNCE?"copy_to_bounce:":"copy_from_bounce:")+n);ret(e,out);continue;
            }
            if(pc==a("version")){actions.add("version:2");ret(e,2);continue;}
            if(pc==a("diagnostic")){actions.add("diagnostic");ret(e,0);continue;}
            if(nativeIdentity()&&pc==a("logger")){
                long fmt=r(e,3);String name=switch((int)fmt){case 0x80c3e89c->"level_mismatch";case 0x80c3e87c->"feature_error";case 0x80c3e8c0->"retry_valid";case 0x80c3e8dc->"restore_failed";case 0x80c3e900->"retry_invalid";case 0x80c3e918->"level_register";case 0x80c3e92c->"check_level";case 0x80c3e954->"check_failed";case 0x80c3d878->"workaround_ok";case 0x80c3d6b0->"uid_feature_error";case 0x80c3d6d8->"uid_error";case 0x80c3d6e4->"uid_ok";case 0x80c3db08->"ioctl_error";default->null;};
                if(name!=null){String event="log:"+name;if(name.equals("uid_feature_error")||name.equals("uid_error"))event+=":"+(int)r(e,5);
                    if(name.equals("uid_ok")){StringBuilder text=new StringBuilder();boolean ended=false;for(int i=0;i<80;i++){int v=mem(e,r(e,6)+i,1)[0]&255;if(v==0){ended=true;break;}text.append((char)v);}if(!ended)throw new IllegalStateException("UID log string bound");event+=":"+r(e,5)+":"+text;}
                    actions.add(event);ret(e,0);continue;
                }
            }
            if(pc==a("logger")){
                String name=switch((int)r(e,3)){case 0x80c37a64->"command_error";case 0x80c37b14->"receive_poll_error";case 0x80c37b54->"transmit_poll_error";case 0x80c37a88->"receive_bounce_error";case 0x80c37acc->"transmit_bounce_error";case 0x80c3d8a8->"page_result";case 0x80c3d6a4->"busy_timeout";case 0x80c3d8f8->"page_guard";case 0x80c3d93c->"copy_result";case 0x80c3da4c->"block_guard";case 0x80c3da90->"erase_result";case 0x80c3db08->"chip_error";case 0x80c34244->"unmapped_block";case 0x80c3425c->"page_read_error";case 0x80c3c068->"storage_no_owner";case 0x80c3c0b4->"storage_bounds";case 0x80c3c114->"storage_read_error";case 0x80c3c148->"storage_program_error";case 0x80c3c180->"storage_erase_error";case 0x80c3c1f0->"storage_rewrite_error";case 0x80c3c1b8->"storage_rewrite_missing";case 0x80c34100->"eftl_write_alignment";case 0x80c34128->"eftl_sequence_error";case 0x80c3422c->"eftl_write_failed";case 0x80c33ff0->"eftl_map_full";case 0x80c33fac->"eftl_block_bad";case 0x80c33f68->"checksum_error";case 0x80c341a8->"eftl_readback_check_failed";case 0x80c34188->"eftl_readback_io_failed";default->throw new IllegalStateException("Unexpected HAL bus log");};
                actions.add("log:"+name);ret(e,0);continue;
            }
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            if(!nativeDma()&&pc==a("dma_setup")){
                boolean receive=c.get("mode").getAsString().contains("receive");long n=word(e,CTRL+20),data=BUFFER+c.get("alignment").getAsLong();
                if(n>64||r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=(receive?io.base+0x100:data)||r(e,2)!=(receive?data:io.base+0x100)||r(e,3)!=n)throw new IllegalStateException("DMA setup arguments");
                int status=c.get("dma_setup_status").getAsInt();byte[] payload=receive?new byte[0]:mem(e,data,(int)n);
                actions.add("dma_setup:"+(receive?"receive":"transmit")+":"+n+":"+io.regs.get(32L)+":"+status+":"+hash(payload));
                if(receive&&status==0&&c.get("dma_copy").getAsBoolean()&&n>0){byte[] b=new byte[(int)n];for(int i=0;i<n;i++)b[i]=(byte)(0x5a+i*7);e.writeMemory(toAddr(data),b);}ret(e,status);continue;
            }
            if(!nativeDma()&&pc==a("dma_wait")){
                boolean receive=c.get("mode").getAsString().contains("receive");if(r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=c.get("timeout").getAsLong())throw new IllegalStateException("DMA wait arguments");
                int status=c.get("dma_wait_status").getAsInt();actions.add("dma_wait:"+r(e,1)+":"+io.regs.get(32L)+":"+status);ret(e,status);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeDma())for(JsonElement span:cfg.getAsJsonArray("native_dma_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativePlatform())for(JsonElement span:cfg.getAsJsonArray("platform_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativePage())for(JsonElement span:cfg.getAsJsonArray("page_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeProgram())for(JsonElement span:cfg.getAsJsonArray("program_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeMaintenance())for(JsonElement span:cfg.getAsJsonArray("maintenance_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeIdentity())for(JsonElement span:cfg.getAsJsonArray("identity_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeDispatch())for(JsonElement span:cfg.getAsJsonArray("dispatch_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeEftl())for(JsonElement span:cfg.getAsJsonArray("eftl_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeStorage())for(JsonElement span:cfg.getAsJsonArray("storage_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeMutation())for(JsonElement span:cfg.getAsJsonArray("mutation_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeReadback())for(JsonElement span:cfg.getAsJsonArray("readback_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(fullPlatform()){
                var instruction=getInstructionAt(toAddr(pc));if(instruction!=null&&instruction.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+instruction.getLength());continue;}
            }
            boolean ok;io.active=true;try{ok=e.step(monitor);}finally{io.active=false;}
            if(!ok)throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=ticks=chunks=dmaTicks=driverCalls=storageCalls=0;dmaReceive=false;actions=new JsonArray();Helper e=new Helper(currentProgram);io=new Io();io.base=c.get("base").getAsLong();io.clock=c.get("clock_word").getAsLong();if(nativeIdentity())io.featureRegs.put(224L,c.get("e0").getAsLong());
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(sentinel,128));
            for(long[] f:new long[][]{{0,c.get("base_present").getAsBoolean()?io.base:0},{8,c.getAsJsonArray("flags").get(0).getAsLong()},{12,c.getAsJsonArray("flags").get(1).getAsLong()},
                {16,c.get("controller_mode").getAsLong()},{20,c.get("count").getAsLong()},{32,dmaPointer(0)},{36,dmaPointer(1)}})put(e,CTRL+f[0],4,f[1]);
            byte[] ctx=mem(e,CTRL,64),buffer=Arrays.copyOf(sentinel,544);for(int i=0;i<512;i++)buffer[i]=(byte)(i*3+1);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(BUFFER),buffer);
            e.writeMemory(toAddr(FRAME),Arrays.copyOf(sentinel,76));for(int i=0;i<11;i++)put(e,FRAME+i*4,4,c.getAsJsonArray("frame").get(i).getAsLong());byte[] frame=mem(e,FRAME,76);
            for(long[] f:new long[][]{{0,0x11111111L},{4,0x22222222L},{8,0x33333333L},{12,0x44444444L},{16,0x55555555L},{24,0},{32,c.get("control").getAsLong()},{36,0},{52,0x101},{84,c.get("fifo").getAsLong()}}){io.regs.put(f[0],f[1]);put(e,io.base+f[0],4,f[1]);}
            put(e,CLOCK,4,io.clock);put(e,SHADOW,4,0xa5a5a5a5L);e.filter(io);
            put(e,0x80d81f28L,4,0x80c3e518L);put(e,0x80d81d6cL,1,0);
            if(nativePlatform()){
                for(var item:c.getAsJsonObject("board_initial").entrySet()){long address=Long.parseLong(item.getKey()),value=item.getValue().getAsLong();io.boardRegs.put(address,value);put(e,address,4,value);}
            }
            if(nativeDma()){
                e.writeMemory(toAddr(BOUNCE),Arrays.copyOf(sentinel,nativeMutation()?2144:544));e.writeMemory(toAddr(TABLE-32),Arrays.copyOf(sentinel,176));e.writeMemory(toAddr(TABLE),new byte[112]);
                if(fullPlatform())e.writeMemory(toAddr(dmaPointer(1)-32),Arrays.copyOf(sentinel,200));
                for(int i=0;i<2;i++){long pointer=dmaPointer(i);byte[] b=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());if(b.length!=(fullPlatform()?68:80))throw new IllegalStateException("Connected DMA context size");if(!fullPlatform())e.writeMemory(toAddr(pointer-32),Arrays.copyOf(sentinel,144));e.writeMemory(toAddr(pointer),b);}
                JsonObject p=c.getAsJsonObject("dma_tx");io.dmaBase=p.get("base").getAsLong();
                for(long[] f:new long[][]{{4,p.get("irq_a").getAsLong()},{8,0x100},{12,p.get("irq_b").getAsLong()},{16,0x200},{20,0},{24,0},{36,p.get("enabled").getAsLong()}})io.dmaRegs.put(f[0],f[1]);
                for(int ch=0;ch<7;ch++)for(long[] f:new long[][]{{0x100,0x12340001},{0x104,0xffff},{0x108,0x11111111},{0x10c,0x22222222},{0x110,0x33333333},{0x114,0x44444444}})io.dmaRegs.put(ch*32+f[0],f[1]);
                for(var item:io.dmaRegs.entrySet())put(e,io.dmaBase+item.getKey(),4,item.getValue());
                if(!fullPlatform()){
                    entry(e,a("dma_init"),DMA0);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("TX DMA initialization failed");
                    entry(e,a("dma_init"),DMA1);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("RX DMA initialization failed");
                }
            }
            String mode=c.get("mode").getAsString();long controller=c.get("context_present").getAsBoolean()?CTRL:0,timeout=c.get("timeout").getAsLong(),data=BUFFER+c.get("alignment").getAsLong();
            byte[] descriptor=null;
            if(fullPlatform()){
                e.writeMemory(toAddr(CTRL),new byte[64]);put(e,CTRL+16,4,c.get("controller_mode").getAsLong());ctx=mem(e,CTRL,64);
                descriptor=new byte[184];currentProgram.getMemory().getBytes(toAddr(nativeIdentity()?c.getAsJsonObject("identity_descriptor").get("address").getAsLong():0x80c3e518L),descriptor);e.writeMemory(toAddr(0x81306000L),descriptor);put(e,0x8130600cL,4,c.get("bus_word").getAsLong());if(nativePage())put(e,0x81306096L,1,c.get("plane").getAsBoolean()?1:0);if(nativeIdentity()){JsonObject p=c.getAsJsonObject("identity_descriptor");for(Object[] f:new Object[][]{{0xa6,"uid_flag",1},{0xad,"uid_mode",1},{0xae,"uid_copies",1},{0xb4,"uid_size",4}})put(e,0x81306000L+(int)f[0],(int)f[2],p.get((String)f[1]).getAsLong());}descriptor=mem(e,0x81306000L,184);e.writeMemory(toAddr(0x813060b8L),Arrays.copyOf(sentinel,32));put(e,0x80d81f28L,4,0x81306000L);
                boolean deferred=c.get("defer_reinit").getAsBoolean();put(e,0x80d81d6cL,1,deferred?1:0);
                if(!deferred){entry(e,a("platform_init"),0x81306000L);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("Actual NAND platform initialization failed");}
                mode=mode.substring("platform_".length());
            }
            byte[] bbt=null;
            if(nativePage()){
                bbt=HexFormat.of().parseHex(c.get("bbt_hex").getAsString());if(bbt.length!=164)throw new IllegalStateException("Read BBT backing");e.writeMemory(toAddr(0x80df42ccL-32),Arrays.copyOf(sentinel,228));e.writeMemory(toAddr(0x80df42ccL),bbt);
                if(!c.get("chip").getAsBoolean())put(e,0x80d81f28L,4,0);
                if(nativeProgram()){put(e,0x80d81b2cL,1,c.get("guard").getAsBoolean()?1:0);put(e,0x80d81f20L,4,512);}
                if(nativeDispatch()){
                    byte[] part=Arrays.copyOf(sentinel,92);Arrays.fill(part,0,60,(byte)0);put(e,0x80d81f34L,4,2048);put(e,0x80d81f30L,4,65536);put(e,0x80d81f2cL,4,64);
                    e.writeMemory(toAddr(0x81308000L),part);put(e,0x81308030L,4,c.get("partition_base").getAsLong());put(e,0x81308034L,4,c.get("partition_span").getAsLong());
                    e.writeMemory(toAddr(0x81308300L),Arrays.copyOf(sentinel,64));for(int i=0;i<4;i++)put(e,0x81308300L+i*4,4,c.getAsJsonArray("arguments").get(i).getAsLong());
                    String state=c.get("driver_state").getAsString();byte[] ops=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80d811f4L),ops);e.writeMemory(toAddr(0x81308200L),ops);e.writeMemory(toAddr(0x81308220L),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(0x81308104L),Arrays.copyOf(sentinel,32));put(e,0x81308100L,4,state.equals("ops_missing")?0:0x81308200L);
                    if(state.equals("callback_missing")){put(e,0x81308208L,4,0);put(e,0x81308218L,4,0);}put(e,0x80d81f10L,4,state.equals("root_missing")?0:state.equals("ok")?0x80d81b28L:0x81308100L);put(e,0x80d81f14L,4,c.get("mutex_present").getAsBoolean()?0x81308400L:0);put(e,0x80d81f1cL,4,8);
                    String operation=c.get("dispatch_operation").getAsString();long handle=c.get("null_handle").getAsBoolean()?0:0x81308000L,out=c.get("null_output").getAsBoolean()?0:BUFFER;
                    if(nativeEftl()){
                        e.writeMemory(toAddr(0x80de5fb8L-32),Arrays.copyOf(sentinel,128));e.writeMemory(toAddr(0x80de5fb8L),new byte[64]);put(e,0x80de5fb8L,4,handle);put(e,0x80de5fbeL,1,c.get("fast").getAsBoolean()?1:0);
                        for(long[] f:new long[][]{{8,64},{12,2048},{24,c.get("fast_base").getAsLong()},{48,0x81309100L},{52,0x8130a000L}})put(e,0x80de5fb8L+f[0],4,f[1]);
                        put(e,0x80de5fb8L+28,2,64);put(e,0x80de5fb8L+30,2,c.get("ecc_total").getAsLong());put(e,0x80de5fb8L+32,2,c.get("ecc_unit").getAsLong());for(int i=0;i<4;i++)put(e,0x80de5fb8L+34+i*2,2,c.getAsJsonArray("positions").get(i).getAsLong());
                        e.writeMemory(toAddr(0x81309100L-32),Arrays.copyOf(sentinel,80));for(int i=0;i<8;i++)put(e,0x81309100L+i*2,2,c.getAsJsonArray("mapping").get(i).getAsLong());put(e,0x80d81ea2L,1,1);
                        byte[] scratch=new byte[2144];for(int i=0;i<2112;i++)scratch[i]=(byte)(i*5+7);Arrays.fill(scratch,2112,2144,(byte)0xa5);e.writeMemory(toAddr(0x8130a000L-32),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(0x8130a000L),scratch);
                        if(nativeReadback())put(e,0x80de5fb8L+5,1,c.get("write_readback").getAsBoolean()?1:0);
                        if(nativeMutation()){
                            e.writeMemory(toAddr(0x8130c000L-32),Arrays.copyOf(sentinel,72));int free=0,reserved=0;for(int i=0;i<8;i++){int flag=c.getAsJsonArray("write_flags").get(i).getAsInt();put(e,0x8130c000L+i,1,flag);if(flag==254)free++;reserved+=flag&1;}
                            put(e,0x80de5fb8L+16,4,8);put(e,0x80de5fb8L+44,4,0x8130c000L);put(e,0x80de5fb8L+56,2,free);put(e,0x80de5fb8L+58,2,8-free-reserved);put(e,0x80de5fb8L+60,2,reserved);
                        }
                        if(nativeStorage()){
                            byte[] table=new byte[960],backend=new byte[76];currentProgram.getMemory().getBytes(toAddr(0x80c33a38L),table);currentProgram.getMemory().getBytes(toAddr(0x80d80fb8L),backend);
                            int selected=-1;String query=c.get("storage_name").getAsString();for(int i=0;i<16;i++){int end=i*60;while(end<i*60+24&&table[end]!=0)end++;if(new String(table,i*60,end-i*60,java.nio.charset.StandardCharsets.US_ASCII).equals(query))selected=i;}
                            if(selected<0)throw new IllegalStateException("Storage partition name");e.writeMemory(toAddr(0x8130b100L),table);e.writeMemory(toAddr(0x8130b4c0L),Arrays.copyOf(sentinel,32));
                            if(c.get("storage_span").getAsLong()>=0)put(e,0x8130b100L+selected*60+52,4,c.get("storage_span").getAsLong());
                            e.writeMemory(toAddr(0x8130b600L),backend);e.writeMemory(toAddr(0x8130b64cL),Arrays.copyOf(sentinel,32));put(e,0x8130b61cL,4,c.get("storage_capacity").getAsLong());if(nativeMutation()&&c.get("rewrite_missing").getAsBoolean())put(e,0x8130b638L,4,0);
                            e.writeMemory(toAddr(0x8130b000L),new byte[64]);e.writeMemory(toAddr(0x8130b040L),Arrays.copyOf(sentinel,32));
                            for(int i=0;i<16;i++){boolean isEftl=table[i*60+24]=='e'&&table[i*60+25]=='f'&&table[i*60+26]=='t'&&table[i*60+27]=='l';put(e,0x8130b000L+i*4,4,isEftl&&!(i==selected&&c.get("storage_owner_missing").getAsBoolean())?0x8130b600L:0);}
                            put(e,0x80d81ee0L,4,0x8130b100L);put(e,0x80d81ed8L,4,16);put(e,0x80d81ed4L,4,0x8130b000L);put(e,0x80d81edcL,1,1);
                            String handleKind=c.get("storage_handle").getAsString();long storageHandle=handleKind.equals("null")?0:handleKind.equals("below")?0x8130b100L-60:handleKind.equals("above")?0x8130b4c0L:0x8130b100L+selected*60;
                            if(nativeMutation()){
                                String mutation=c.get("mutation_operation").getAsString();if(mutation.equals("erase"))entry(e,a("storage_erase"),storageHandle,c.get("storage_offset").getAsLong(),c.get("storage_size").getAsLong());
                                else entry(e,a("storage_"+mutation),storageHandle,c.get("storage_offset").getAsLong(),c.get("storage_null_output").getAsBoolean()?0:BUFFER,c.get("storage_size").getAsLong());
                            }else entry(e,a("storage_read"),storageHandle,c.get("storage_offset").getAsLong(),c.get("storage_null_output").getAsBoolean()?0:BUFFER,c.get("storage_size").getAsLong());
                        }else if(operation.equals("eftl_page"))entry(e,a(operation),0x80de5fb8L,BUFFER,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong());
                        else if(operation.equals("eftl_oob"))entry(e,a(operation),0x80de5fb8L,c.get("page").getAsLong(),BUFFER);
                        else if(operation.equals("eftl_wrapper"))entry(e,a(operation),c.get("offset").getAsLong(),BUFFER,c.get("count").getAsLong());
                        else entry(e,a("eftl_map"),0x80de5fb8L,BUFFER,c.get("offset").getAsLong(),c.get("count").getAsLong());
                    }else if(operation.equals("partition_read"))entry(e,a(operation),handle,out,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong());
                    else if(operation.equals("driver_read"))entry(e,a("dispatch_read"),0x81308018L,out,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong());
                    else if(operation.equals("partition_ioctl"))entry(e,a(operation),handle,c.get("query").getAsLong(),c.get("null_argument").getAsBoolean()?0:0x81308300L);
                    else entry(e,a("dispatch_ioctl"),0x81308018L,c.get("query").getAsLong(),0x81308300L);
                }else if(nativeIdentity()){
                    e.writeMemory(toAddr(0x80df4370L),Arrays.copyOf(sentinel,160));put(e,0x80d81f24L,1,c.get("initial_uid_length").getAsLong());
                    if(mode.equals("page_read"))entry(e,a(mode),data,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong(),c.get("blocking").getAsBoolean()?1:0);
                    else if(mode.equals("identity_level"))entry(e,a(mode),c.get("level").getAsLong());
                    else if(mode.equals("identity_retry"))entry(e,a(mode),c.get("page").getAsLong());
                    else if(mode.equals("identity_uid_export")){entry(e,a("identity_uid"));if(stopped==null)entry(e,a("identity_ioctl"),24,BUFFER,1);}
                    else entry(e,a(mode));
                }else if(nativeMaintenance()){
                    put(e,0x80d81f1cL,4,8);
                    if(mode.equals("erase"))entry(e,a(mode),c.get("block").getAsLong(),c.get("blocking").getAsBoolean()?1:0);
                    else if(mode.equals("copy_page"))entry(e,a(mode),c.get("page").getAsLong(),c.get("dest").getAsLong());
                    else if(mode.equals("copy_oob"))entry(e,a(mode),c.get("page").getAsLong(),c.get("dest").getAsLong(),data,c.get("count").getAsLong());
                    else throw new IllegalArgumentException("Maintenance root");
                }else entry(e,a(mode),c.get("buffer").getAsBoolean()?data:0,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong(),c.get("blocking").getAsBoolean()?1:0);
            }
            else if(fullPlatform()&&mode.equals("init")){}
            else if(mode.equals("pinmux")||mode.equals("pin_function"))entry(e,a(mode),c.get("pin_p0").getAsLong(),c.get("pin_p1").getAsLong(),c.get("pin_value").getAsLong());
            else if(mode.equals("clock"))entry(e,a(mode),c.get("clock_select").getAsLong());
            else if(mode.equals("init"))entry(e,a(mode),controller);
            else if(mode.equals("pack"))entry(e,a(mode),FRAME);
            else if(mode.equals("rx_count")||mode.equals("tx_count"))entry(e,a(mode),io.base);
            else if(mode.equals("complete")||mode.equals("wait_receive")||mode.equals("wait_transmit"))entry(e,a(mode),controller,timeout);
            else if(mode.equals("feature_read"))entry(e,a(mode),c.get("feature_register").getAsLong(),data);
            else if(mode.equals("feature_write"))entry(e,a(mode),c.get("feature_register").getAsLong(),c.get("feature_value").getAsLong());
            else if(mode.equals("cache_read")||mode.equals("cache_write"))entry(e,a(mode),c.get("address").getAsLong(),data,c.get("count").getAsLong(),0);
            else if(nativeDma()&&(mode.equals("cache_read_bounce")||mode.equals("cache_write_bounce")))entry(e,a(mode),c.get("address").getAsLong(),data,c.get("count").getAsLong(),0);
            else if(mode.equals("write_enable"))entry(e,a(mode));
            else{
                if(mode.startsWith("command"))entry(e,a("command"),controller,c.get("frame_present").getAsBoolean()?FRAME:0,timeout);
                if(!mode.equals("command")&&(!mode.startsWith("command")||r(e,0)==0))entry(e,a(mode.replace("command_","")),controller,data,timeout);
            }
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{CTRL-32,nativeDma()?BOUNCE+(nativeMutation()?2112:512):CTRL+64,BUFFER-32,BUFFER+512})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("HAL guard changed");
            byte[] endCtx=mem(e,CTRL,64);System.arraycopy(ctx,20,endCtx,20,4);if(fullPlatform())for(int at:new int[]{0,8,12,32,36})System.arraycopy(ctx,at,endCtx,at,4);if(!Arrays.equals(ctx,endCtx)||!Arrays.equals(frame,mem(e,FRAME,76)))throw new IllegalStateException("HAL input changed");
            JsonObject row=new JsonObject();row.add("returned",stopped==null&&!mode.equals("pinmux")&&!mode.equals("pin_function")&&!mode.equals("identity_uid")?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("context_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("tx_hex",HexFormat.of().formatHex(io.tx.toByteArray()));row.addProperty("rx_bytes",io.rx);
            JsonObject mmio=new JsonObject();for(var item:io.regs.entrySet())mmio.addProperty(Long.toString(item.getKey()),item.getValue());row.add("mmio",mmio);row.addProperty("clock_word",io.clock);row.addProperty("clock_shadow",word(e,SHADOW));
            if(nativeDma()){
                JsonArray contexts=new JsonArray();for(int i=0;i<2;i++){
                    long pointer=dmaPointer(i);int length=fullPlatform()?68:80;byte[] b=mem(e,pointer,length),original=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());contexts.add(HexFormat.of().formatHex(b));
                    System.arraycopy(original,60,b,60,8);if(fullPlatform()){System.arraycopy(original,0,b,0,40);System.arraycopy(original,44,b,44,4);}
                    if(!Arrays.equals(original,b)||!fullPlatform()&&(!Arrays.equals(guard,mem(e,pointer-32,32))||!Arrays.equals(guard,mem(e,pointer+80,32))))throw new IllegalStateException("Connected DMA context/guard changed");
                }row.add("dma_contexts_hex",contexts);JsonArray registry=new JsonArray();for(int i=0;i<28;i++)registry.add(word(e,TABLE+i*4));row.add("dma_registry",registry);
                JsonObject regs=new JsonObject();for(var item:io.dmaRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("dma_mmio",regs);row.addProperty("bounce_sha256",hash(mem(e,BOUNCE,nativeMutation()?2112:512)));
                for(long at:new long[]{TABLE-32,TABLE+112})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Connected DMA registry guard");
                if(fullPlatform())for(long at:new long[]{dmaPointer(1)-32,dmaPointer(0)+68})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Adjacent original DMA guard");
            }
            if(nativePage()){
                if(!Arrays.equals(bbt,mem(e,0x80df42ccL,164))||!Arrays.equals(guard,mem(e,0x80df42ccL-32,32))||!Arrays.equals(guard,mem(e,nativeIdentity()?0x80df4370L+128:0x80df42ccL+164,32)))throw new IllegalStateException("Read BBT input/guard changed");
                row.addProperty("feature_reads",io.featureReads);
            }
            if(nativeIdentity()){
                row.addProperty("uid_length",mem(e,0x80d81f24L,1)[0]&255);row.addProperty("uid_sha256",hash(mem(e,0x80df4370L,128)));row.addProperty("status_reads",io.statusReads);row.addProperty("e0_reads",io.e0Reads);
                JsonObject regs=new JsonObject();for(var item:io.featureRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("feature_registers",regs);
            }
            if(nativeDispatch()){
                row.addProperty("argument_hex",HexFormat.of().formatHex(mem(e,0x81308300L,32)));row.addProperty("driver_calls",driverCalls);
                byte[] part=new byte[60];for(int i=0;i<4;i++){part[48+i]=(byte)(c.get("partition_base").getAsLong()>>>(8*i));part[52+i]=(byte)(c.get("partition_span").getAsLong()>>>(8*i));}
                if(!Arrays.equals(part,mem(e,0x81308000L,60)))throw new IllegalStateException("Partition descriptor changed");
                for(long at:new long[]{0x8130803cL,0x81308104L,0x81308220L,0x81308320L})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Dispatch guards");
            }
            if(nativeEftl()){
                row.addProperty("scratch_sha256",hash(mem(e,0x8130a000L,2112)));row.addProperty("eftl_context_hex",HexFormat.of().formatHex(mem(e,0x80de5fb8L,64)));row.addProperty("mapping_hex",HexFormat.of().formatHex(mem(e,0x81309100L,16)));
                for(long at:new long[]{0x80de5fb8L-32,0x80de5fb8L+64,0x81309100L-32,0x81309100L+16,0x8130a000L-32,0x8130a000L+2112})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("EFTL guards");
            }
            if(nativeStorage()){
                row.addProperty("storage_backend_calls",storageCalls);row.addProperty("storage_table_sha256",hash(mem(e,0x8130b100L,960)));row.addProperty("storage_backend_sha256",hash(mem(e,0x8130b600L,76)));row.addProperty("storage_owners_sha256",hash(mem(e,0x8130b000L,64)));
                for(long at:new long[]{0x8130b040L,0x8130b4c0L,0x8130b64cL})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Storage guards");
            }
            if(nativeMutation()){row.addProperty("write_flags_hex",HexFormat.of().formatHex(mem(e,0x8130c000L,8)));for(long at:new long[]{0x8130c000L-32,0x8130c008L})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Write flag guards");}
            if(nativePlatform()){JsonObject regs=new JsonObject();for(var item:io.boardRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("board_mmio",regs);}
            if(fullPlatform()){
                if(!Arrays.equals(descriptor,mem(e,0x81306000L,184))||!Arrays.equals(guard,mem(e,0x813060b8L,32)))throw new IllegalStateException("Platform descriptor changed");
                row.addProperty("reinit_flag",mem(e,0x80d81d6cL,1)[0]&255);
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/qspi-hal-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized QSPI HAL code");}
        for(JsonElement item:cfg.getAsJsonArray("native_dma_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected DMA code");}
        for(JsonElement item:cfg.getAsJsonArray("platform_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND platform code/data");}
        for(JsonElement item:cfg.getAsJsonArray("page_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected NAND read code/data");}
        for(JsonElement item:cfg.getAsJsonArray("program_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND program code");}
        for(JsonElement item:cfg.getAsJsonArray("maintenance_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND maintenance code");}
        for(JsonElement item:cfg.getAsJsonArray("identity_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected identity code/data");}
        for(JsonElement item:cfg.getAsJsonArray("dispatch_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND dispatch code/data");}
        for(JsonElement item:cfg.getAsJsonArray("eftl_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected EFTL code");}
        for(JsonElement item:cfg.getAsJsonArray("storage_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized storage/EFTL code/data");}
        for(JsonElement item:cfg.getAsJsonArray("mutation_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized EFTL mutation code");}
        for(JsonElement item:cfg.getAsJsonArray("readback_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized EFTL readback code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");executionBound=input.has("bound_per_case")?input.get("bound_per_case").getAsInt():100000;if(executionBound<1||executionBound>1500000)throw new IllegalArgumentException("Execution bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",executionBound);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("QSPI_HAL_VALIDATION cases="+rows.size());
    }
}
