package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * The generator set {@code bulletproof-bls12-381-g1-gens-v1} and the Pedersen bases it is used with
 * (spec {@code bulletproof-range-bls12-381-g1-v1} §2, Appendix A).
 *
 * <p>The 129 encodings are the pinned values of Appendix A; nothing is hashed at run time (spec
 * §2.4). {@code BulletproofGeneratorReproductionTest} recomputes them with RFC 9380
 * {@code hash_to_curve}. On first use the holder checks the pinned octets against {@link #D_GENS_HEX},
 * decodes every point with the strict decoder (curve and prime-order subgroup, not the identity),
 * and checks the §2.2 rule that no two of the 131 points are equal or negatives. A failure is an
 * {@link IllegalStateException}: the constants are corrupt and nothing can be proved or verified.
 *
 * <p>{@code G} and {@code H} are the {@code pedersen-bls12-381-g1-basis-v1} bases of
 * {@code pedersen-bls12-381-g1-v1.md} §2.2, pinned here because that package keeps them private;
 * {@code BulletproofBasesTest} checks them against the G1 Pedersen profile.
 */
final class BulletproofGenerators {

    /** The largest width; the set holds this many {@code G_i} and {@code H_i}. */
    static final int MAX_BITS = 64;

    /** The generator-set tag, 70 ASCII octets (spec §2.1). Recorded for reproduction; not hashed here. */
    static final String DST_BP = "ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    /** {@code D_gens} (spec §2.3). */
    static final String D_GENS_HEX = "69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19";

    /** Compressed {@code G} (pedersen-bls12-381-g1-v1.md §2.2). */
    static final String G_HEX = "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";

    /** Compressed {@code H} (pedersen-bls12-381-g1-v1.md §2.2). */
    static final String H_HEX = "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";

    /** Compressed {@code G_0 … G_63} (Appendix A). */
    static final List<String> G_VEC_HEX = List.of(
            "82ca0040fdcaae82d1dd666dbddaa09c3cd9546ab3a31150cd56385b167c7e0ac100305d0896a5615281c9aa8712190b",
            "ac1f919ad08cf6a24a80d52f4c1172410b3ab1b270374b74c4da4ea21437fd1825b142af9722681a66c06aa0409b7403",
            "aa4c2692fef0dbb5a11daaf2c19b891d5d050a99d836535825c83d5fd2637d177aac09bd0d8635c62f6551cc19abacb7",
            "8c9dfe0243bfe1e91df7600949ad27fbe8ff0e164abc6c4fc1cf8cadd390c9ce431adad19e2131cc23853c9d587e308d",
            "83887742c598d9379529b8ea56833714a755263464eed57d2f706017c0965b55c875d399e4fc213217870cb429ea1dec",
            "8112ec3a3970c6b161517be9556db196d38edbe3ebd711e8e63cf3a3784e85b1aecee28cde8489e4288d32194a616c43",
            "a223e918ab25d78ad06114eeb0f1faceec148762b1a3c0986ef33395d67c3ede73dc31bc492c0cf5b03ebf3a7f715e22",
            "8580881b258e4aebcd9d96890a69931681b039611655dddedb51ea0ac8adc8536b3287e01518972b14f5ba71c024c8d9",
            "946af27a4477e27a09d34533ab02fef35ae67845c032f6fe5a443b005ffbb4881f0acd9ff3cfb88a744139933fab48c2",
            "80b182fafc8dafe415f496029412ffb94fd25495640448863f52469e218844721005ca243868793ef16839fe36f1f914",
            "8b2db246d53eeebd0a0ea1bee579f26fba41a9547926585a358f9f2490a449a0774f2c9ff6c46168c0b3d55ad1276ee6",
            "b8575f5c69058ead8d9a5f5e043eb4960da3fa3239103c95a45f5eda9281074bab5d6b5b2189fd68b4c40e901a3cb583",
            "8ace2f20ae4f5465ea892a72b824b32ef76e0e2a5178f0f4cb8f0fef386ff4a7fbb1951e7b53706761cdc582824f58ab",
            "b9eee450b606958308b270dba17b26c072796b455183f7e260d33b4f10b9b574ef1c1e291ee7c18eec76a38348a31644",
            "b73ef17b180e6ca9e44ecea3b00036d9ad1bd3a8193c0fb48bb65968add218fbf02c8e60d809990ddc6f58af51451f7b",
            "b4c7d95f314229cd84c4d45ef6e92e803d9caffeb0ee574f3f2578f5404382e160924bd0ebff8226e78ace6af44a4176",
            "80c7604574dafa6d29d33a0b28702598f6be7f63786b258586d96b520d05c9c5c3b40bf71f27367e94c6df49082c82a1",
            "a86a50f44ac52c51ef9deb036fa9eb1e79a7938113102daceb90d0ecd415f593a8aec64767ad4111db0bd95226b48f58",
            "8444d6d94457f70f175317e0af70e1add29801bbf75fcb5f0c567e4ac5925bf54b816e365239ecf3f6a6004ec7beddc9",
            "95acecda5b597c997f57f255e87ee1c5cb03e83db81cf9506f161fc5f57f1de2fe16f85d453226c4f8ff03482585ac59",
            "84cd34e19db686d063279702d2e64d951cf496fe1c2ff6f983a3ac4f1813449955a466de037e276ae62848eb6ccd093c",
            "96ffe43ad0dad038094fcd1bc1f356aec4973b0b144019da92ea0bed3f0a9feced6a2a454f586e906de512e6be2e4227",
            "b659f7c852783d758f75ecdfb23efb73833cd64e2f49d0a75c1d955bb7d9f5b8683b0282d5c61ee70663e5c6ca0cf5d6",
            "b3e968cc78943241b0e176bb24363de75542858591d2ff5f3327660627488853a8ea107594a59209fa0a5b10e5415d80",
            "9828e791bd610281fb29bdbfc1699682bc46b658d2982f6b77a2b67825d697646a655d1fba2f7816327bd6254706deeb",
            "94f0127fb8bfbfd0e34c6b5c3349301f5222781a7ce44d3334a684e9971be6f07658d47bc6ef7b565cef4b17d9c72813",
            "a75d23a5ba467f71cde7dbb0529069ae26ee0fa75465433548e0e9cc3d6cda82dac718d98924c82326d5d8bf3b88a7e1",
            "ae38be5289776c4d56e8caac024a408b9c70f99aa38658afb45ca8f5d91b07c1ef0295caf806126f0e8df92c5d94e6db",
            "a92a2020233d3305d9cbf8561ac6dace8873c54ae2a13aed29832f8df315763815905e5271b33f5e29ea47fc6b6b4f11",
            "b94aa4e0546775b028733e90fdcda6e22a5d3ff3521d5316ea66c6475f59edb40471d117e1a179143c308867ef47b3d7",
            "b799a248151f5fbbe2b1925dbb973dc560c6359bd27fa3a1bf1cbf0597d373a12af54d10ef710648b01db0c797cb9249",
            "b5aa689d9a7af0eed59d0e628d437dba8d04ad2c50b976d7a1c9ea2814c4242dc40bbad3228da413cb293f7d0996765d",
            "b8bb2238b78bf1c3d1215fa2410d8887c3160aafa7e37e2b72f737de1ee2fb6ccd0ddfd40e9c7cf5d0a18906f31c6cd2",
            "b985146a8b6d2b9405ad75ac7768b2bf00b98b92be8cf61d099543eb19d1461e1c1ca2423a0fe498d1e0066d51722d7c",
            "b8a851df1b4b378eca406b50d88ed3a8586bae1f07545f426295bba6ac2ff527fbac25ef67db1e5285753eeb73499280",
            "b3432854210f5ba00992dba5510fe94d5f806d587b2d6a59dd5bbcf44962615a5f6a04da532ca656773b05d414be8be4",
            "a1d420a83be98aecc722b72c8ffdd7ad7f9193753e688fecef39336655405bc041d825f2b3e4432a9785b6b9e8087230",
            "a2f4e5cf5bcf295db725e36b0b0f64dd2c2e9af9677efb869ebb71f22d32548862a4592a2f793add358d4fa413c96554",
            "a1b65f34dc9f903c5467f5880a04f48d208705341dcca5909692af1a3ba8a49b1ee5a343915f3f3a50a3d39fcff4d312",
            "8d820ca564f17e9b03e34c2e39704ce38904f2f83d9af763be566a4ae3ce70fd63c797492850d672197294a2ece300f5",
            "ac50be30f2fe0de55e957544a4f400ab2b43716a30a4dbf1cdb1c980d15459632fc3cd1249b3ec3bc71e5b4e5b9d8e0b",
            "979a715d1b76cef6090b972eccd5fdfff26a62577d3fb29359f23ba2a1c3e985b9f16bc59eb6169f0b2ab9c926e420a8",
            "a070feb73c96b54d34be3ce931c51d34ffbdf0a2c0eed717e2d19f995995a7055ff199b68543826f0522202bf452ea26",
            "a6be88ef610278f4861fe4a880bbf019e86b5bee439514160240dbb224935639c1c898b7f89e2fcc0219edd593275d7d",
            "9705f3e8c23af393d7a0cd1592ab49e2417d57167c36a5e6d10abe12335d4fcf789fafb503098bc291d247333822fa8a",
            "a7daa703335505a3722caa69f80b2d50168bfef796a8aaafffd9d23e8882f475d026a6b3f6bdca2895304ab571158685",
            "903946088346bb0631f9f498aa0badd47755038c83ad817a1c28a2babfda7cf18474da3d7e6b9f58731510ce2cb0da73",
            "b30c1cbe2ecd3d5c41d892e22986059686f1728934d788aaefb0b9ed4a4b073316b192a1ec4149142f4613e1ba5478e8",
            "86a7f5df2e571bd95f1e2b4f880db041affaed014e4e9d3a8533ede275ff25728d964036e5c68b80adfbfb4845cc7795",
            "842b7407d3ca099cc7e8635bf60ae8e7922cd01bd762947759107e127aad754da9476731cdeaa4be163e84c42a8b12e6",
            "a327ab9093ef86e9bec231c3e25c49ac7d3310f9b7adff09ebcf70759a46134971c33d56c506dd5932f12ad313d9c520",
            "ae12b7cb46c52023517c5d24ad07d28015b4dd3d3d7685fcecdd144253a1175d90dfd6cbed50370807a46ca84e9e2e62",
            "97d6ebd5e99c2b8a2469c9bfc866e16308bdc483fa2ebbac311140035648a87efb705731731fe6e5b714b9ea7bfa5608",
            "83c5493642d54e49748ef3fb20fe56a5f158b12bc2191e5e65abe8f7b4673ba67602a5a18a4a91328c330b8ca83177d3",
            "a68efd028f7a853a827310c8a7d6fd8655a72ebd891184e57cb98faa35fbb3adc529e093f17426c5529785e5df198e0e",
            "b24765b4823fbb60d3954da4845683834aea69d0ea1cb934559b150250c60cc52042936cb28aeaa214fc699fcfc43905",
            "aebb8f8c489c8c5882eb5fbbd0899cb2986a51af823956a128c1521fc2b3357e64b99a5a9cc25254086aed73f689fdc3",
            "aa9e1e0b820556457f429ce36d879c88f4798681ea49e1bfb0f940279eeaa0b1851a4a6295fdb626a71d0a7db237779c",
            "97f556bb64501b0790d9bd161318f8380d77ca798013d6dd0b083e4cd3e2588517131bdc2b7eee1cf7b342231210ba2a",
            "8349bf7cda99b9a62d4293121581a2a2dc019c20622b097d808aa2424d3f9c3d1371f7d4da29a2815f6b6af38fa51ed8",
            "b56aa2e47c241c227f260a6e8c16a40dfadf874edb17dc2185e77f204fc6d4f6283c4e4443b40dd907e7d63bbb98495a",
            "a5bc5bec83102faef7b09517c740c72ef2ae0481b5223e0b94efa47383d6b6078f324fb6984f552b421a26b6bf55da72",
            "8518f5a10b8e32f97c057adab4ac6ad07322caa9fb8555de9c367c58cb5765ecfbbb23ccdd041cd4cadeec420663089d",
            "ad1cbd97688003fb6963288fa9af2d6830a1798bdc5ad10fa0ffa0b0a7f804ab92150660f961111b8fb3b94477f1ba10");

    /** Compressed {@code H_0 … H_63} (Appendix A). */
    static final List<String> H_VEC_HEX = List.of(
            "b93983422e013af87d7cf978597e1acaff89d2d8179b6442a3519542d92e7bfaa8d9d6a55ca0ef231f9f5e9408ef21e7",
            "98c0cbce702916378201cfceb6838a5faf9967a4828d6205b54328ddd316ed5585d950466d2e43787923b3ef5ff38446",
            "8dc6dbc198f08040efda1e1cfc5863f33fc44c036de4021a0db61c869eb8c4106f0dbfb59eb1e6a1a2eecfd428bc4416",
            "b15e4a50d068f4d7e562b31e3ef2a2d14ca9962ad5250a189227a3db71c1ddb6bd8982215eb0654306ffb749a0c9f7e1",
            "9610c10418a4164b3278e953e90d6dd8745ec241ced30f6a5e714e1bd9e7acb61b901fd69af42a927da276ced872fb9a",
            "85a73b9a6c3f8cbd0cac63727a05e703596323d0e9238f423e91416cc56796231af8364f0a00e1b9166e507673ebe530",
            "b89b942c13dc91f981c69e394645ebca82690556ab9f4280c55a09dbad1084851f48013a5828ab01d056cfd832d29ce8",
            "90359fc6d85f732610202d8d4c5f8dfa35510a2898389bbc32e6490131d5aa8e820269499a6699fe9b2f637ee09023f4",
            "a7c80ebac1fd184bdb1dfdb9133cfe900f79ef5b5bb87e82f75e4ced6d469d15da7cf7353f15e460d7c875d08ad6ba8f",
            "887c7d989cd51e063734ba8c065fa85e43e846fd90d019a79353d0732232422c938ecdb82c26f56f9cfb456b60a925c1",
            "b7ecae415bd559a9f0d0e5b44b24c7007f7e75d31f04bbbf95c8a98fd40bd51a2f6a2aa5cec8a367740857932e86c428",
            "87e5bc155a914d529f9c22eb0ae196bf1e4dbde2a8042f9f17e31e13965c7bd405479a481a77baeb279f6108f408e191",
            "812f854ccad3328712724c5e28da74e288009e4dd75915a3218cabf2c79d4ca6438fe1d96779067b4f8997f39bd5c7d5",
            "af24e7fa99a91f1243b3bbd4e26d474a9205d4354f4d26cd0778820098a9208f24c9745d193e313d4ba85f009f72e5ce",
            "aff29eb712a5dc8b57b8eef5a45405e4fc9361173729d15110145f11cf1070ad7b19a1044ed3940e19302e4d241f17ec",
            "8daf8ea644e5938c43819d5d149f83875dc58272f1a78e750f2904355a37e9844265f7df1a2ffa88752fe56015c494de",
            "909b1a4b82fef76f8a97a3db2cc66ab401eb5aefd2b1faa1423be8e9db982ded6143de772dd1615bbd0978308b731ce5",
            "b909ea71b4dc9624b156d90380c84968751e60962610831d20b105d23c25e7997f9db6dcf848c107b047450aa3feb1f8",
            "a23a8111494471d2982ca5f5d42101d1ce4591d9f87c0311b262264db276d5aa1df84f9c88dfb8d6d9ac5420afd9a35e",
            "8f21ea555da04f49321dbc9919e442e82f40f2c2efeb1d941521d06010fc4a0864f9012d7f1c955899d11964e7218103",
            "85a617bc5631eb1050c0770387b0c213c110afa1ea93c1f36c4802685aeb88ec4c079ae7e16f4ec5473ff4039ea8aa9e",
            "8b28fdc6815faf9e3709e9f01ccc3f588c49f53161a61f1e5bd80eb29bb6390ef907d044cf43dc77c109d283e31cd71d",
            "b083bc506c6360c4151d73dde36ee0ebf155966c2554bd8d9e196823e59cfeef21ce49854a67d227f6095d978b00520d",
            "82aa105d3b4c0417969ac37cf98583fa6b6b3a9eb60182bc0b3ff8693eac561a023b78b351d616e11e234de8f37bbf5c",
            "9808fbded822ae330fa51cbbb8e0046773eedd991a0b41ec6d434ba795b349e8c3c0fe20928055bc5350564d39f6a1f0",
            "afca6f5a4a3dc2033ddf8119115d707d6027455996e82d29a014669569eb33890f29bf747d5c530153dd8c6e8ff9ad41",
            "8fd266d359c0f5046bf6185a5f58b55723dd1de7dd40449d31ffefba7f8167fecfd259e15d2a5d7a948f3e7302850aca",
            "96332b95406828450172f540f9e15aa1030db766c76b6dc8a62faf3ec67eb5a1c92499b8655ff3d38676e61261270c23",
            "83b7c7eead6d61f312088469bd2929763a48dedde38d0bdc390dfe39a514f6a0b565cedd05e54841c2e45f3e17b95a06",
            "b16ce8ced752a85e3fd0a46d037eceb9c35a88a583c42c2899de72dd1439c9def2adb3294941960d21ab0763b6accae0",
            "8d879228c967e8aee06d0deac0f4b3eb31a99fdebe8966df72487466198a8d12de21808f34d7828eaa92446bddb67579",
            "8d7a70096660d9de71785e2c0f3dedc22247818afb7b0700a67a1e0b47fb07bdcd194604da086d252adaeb54316cd6ed",
            "800aa1a19081f1e07f14d782facbd3b4327722d6ee70d60ce43d003c537853cb0f3283dabf045cfa56875387447e5302",
            "8383ee315aa3a320095d6ee1c2813bb29d8eceb4c9cba4acfb87ecd0e76054015952f9a143a585b472cb29ad1a6202a3",
            "a0230d60740bd1d84ce8eaf532a5ef547a164c49331ab14c87f4ee9a4a45de74938c6e47523649bd2c526068d8586416",
            "b1548ba89e0be98bb31cc8a6a848f8d9dc8463de2411b2421ebfd13a7899477ed06c77da08f62ac6cf698292aa7b2ecb",
            "b5f868d03d5b36127f772072d07da73e8ffa628a343193e29e3b628a20168218fca3958e544f96e3893b87039d01b6ac",
            "86295f005c35fe3e82fee184dde649b6a31e436eacf6454310c8349473f4222229c555bac27ec018c281f4c3533a5254",
            "acfee6ad9cf49d4b40f3b31230b7eb72bcf51914aad8d44232c1fe0a56e61db45b4b9f0b75a047955a3e185f4ab4f674",
            "85dbd71550c1a526c82e0c207afc42266f87308f34d1dbdfbade4baaa8e0950955cd6fb39a9064d6ff23f34979eff616",
            "98e71b85be177e2e439366f5480cb62d0b81052275cd3c43373a7c3a7d3fcac8c056debbd40d46fa5faff8fb8a933d44",
            "98934b2e522118f7ff9176b826313325b6de2b164dac70a44994d3335a28d6ff89a9c58b94fa82ce35e980618842b122",
            "b3b9214dd640019a3811b54708cbbd8b19d448b82f29d4d26c7b57b286ba2c9cef91a585346c46eec825ea61845823f4",
            "9365a88f37cf72a3c9eec14dab305dc4a145c585caa1962acdc68405adf3297b14de7322ada63efd2e9cd18d2aa09596",
            "984d815b09dfd668901862a3fb6c79dea02b2188b5a109600a1dcdb392e0948a6a243688fa0f27d94eb5af68bb53125a",
            "91dd73a88b28a9cd722952e0d4525af6e8e45c594fe6b60d6fe6977fb128c8b439504750337acc3a7e2dc849dcf3d918",
            "b47925aa8b0ad20a5e587db49534e050e28492395bf07d08dff1244181a3bd3b24142b311c1468a5b21a20ef22f19e15",
            "9240a367e5231aa3993d484d7558ad069cd47db0f911c7d84072260d18d375db0050c1c7cea9de993957bd5d8540b54d",
            "a4e2d1215644d063c6ffe28d174e57b4a2ff0ac136c9c4ef9241099cec2fe59cbc62dfea816282cb78bddbe26827123f",
            "a35617504745af2d67ab32618294917bb34a0f5f50f31b7870a0dd041bd309c1a59fad1ef59bd468a3020ddac5ab51bc",
            "9157aaa70da86db7d9d4c6752f0644c7071812992604607107cd149acf5627e1bb4ce653c9f916f0d12a3064e3778a6c",
            "b026929d3cf8d84202724fb7563bad8e899f48986d1c985a4dc72b728bbb293b980a99d8d834aad3763a05d95c8caa57",
            "89ebe83fa9044802819eb419a430c735904b186362336f56ae58fed133f523bcbef167e0e6992fbaf17fcd3d1fbb8024",
            "8c3cbe032a1076bf6820ce04c6b97ae9faf8d58d9c568defa643d75684f331dd17d35a4535f2918e29d776fb66aec531",
            "858698028abfaa4dec69ad78c98681a95e51f601ae3d13d84cad5ff619d351a7f7ea348f3caafdb5dd395f6046f9a934",
            "8c169e54240803ba610dc5cd28d642f776531d46f8bc3eed83341a59ad9fe6c0f3607cef54f287d0ff8fd26c7a4671af",
            "a040ee5baf6f8b0eca5b804e940df9396c3a68448bb75de7793c8de6d8ecdd532daa0f01aad7c5a623525433f95f03c1",
            "a46e4ccfe8aac7e57e0573a3939e8b0e0a119a8f0a7a5bd5fdcdb34028f7b05bb13042bb6eb8a2e6e8c46e97d3059cd9",
            "b34ca23cb48f86d1b621c7cd30a6424d8bb5ed1efcac94e44c3e3dced6f98807474462357e995a07306c898798d761de",
            "b59a0e9cd2cdca9fde74bd79173fb49e73c2d03a99eef390badcc2c577aca17b3b80ef8565a8871e256afe5f91bce6d1",
            "a8c1ed6549aadd56d03b37b4c2c11095226a78cdf6edde242b5d1e0de54966f1f044a6c5bf128dc73bf5b27e985d404e",
            "85e8bace88c1dd31d9f664907acba0f5c12859854226b4ba9be8fddef48f9be0a84f109e2bc33929ff3c3f1c1ccd0120",
            "b70f2a8733a09e9fb58f577b495d8a9a7b10959300047c3796ccd01b530807c6d3ac80d896c66a7a69bab8d5ec26279f",
            "82c6faca133082265707f8e2422692c79663999e3e87b919dddccfd3a67c23dcff5a5910bf58425b02deebcc56aa327b");

    /** Compressed {@code U} (Appendix A). */
    static final String U_HEX = "aaf94b4c700852ac8db3659ccfe7b0bbb7157c18ee881878fe1c2222b7eb31d73943af9a7d1c341dd2a1eb49eec7696e";

    private BulletproofGenerators() {
    }

    /** The value base {@code G}. */
    static G1Point g() {
        return Holder.G;
    }

    /** The blinding base {@code H}. */
    static G1Point h() {
        return Holder.H;
    }

    /** {@code G_i}, {@code 0 ≤ i < 64}. */
    static G1Point gVec(int i) {
        return Holder.G_VEC[i];
    }

    /** {@code H_i}, {@code 0 ≤ i < 64}. */
    static G1Point hVec(int i) {
        return Holder.H_VEC[i];
    }

    /** {@code U}, the inner-product generator. */
    static G1Point u() {
        return Holder.U;
    }

    /** A fresh copy of {@code D_gens}. */
    static byte[] digest() {
        return HexFormat.of().parseHex(D_GENS_HEX);
    }

    private static final class Holder {
        static final G1Point G = strict(G_HEX);
        static final G1Point H = strict(H_HEX);
        static final G1Point[] G_VEC = new G1Point[MAX_BITS];
        static final G1Point[] H_VEC = new G1Point[MAX_BITS];
        static final G1Point U;

        static {
            HexFormat hex = HexFormat.of();
            MessageDigest sha256;
            try {
                sha256 = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is not available", e);
            }
            if (G_VEC_HEX.size() != MAX_BITS || H_VEC_HEX.size() != MAX_BITS) {
                throw new IllegalStateException("bulletproof-bls12-381-g1-gens-v1 has the wrong size");
            }
            for (String s : G_VEC_HEX) sha256.update(hex.parseHex(s));
            for (String s : H_VEC_HEX) sha256.update(hex.parseHex(s));
            sha256.update(hex.parseHex(U_HEX));
            if (!MessageDigest.isEqual(sha256.digest(), hex.parseHex(D_GENS_HEX))) {
                throw new IllegalStateException("bulletproof-bls12-381-g1-gens-v1 does not match D_gens");
            }
            for (int i = 0; i < MAX_BITS; i++) {
                G_VEC[i] = strict(G_VEC_HEX.get(i));
                H_VEC[i] = strict(H_VEC_HEX.get(i));
            }
            U = strict(U_HEX);

            // Spec §2.2: no two of the 131 points are equal or negatives. For the same x, the only
            // points are ±P, so distinct x-coordinates are exactly that condition.
            Set<Object> xs = new HashSet<>();
            requireNewX(xs, G);
            requireNewX(xs, H);
            for (int i = 0; i < MAX_BITS; i++) {
                requireNewX(xs, G_VEC[i]);
                requireNewX(xs, H_VEC[i]);
            }
            requireNewX(xs, U);
        }

        private static void requireNewX(Set<Object> xs, G1Point p) {
            if (!xs.add(p.x())) {
                throw new IllegalStateException("bulletproof-bls12-381-g1-gens-v1 has two equal or opposite points");
            }
        }

        private static G1Point strict(String hexValue) {
            G1Point p;
            try {
                p = PointCodec.decode(HexFormat.of().parseHex(hexValue));
            } catch (CommitmentFormatException e) {
                throw new IllegalStateException("a pinned bulletproof generator is invalid: " + e.reason(), e);
            }
            return p;
        }
    }
}
