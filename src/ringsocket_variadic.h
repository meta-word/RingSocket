// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

// This header file contains helper macros that enable macros to expand into
// different child macros depending on the number of __VA_ARGS__ they are called
// with.

// Even though these 6 macros do exactly the same thing, they need to be defined
// separately, because they may need to be expanded inside the expansion of any
// of its sibling definitions (e.g., as is this case for RS_APP()); but, alas,
// the C preprocessor does not allow recursive expansion -- otherwise this file
// would be a _lot_ shorter.
#define RS_MACRIFY_SWITCH(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_SWITCH2(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_INIT(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_ARGC(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_TYPE(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_LOG(identifier, ...) identifier(__VA_ARGS__)
#define RS_MACRIFY_EACH(identifier, ...) identifier(__VA_ARGS__)

#define RS_256( \
    a001, a002, a003, a004, a005, a006, a007, a008, a009, a010, a011, a012, \
    a013, a014, a015, a016, a017, a018, a019, a020, a021, a022, a023, a024, \
    a025, a026, a027, a028, a029, a030, a031, a032, a033, a034, a035, a036, \
    a037, a038, a039, a040, a041, a042, a043, a044, a045, a046, a047, a048, \
    a049, a050, a051, a052, a053, a054, a055, a056, a057, a058, a059, a060, \
    a061, a062, a063, a064, a065, a066, a067, a068, a069, a070, a071, a072, \
    a073, a074, a075, a076, a077, a078, a079, a080, a081, a082, a083, a084, \
    a085, a086, a087, a088, a089, a090, a091, a092, a093, a094, a095, a096, \
    a097, a098, a099, a100, a101, a102, a103, a104, a105, a106, a107, a108, \
    a109, a110, a111, a112, a113, a114, a115, a116, a117, a118, a119, a120, \
    a121, a122, a123, a124, a125, a126, a127, a128, a129, a130, a131, a132, \
    a133, a134, a135, a136, a137, a138, a139, a140, a141, a142, a143, a144, \
    a145, a146, a147, a148, a149, a150, a151, a152, a153, a154, a155, a156, \
    a157, a158, a159, a160, a161, a162, a163, a164, a165, a166, a167, a168, \
    a169, a170, a171, a172, a173, a174, a175, a176, a177, a178, a179, a180, \
    a181, a182, a183, a184, a185, a186, a187, a188, a189, a190, a191, a192, \
    a193, a194, a195, a196, a197, a198, a199, a200, a201, a202, a203, a204, \
    a205, a206, a207, a208, a209, a210, a211, a212, a213, a214, a215, a216, \
    a217, a218, a219, a220, a221, a222, a223, a224, a225, a226, a227, a228, \
    a229, a230, a231, a232, a233, a234, a235, a236, a237, a238, a239, a240, \
    a241, a242, a243, a244, a245, a246, a247, a248, a249, a250, a251, a252, \
    a253, a254, a255, a256, \
    m001, m002, m003, m004, m005, m006, m007, m008, m009, m010, m011, m012, \
    m013, m014, m015, m016, m017, m018, m019, m020, m021, m022, m023, m024, \
    m025, m026, m027, m028, m029, m030, m031, m032, m033, m034, m035, m036, \
    m037, m038, m039, m040, m041, m042, m043, m044, m045, m046, m047, m048, \
    m049, m050, m051, m052, m053, m054, m055, m056, m057, m058, m059, m060, \
    m061, m062, m063, m064, m065, m066, m067, m068, m069, m070, m071, m072, \
    m073, m074, m075, m076, m077, m078, m079, m080, m081, m082, m083, m084, \
    m085, m086, m087, m088, m089, m090, m091, m092, m093, m094, m095, m096, \
    m097, m098, m099, m100, m101, m102, m103, m104, m105, m106, m107, m108, \
    m109, m110, m111, m112, m113, m114, m115, m116, m117, m118, m119, m120, \
    m121, m122, m123, m124, m125, m126, m127, m128, m129, m130, m131, m132, \
    m133, m134, m135, m136, m137, m138, m139, m140, m141, m142, m143, m144, \
    m145, m146, m147, m148, m149, m150, m151, m152, m153, m154, m155, m156, \
    m157, m158, m159, m160, m161, m162, m163, m164, m165, m166, m167, m168, \
    m169, m170, m171, m172, m173, m174, m175, m176, m177, m178, m179, m180, \
    m181, m182, m183, m184, m185, m186, m187, m188, m189, m190, m191, m192, \
    m193, m194, m195, m196, m197, m198, m199, m200, m201, m202, m203, m204, \
    m205, m206, m207, m208, m209, m210, m211, m212, m213, m214, m215, m216, \
    m217, m218, m219, m220, m221, m222, m223, m224, m225, m226, m227, m228, \
    m229, m230, m231, m232, m233, m234, m235, m236, m237, m238, m239, m240, \
    m241, m242, m243, m244, m245, m246, m247, m248, m249, m250, m251, m252, \
    m253, m254, m255, m256, \
    ...) m256

#define RS_256_2( \
        m001, m002, \
    ...) RS_256( \
    __VA_ARGS__, \
          m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, m002, \
    m002, m002, m002, m001, \
    placeholder_tail_for_va_args_count_less_than_2)

#define RS_256_3( \
        m001, m002, m003, \
    ...) RS_256( \
    __VA_ARGS__, \
          m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, m003, \
    m003, m003, m002, m001, \
    placeholder_tail_for_va_args_count_less_than_2)

#define RS_256_16( \
    m001, m002, m003, m004, m005, m006, m007, m008, m009, m010, m011, m012, \
    m013, m014, m015, m016, \
    ...) RS_256( \
    __VA_ARGS__, \
          m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, m016, \
    m016, m015, m014, m013, m012, m011, m010, m009, m008, m007, m006, m005, \
    m004, m003, m002, m001, \
    placeholder_tail_for_va_args_count_less_than_2)

#define RS_256_256( \
    m001, m002, m003, m004, m005, m006, m007, m008, m009, m010, m011, m012, \
    m013, m014, m015, m016, m017, m018, m019, m020, m021, m022, m023, m024, \
    m025, m026, m027, m028, m029, m030, m031, m032, m033, m034, m035, m036, \
    m037, m038, m039, m040, m041, m042, m043, m044, m045, m046, m047, m048, \
    m049, m050, m051, m052, m053, m054, m055, m056, m057, m058, m059, m060, \
    m061, m062, m063, m064, m065, m066, m067, m068, m069, m070, m071, m072, \
    m073, m074, m075, m076, m077, m078, m079, m080, m081, m082, m083, m084, \
    m085, m086, m087, m088, m089, m090, m091, m092, m093, m094, m095, m096, \
    m097, m098, m099, m100, m101, m102, m103, m104, m105, m106, m107, m108, \
    m109, m110, m111, m112, m113, m114, m115, m116, m117, m118, m119, m120, \
    m121, m122, m123, m124, m125, m126, m127, m128, m129, m130, m131, m132, \
    m133, m134, m135, m136, m137, m138, m139, m140, m141, m142, m143, m144, \
    m145, m146, m147, m148, m149, m150, m151, m152, m153, m154, m155, m156, \
    m157, m158, m159, m160, m161, m162, m163, m164, m165, m166, m167, m168, \
    m169, m170, m171, m172, m173, m174, m175, m176, m177, m178, m179, m180, \
    m181, m182, m183, m184, m185, m186, m187, m188, m189, m190, m191, m192, \
    m193, m194, m195, m196, m197, m198, m199, m200, m201, m202, m203, m204, \
    m205, m206, m207, m208, m209, m210, m211, m212, m213, m214, m215, m216, \
    m217, m218, m219, m220, m221, m222, m223, m224, m225, m226, m227, m228, \
    m229, m230, m231, m232, m233, m234, m235, m236, m237, m238, m239, m240, \
    m241, m242, m243, m244, m245, m246, m247, m248, m249, m250, m251, m252, \
    m253, m254, m255, m256, \
    ...) RS_256( \
    __VA_ARGS__, \
          m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, m256, \
    m256, m256, m256, m256, \
    m256, m255, m254, m253, m252, m251, m250, m249, m248, m247, m246, m245, \
    m244, m243, m242, m241, m240, m239, m238, m237, m236, m235, m234, m233, \
    m232, m231, m230, m229, m228, m227, m226, m225, m224, m223, m222, m221, \
    m220, m219, m218, m217, m216, m215, m214, m213, m212, m211, m210, m209, \
    m208, m207, m206, m205, m204, m203, m202, m201, m200, m199, m198, m197, \
    m196, m195, m194, m193, m192, m191, m190, m189, m188, m187, m186, m185, \
    m184, m183, m182, m181, m180, m179, m178, m177, m176, m175, m174, m173, \
    m172, m171, m170, m169, m168, m167, m166, m165, m164, m163, m162, m161, \
    m160, m159, m158, m157, m156, m155, m154, m153, m152, m151, m150, m149, \
    m148, m147, m146, m145, m144, m143, m142, m141, m140, m139, m138, m137, \
    m136, m135, m134, m133, m132, m131, m130, m129, m128, m127, m126, m125, \
    m124, m123, m122, m121, m120, m119, m118, m117, m116, m115, m114, m113, \
    m112, m111, m110, m109, m108, m107, m106, m105, m104, m103, m102, m101, \
    m100, m099, m098, m097, m096, m095, m094, m093, m092, m091, m090, m089, \
    m088, m087, m086, m085, m084, m083, m082, m081, m080, m079, m078, m077, \
    m076, m075, m074, m073, m072, m071, m070, m069, m068, m067, m066, m065, \
    m064, m063, m062, m061, m060, m059, m058, m057, m056, m055, m054, m053, \
    m052, m051, m050, m049, m048, m047, m046, m045, m044, m043, m042, m041, \
    m040, m039, m038, m037, m036, m035, m034, m033, m032, m031, m030, m029, \
    m028, m027, m026, m025, m024, m023, m022, m021, m020, m019, m018, m017, \
    m016, m015, m014, m013, m012, m011, m010, m009, m008, m007, m006, m005, \
    m004, m003, m002, m001, \
    placeholder_tail_for_va_args_count_less_than_2)

#define RS_PREFIX_EACH(prefix, ...) RS_MACRIFY_EACH(RS_256_256( \
    RS_PREFIX001, RS_PREFIX002, RS_PREFIX003, RS_PREFIX004, RS_PREFIX005, \
    RS_PREFIX006, RS_PREFIX007, RS_PREFIX008, RS_PREFIX009, RS_PREFIX010, \
    RS_PREFIX011, RS_PREFIX012, RS_PREFIX013, RS_PREFIX014, RS_PREFIX015, \
    RS_PREFIX016, RS_PREFIX017, RS_PREFIX018, RS_PREFIX019, RS_PREFIX020, \
    RS_PREFIX021, RS_PREFIX022, RS_PREFIX023, RS_PREFIX024, RS_PREFIX025, \
    RS_PREFIX026, RS_PREFIX027, RS_PREFIX028, RS_PREFIX029, RS_PREFIX030, \
    RS_PREFIX031, RS_PREFIX032, RS_PREFIX033, RS_PREFIX034, RS_PREFIX035, \
    RS_PREFIX036, RS_PREFIX037, RS_PREFIX038, RS_PREFIX039, RS_PREFIX040, \
    RS_PREFIX041, RS_PREFIX042, RS_PREFIX043, RS_PREFIX044, RS_PREFIX045, \
    RS_PREFIX046, RS_PREFIX047, RS_PREFIX048, RS_PREFIX049, RS_PREFIX050, \
    RS_PREFIX051, RS_PREFIX052, RS_PREFIX053, RS_PREFIX054, RS_PREFIX055, \
    RS_PREFIX056, RS_PREFIX057, RS_PREFIX058, RS_PREFIX059, RS_PREFIX060, \
    RS_PREFIX061, RS_PREFIX062, RS_PREFIX063, RS_PREFIX064, RS_PREFIX065, \
    RS_PREFIX066, RS_PREFIX067, RS_PREFIX068, RS_PREFIX069, RS_PREFIX070, \
    RS_PREFIX071, RS_PREFIX072, RS_PREFIX073, RS_PREFIX074, RS_PREFIX075, \
    RS_PREFIX076, RS_PREFIX077, RS_PREFIX078, RS_PREFIX079, RS_PREFIX080, \
    RS_PREFIX081, RS_PREFIX082, RS_PREFIX083, RS_PREFIX084, RS_PREFIX085, \
    RS_PREFIX086, RS_PREFIX087, RS_PREFIX088, RS_PREFIX089, RS_PREFIX090, \
    RS_PREFIX091, RS_PREFIX092, RS_PREFIX093, RS_PREFIX094, RS_PREFIX095, \
    RS_PREFIX096, RS_PREFIX097, RS_PREFIX098, RS_PREFIX099, RS_PREFIX100, \
    RS_PREFIX101, RS_PREFIX102, RS_PREFIX103, RS_PREFIX104, RS_PREFIX105, \
    RS_PREFIX106, RS_PREFIX107, RS_PREFIX108, RS_PREFIX109, RS_PREFIX110, \
    RS_PREFIX111, RS_PREFIX112, RS_PREFIX113, RS_PREFIX114, RS_PREFIX115, \
    RS_PREFIX116, RS_PREFIX117, RS_PREFIX118, RS_PREFIX119, RS_PREFIX120, \
    RS_PREFIX121, RS_PREFIX122, RS_PREFIX123, RS_PREFIX124, RS_PREFIX125, \
    RS_PREFIX126, RS_PREFIX127, RS_PREFIX128, RS_PREFIX129, RS_PREFIX130, \
    RS_PREFIX131, RS_PREFIX132, RS_PREFIX133, RS_PREFIX134, RS_PREFIX135, \
    RS_PREFIX136, RS_PREFIX137, RS_PREFIX138, RS_PREFIX139, RS_PREFIX140, \
    RS_PREFIX141, RS_PREFIX142, RS_PREFIX143, RS_PREFIX144, RS_PREFIX145, \
    RS_PREFIX146, RS_PREFIX147, RS_PREFIX148, RS_PREFIX149, RS_PREFIX150, \
    RS_PREFIX151, RS_PREFIX152, RS_PREFIX153, RS_PREFIX154, RS_PREFIX155, \
    RS_PREFIX156, RS_PREFIX157, RS_PREFIX158, RS_PREFIX159, RS_PREFIX160, \
    RS_PREFIX161, RS_PREFIX162, RS_PREFIX163, RS_PREFIX164, RS_PREFIX165, \
    RS_PREFIX166, RS_PREFIX167, RS_PREFIX168, RS_PREFIX169, RS_PREFIX170, \
    RS_PREFIX171, RS_PREFIX172, RS_PREFIX173, RS_PREFIX174, RS_PREFIX175, \
    RS_PREFIX176, RS_PREFIX177, RS_PREFIX178, RS_PREFIX179, RS_PREFIX180, \
    RS_PREFIX181, RS_PREFIX182, RS_PREFIX183, RS_PREFIX184, RS_PREFIX185, \
    RS_PREFIX186, RS_PREFIX187, RS_PREFIX188, RS_PREFIX189, RS_PREFIX190, \
    RS_PREFIX191, RS_PREFIX192, RS_PREFIX193, RS_PREFIX194, RS_PREFIX195, \
    RS_PREFIX196, RS_PREFIX197, RS_PREFIX198, RS_PREFIX199, RS_PREFIX200, \
    RS_PREFIX201, RS_PREFIX202, RS_PREFIX203, RS_PREFIX204, RS_PREFIX205, \
    RS_PREFIX206, RS_PREFIX207, RS_PREFIX208, RS_PREFIX209, RS_PREFIX210, \
    RS_PREFIX211, RS_PREFIX212, RS_PREFIX213, RS_PREFIX214, RS_PREFIX215, \
    RS_PREFIX216, RS_PREFIX217, RS_PREFIX218, RS_PREFIX219, RS_PREFIX220, \
    RS_PREFIX221, RS_PREFIX222, RS_PREFIX223, RS_PREFIX224, RS_PREFIX225, \
    RS_PREFIX226, RS_PREFIX227, RS_PREFIX228, RS_PREFIX229, RS_PREFIX230, \
    RS_PREFIX231, RS_PREFIX232, RS_PREFIX233, RS_PREFIX234, RS_PREFIX235, \
    RS_PREFIX236, RS_PREFIX237, RS_PREFIX238, RS_PREFIX239, RS_PREFIX240, \
    RS_PREFIX241, RS_PREFIX242, RS_PREFIX243, RS_PREFIX244, RS_PREFIX245, \
    RS_PREFIX246, RS_PREFIX247, RS_PREFIX248, RS_PREFIX249, RS_PREFIX250, \
    RS_PREFIX251, RS_PREFIX252, RS_PREFIX253, RS_PREFIX254, RS_PREFIX255, \
    RS_PREFIX256, __VA_ARGS__), prefix, __VA_ARGS__)

#define RS_PREFIX001(pre, macro) pre##macro
#define RS_PREFIX002(pre, m1, m2) pre##m1; pre##m2
#define RS_PREFIX003(pre, m1, m2, m3) pre##m1; pre##m2; pre##m3
#define RS_PREFIX004(pre, m1, m2, m3, m4) pre##m1; pre##m2; pre##m3; pre##m4
#define RS_PREFIX005(pre, macro, ...) pre##macro; RS_PREFIX004(pre, __VA_ARGS__)
#define RS_PREFIX006(pre, macro, ...) pre##macro; RS_PREFIX005(pre, __VA_ARGS__)
#define RS_PREFIX007(pre, macro, ...) pre##macro; RS_PREFIX006(pre, __VA_ARGS__)
#define RS_PREFIX008(pre, macro, ...) pre##macro; RS_PREFIX007(pre, __VA_ARGS__)
#define RS_PREFIX009(pre, macro, ...) pre##macro; RS_PREFIX008(pre, __VA_ARGS__)
#define RS_PREFIX010(pre, macro, ...) pre##macro; RS_PREFIX009(pre, __VA_ARGS__)
#define RS_PREFIX011(pre, macro, ...) pre##macro; RS_PREFIX010(pre, __VA_ARGS__)
#define RS_PREFIX012(pre, macro, ...) pre##macro; RS_PREFIX011(pre, __VA_ARGS__)
#define RS_PREFIX013(pre, macro, ...) pre##macro; RS_PREFIX012(pre, __VA_ARGS__)
#define RS_PREFIX014(pre, macro, ...) pre##macro; RS_PREFIX013(pre, __VA_ARGS__)
#define RS_PREFIX015(pre, macro, ...) pre##macro; RS_PREFIX014(pre, __VA_ARGS__)
#define RS_PREFIX016(pre, macro, ...) pre##macro; RS_PREFIX015(pre, __VA_ARGS__)
#define RS_PREFIX017(pre, macro, ...) pre##macro; RS_PREFIX016(pre, __VA_ARGS__)
#define RS_PREFIX018(pre, macro, ...) pre##macro; RS_PREFIX017(pre, __VA_ARGS__)
#define RS_PREFIX019(pre, macro, ...) pre##macro; RS_PREFIX018(pre, __VA_ARGS__)
#define RS_PREFIX020(pre, macro, ...) pre##macro; RS_PREFIX019(pre, __VA_ARGS__)
#define RS_PREFIX021(pre, macro, ...) pre##macro; RS_PREFIX020(pre, __VA_ARGS__)
#define RS_PREFIX022(pre, macro, ...) pre##macro; RS_PREFIX021(pre, __VA_ARGS__)
#define RS_PREFIX023(pre, macro, ...) pre##macro; RS_PREFIX022(pre, __VA_ARGS__)
#define RS_PREFIX024(pre, macro, ...) pre##macro; RS_PREFIX023(pre, __VA_ARGS__)
#define RS_PREFIX025(pre, macro, ...) pre##macro; RS_PREFIX024(pre, __VA_ARGS__)
#define RS_PREFIX026(pre, macro, ...) pre##macro; RS_PREFIX025(pre, __VA_ARGS__)
#define RS_PREFIX027(pre, macro, ...) pre##macro; RS_PREFIX026(pre, __VA_ARGS__)
#define RS_PREFIX028(pre, macro, ...) pre##macro; RS_PREFIX027(pre, __VA_ARGS__)
#define RS_PREFIX029(pre, macro, ...) pre##macro; RS_PREFIX028(pre, __VA_ARGS__)
#define RS_PREFIX030(pre, macro, ...) pre##macro; RS_PREFIX029(pre, __VA_ARGS__)
#define RS_PREFIX031(pre, macro, ...) pre##macro; RS_PREFIX030(pre, __VA_ARGS__)
#define RS_PREFIX032(pre, macro, ...) pre##macro; RS_PREFIX031(pre, __VA_ARGS__)
#define RS_PREFIX033(pre, macro, ...) pre##macro; RS_PREFIX032(pre, __VA_ARGS__)
#define RS_PREFIX034(pre, macro, ...) pre##macro; RS_PREFIX033(pre, __VA_ARGS__)
#define RS_PREFIX035(pre, macro, ...) pre##macro; RS_PREFIX034(pre, __VA_ARGS__)
#define RS_PREFIX036(pre, macro, ...) pre##macro; RS_PREFIX035(pre, __VA_ARGS__)
#define RS_PREFIX037(pre, macro, ...) pre##macro; RS_PREFIX036(pre, __VA_ARGS__)
#define RS_PREFIX038(pre, macro, ...) pre##macro; RS_PREFIX037(pre, __VA_ARGS__)
#define RS_PREFIX039(pre, macro, ...) pre##macro; RS_PREFIX038(pre, __VA_ARGS__)
#define RS_PREFIX040(pre, macro, ...) pre##macro; RS_PREFIX039(pre, __VA_ARGS__)
#define RS_PREFIX041(pre, macro, ...) pre##macro; RS_PREFIX040(pre, __VA_ARGS__)
#define RS_PREFIX042(pre, macro, ...) pre##macro; RS_PREFIX041(pre, __VA_ARGS__)
#define RS_PREFIX043(pre, macro, ...) pre##macro; RS_PREFIX042(pre, __VA_ARGS__)
#define RS_PREFIX044(pre, macro, ...) pre##macro; RS_PREFIX043(pre, __VA_ARGS__)
#define RS_PREFIX045(pre, macro, ...) pre##macro; RS_PREFIX044(pre, __VA_ARGS__)
#define RS_PREFIX046(pre, macro, ...) pre##macro; RS_PREFIX045(pre, __VA_ARGS__)
#define RS_PREFIX047(pre, macro, ...) pre##macro; RS_PREFIX046(pre, __VA_ARGS__)
#define RS_PREFIX048(pre, macro, ...) pre##macro; RS_PREFIX047(pre, __VA_ARGS__)
#define RS_PREFIX049(pre, macro, ...) pre##macro; RS_PREFIX048(pre, __VA_ARGS__)
#define RS_PREFIX050(pre, macro, ...) pre##macro; RS_PREFIX049(pre, __VA_ARGS__)
#define RS_PREFIX051(pre, macro, ...) pre##macro; RS_PREFIX050(pre, __VA_ARGS__)
#define RS_PREFIX052(pre, macro, ...) pre##macro; RS_PREFIX051(pre, __VA_ARGS__)
#define RS_PREFIX053(pre, macro, ...) pre##macro; RS_PREFIX052(pre, __VA_ARGS__)
#define RS_PREFIX054(pre, macro, ...) pre##macro; RS_PREFIX053(pre, __VA_ARGS__)
#define RS_PREFIX055(pre, macro, ...) pre##macro; RS_PREFIX054(pre, __VA_ARGS__)
#define RS_PREFIX056(pre, macro, ...) pre##macro; RS_PREFIX055(pre, __VA_ARGS__)
#define RS_PREFIX057(pre, macro, ...) pre##macro; RS_PREFIX056(pre, __VA_ARGS__)
#define RS_PREFIX058(pre, macro, ...) pre##macro; RS_PREFIX057(pre, __VA_ARGS__)
#define RS_PREFIX059(pre, macro, ...) pre##macro; RS_PREFIX058(pre, __VA_ARGS__)
#define RS_PREFIX060(pre, macro, ...) pre##macro; RS_PREFIX059(pre, __VA_ARGS__)
#define RS_PREFIX061(pre, macro, ...) pre##macro; RS_PREFIX060(pre, __VA_ARGS__)
#define RS_PREFIX062(pre, macro, ...) pre##macro; RS_PREFIX061(pre, __VA_ARGS__)
#define RS_PREFIX063(pre, macro, ...) pre##macro; RS_PREFIX062(pre, __VA_ARGS__)
#define RS_PREFIX064(pre, macro, ...) pre##macro; RS_PREFIX063(pre, __VA_ARGS__)
#define RS_PREFIX065(pre, macro, ...) pre##macro; RS_PREFIX064(pre, __VA_ARGS__)
#define RS_PREFIX066(pre, macro, ...) pre##macro; RS_PREFIX065(pre, __VA_ARGS__)
#define RS_PREFIX067(pre, macro, ...) pre##macro; RS_PREFIX066(pre, __VA_ARGS__)
#define RS_PREFIX068(pre, macro, ...) pre##macro; RS_PREFIX067(pre, __VA_ARGS__)
#define RS_PREFIX069(pre, macro, ...) pre##macro; RS_PREFIX068(pre, __VA_ARGS__)
#define RS_PREFIX070(pre, macro, ...) pre##macro; RS_PREFIX069(pre, __VA_ARGS__)
#define RS_PREFIX071(pre, macro, ...) pre##macro; RS_PREFIX070(pre, __VA_ARGS__)
#define RS_PREFIX072(pre, macro, ...) pre##macro; RS_PREFIX071(pre, __VA_ARGS__)
#define RS_PREFIX073(pre, macro, ...) pre##macro; RS_PREFIX072(pre, __VA_ARGS__)
#define RS_PREFIX074(pre, macro, ...) pre##macro; RS_PREFIX073(pre, __VA_ARGS__)
#define RS_PREFIX075(pre, macro, ...) pre##macro; RS_PREFIX074(pre, __VA_ARGS__)
#define RS_PREFIX076(pre, macro, ...) pre##macro; RS_PREFIX075(pre, __VA_ARGS__)
#define RS_PREFIX077(pre, macro, ...) pre##macro; RS_PREFIX076(pre, __VA_ARGS__)
#define RS_PREFIX078(pre, macro, ...) pre##macro; RS_PREFIX077(pre, __VA_ARGS__)
#define RS_PREFIX079(pre, macro, ...) pre##macro; RS_PREFIX078(pre, __VA_ARGS__)
#define RS_PREFIX080(pre, macro, ...) pre##macro; RS_PREFIX079(pre, __VA_ARGS__)
#define RS_PREFIX081(pre, macro, ...) pre##macro; RS_PREFIX080(pre, __VA_ARGS__)
#define RS_PREFIX082(pre, macro, ...) pre##macro; RS_PREFIX081(pre, __VA_ARGS__)
#define RS_PREFIX083(pre, macro, ...) pre##macro; RS_PREFIX082(pre, __VA_ARGS__)
#define RS_PREFIX084(pre, macro, ...) pre##macro; RS_PREFIX083(pre, __VA_ARGS__)
#define RS_PREFIX085(pre, macro, ...) pre##macro; RS_PREFIX084(pre, __VA_ARGS__)
#define RS_PREFIX086(pre, macro, ...) pre##macro; RS_PREFIX085(pre, __VA_ARGS__)
#define RS_PREFIX087(pre, macro, ...) pre##macro; RS_PREFIX086(pre, __VA_ARGS__)
#define RS_PREFIX088(pre, macro, ...) pre##macro; RS_PREFIX087(pre, __VA_ARGS__)
#define RS_PREFIX089(pre, macro, ...) pre##macro; RS_PREFIX088(pre, __VA_ARGS__)
#define RS_PREFIX090(pre, macro, ...) pre##macro; RS_PREFIX089(pre, __VA_ARGS__)
#define RS_PREFIX091(pre, macro, ...) pre##macro; RS_PREFIX090(pre, __VA_ARGS__)
#define RS_PREFIX092(pre, macro, ...) pre##macro; RS_PREFIX091(pre, __VA_ARGS__)
#define RS_PREFIX093(pre, macro, ...) pre##macro; RS_PREFIX092(pre, __VA_ARGS__)
#define RS_PREFIX094(pre, macro, ...) pre##macro; RS_PREFIX093(pre, __VA_ARGS__)
#define RS_PREFIX095(pre, macro, ...) pre##macro; RS_PREFIX094(pre, __VA_ARGS__)
#define RS_PREFIX096(pre, macro, ...) pre##macro; RS_PREFIX095(pre, __VA_ARGS__)
#define RS_PREFIX097(pre, macro, ...) pre##macro; RS_PREFIX096(pre, __VA_ARGS__)
#define RS_PREFIX098(pre, macro, ...) pre##macro; RS_PREFIX097(pre, __VA_ARGS__)
#define RS_PREFIX099(pre, macro, ...) pre##macro; RS_PREFIX098(pre, __VA_ARGS__)
#define RS_PREFIX100(pre, macro, ...) pre##macro; RS_PREFIX099(pre, __VA_ARGS__)
#define RS_PREFIX101(pre, macro, ...) pre##macro; RS_PREFIX100(pre, __VA_ARGS__)
#define RS_PREFIX102(pre, macro, ...) pre##macro; RS_PREFIX101(pre, __VA_ARGS__)
#define RS_PREFIX103(pre, macro, ...) pre##macro; RS_PREFIX102(pre, __VA_ARGS__)
#define RS_PREFIX104(pre, macro, ...) pre##macro; RS_PREFIX103(pre, __VA_ARGS__)
#define RS_PREFIX105(pre, macro, ...) pre##macro; RS_PREFIX104(pre, __VA_ARGS__)
#define RS_PREFIX106(pre, macro, ...) pre##macro; RS_PREFIX105(pre, __VA_ARGS__)
#define RS_PREFIX107(pre, macro, ...) pre##macro; RS_PREFIX106(pre, __VA_ARGS__)
#define RS_PREFIX108(pre, macro, ...) pre##macro; RS_PREFIX107(pre, __VA_ARGS__)
#define RS_PREFIX109(pre, macro, ...) pre##macro; RS_PREFIX108(pre, __VA_ARGS__)
#define RS_PREFIX110(pre, macro, ...) pre##macro; RS_PREFIX109(pre, __VA_ARGS__)
#define RS_PREFIX111(pre, macro, ...) pre##macro; RS_PREFIX110(pre, __VA_ARGS__)
#define RS_PREFIX112(pre, macro, ...) pre##macro; RS_PREFIX111(pre, __VA_ARGS__)
#define RS_PREFIX113(pre, macro, ...) pre##macro; RS_PREFIX112(pre, __VA_ARGS__)
#define RS_PREFIX114(pre, macro, ...) pre##macro; RS_PREFIX113(pre, __VA_ARGS__)
#define RS_PREFIX115(pre, macro, ...) pre##macro; RS_PREFIX114(pre, __VA_ARGS__)
#define RS_PREFIX116(pre, macro, ...) pre##macro; RS_PREFIX115(pre, __VA_ARGS__)
#define RS_PREFIX117(pre, macro, ...) pre##macro; RS_PREFIX116(pre, __VA_ARGS__)
#define RS_PREFIX118(pre, macro, ...) pre##macro; RS_PREFIX117(pre, __VA_ARGS__)
#define RS_PREFIX119(pre, macro, ...) pre##macro; RS_PREFIX118(pre, __VA_ARGS__)
#define RS_PREFIX120(pre, macro, ...) pre##macro; RS_PREFIX119(pre, __VA_ARGS__)
#define RS_PREFIX121(pre, macro, ...) pre##macro; RS_PREFIX120(pre, __VA_ARGS__)
#define RS_PREFIX122(pre, macro, ...) pre##macro; RS_PREFIX121(pre, __VA_ARGS__)
#define RS_PREFIX123(pre, macro, ...) pre##macro; RS_PREFIX122(pre, __VA_ARGS__)
#define RS_PREFIX124(pre, macro, ...) pre##macro; RS_PREFIX123(pre, __VA_ARGS__)
#define RS_PREFIX125(pre, macro, ...) pre##macro; RS_PREFIX124(pre, __VA_ARGS__)
#define RS_PREFIX126(pre, macro, ...) pre##macro; RS_PREFIX125(pre, __VA_ARGS__)
#define RS_PREFIX127(pre, macro, ...) pre##macro; RS_PREFIX126(pre, __VA_ARGS__)
#define RS_PREFIX128(pre, macro, ...) pre##macro; RS_PREFIX127(pre, __VA_ARGS__)
#define RS_PREFIX129(pre, macro, ...) pre##macro; RS_PREFIX128(pre, __VA_ARGS__)
#define RS_PREFIX130(pre, macro, ...) pre##macro; RS_PREFIX129(pre, __VA_ARGS__)
#define RS_PREFIX131(pre, macro, ...) pre##macro; RS_PREFIX130(pre, __VA_ARGS__)
#define RS_PREFIX132(pre, macro, ...) pre##macro; RS_PREFIX131(pre, __VA_ARGS__)
#define RS_PREFIX133(pre, macro, ...) pre##macro; RS_PREFIX132(pre, __VA_ARGS__)
#define RS_PREFIX134(pre, macro, ...) pre##macro; RS_PREFIX133(pre, __VA_ARGS__)
#define RS_PREFIX135(pre, macro, ...) pre##macro; RS_PREFIX134(pre, __VA_ARGS__)
#define RS_PREFIX136(pre, macro, ...) pre##macro; RS_PREFIX135(pre, __VA_ARGS__)
#define RS_PREFIX137(pre, macro, ...) pre##macro; RS_PREFIX136(pre, __VA_ARGS__)
#define RS_PREFIX138(pre, macro, ...) pre##macro; RS_PREFIX137(pre, __VA_ARGS__)
#define RS_PREFIX139(pre, macro, ...) pre##macro; RS_PREFIX138(pre, __VA_ARGS__)
#define RS_PREFIX140(pre, macro, ...) pre##macro; RS_PREFIX139(pre, __VA_ARGS__)
#define RS_PREFIX141(pre, macro, ...) pre##macro; RS_PREFIX140(pre, __VA_ARGS__)
#define RS_PREFIX142(pre, macro, ...) pre##macro; RS_PREFIX141(pre, __VA_ARGS__)
#define RS_PREFIX143(pre, macro, ...) pre##macro; RS_PREFIX142(pre, __VA_ARGS__)
#define RS_PREFIX144(pre, macro, ...) pre##macro; RS_PREFIX143(pre, __VA_ARGS__)
#define RS_PREFIX145(pre, macro, ...) pre##macro; RS_PREFIX144(pre, __VA_ARGS__)
#define RS_PREFIX146(pre, macro, ...) pre##macro; RS_PREFIX145(pre, __VA_ARGS__)
#define RS_PREFIX147(pre, macro, ...) pre##macro; RS_PREFIX146(pre, __VA_ARGS__)
#define RS_PREFIX148(pre, macro, ...) pre##macro; RS_PREFIX147(pre, __VA_ARGS__)
#define RS_PREFIX149(pre, macro, ...) pre##macro; RS_PREFIX148(pre, __VA_ARGS__)
#define RS_PREFIX150(pre, macro, ...) pre##macro; RS_PREFIX149(pre, __VA_ARGS__)
#define RS_PREFIX151(pre, macro, ...) pre##macro; RS_PREFIX150(pre, __VA_ARGS__)
#define RS_PREFIX152(pre, macro, ...) pre##macro; RS_PREFIX151(pre, __VA_ARGS__)
#define RS_PREFIX153(pre, macro, ...) pre##macro; RS_PREFIX152(pre, __VA_ARGS__)
#define RS_PREFIX154(pre, macro, ...) pre##macro; RS_PREFIX153(pre, __VA_ARGS__)
#define RS_PREFIX155(pre, macro, ...) pre##macro; RS_PREFIX154(pre, __VA_ARGS__)
#define RS_PREFIX156(pre, macro, ...) pre##macro; RS_PREFIX155(pre, __VA_ARGS__)
#define RS_PREFIX157(pre, macro, ...) pre##macro; RS_PREFIX156(pre, __VA_ARGS__)
#define RS_PREFIX158(pre, macro, ...) pre##macro; RS_PREFIX157(pre, __VA_ARGS__)
#define RS_PREFIX159(pre, macro, ...) pre##macro; RS_PREFIX158(pre, __VA_ARGS__)
#define RS_PREFIX160(pre, macro, ...) pre##macro; RS_PREFIX159(pre, __VA_ARGS__)
#define RS_PREFIX161(pre, macro, ...) pre##macro; RS_PREFIX160(pre, __VA_ARGS__)
#define RS_PREFIX162(pre, macro, ...) pre##macro; RS_PREFIX161(pre, __VA_ARGS__)
#define RS_PREFIX163(pre, macro, ...) pre##macro; RS_PREFIX162(pre, __VA_ARGS__)
#define RS_PREFIX164(pre, macro, ...) pre##macro; RS_PREFIX163(pre, __VA_ARGS__)
#define RS_PREFIX165(pre, macro, ...) pre##macro; RS_PREFIX164(pre, __VA_ARGS__)
#define RS_PREFIX166(pre, macro, ...) pre##macro; RS_PREFIX165(pre, __VA_ARGS__)
#define RS_PREFIX167(pre, macro, ...) pre##macro; RS_PREFIX166(pre, __VA_ARGS__)
#define RS_PREFIX168(pre, macro, ...) pre##macro; RS_PREFIX167(pre, __VA_ARGS__)
#define RS_PREFIX169(pre, macro, ...) pre##macro; RS_PREFIX168(pre, __VA_ARGS__)
#define RS_PREFIX170(pre, macro, ...) pre##macro; RS_PREFIX169(pre, __VA_ARGS__)
#define RS_PREFIX171(pre, macro, ...) pre##macro; RS_PREFIX170(pre, __VA_ARGS__)
#define RS_PREFIX172(pre, macro, ...) pre##macro; RS_PREFIX171(pre, __VA_ARGS__)
#define RS_PREFIX173(pre, macro, ...) pre##macro; RS_PREFIX172(pre, __VA_ARGS__)
#define RS_PREFIX174(pre, macro, ...) pre##macro; RS_PREFIX173(pre, __VA_ARGS__)
#define RS_PREFIX175(pre, macro, ...) pre##macro; RS_PREFIX174(pre, __VA_ARGS__)
#define RS_PREFIX176(pre, macro, ...) pre##macro; RS_PREFIX175(pre, __VA_ARGS__)
#define RS_PREFIX177(pre, macro, ...) pre##macro; RS_PREFIX176(pre, __VA_ARGS__)
#define RS_PREFIX178(pre, macro, ...) pre##macro; RS_PREFIX177(pre, __VA_ARGS__)
#define RS_PREFIX179(pre, macro, ...) pre##macro; RS_PREFIX178(pre, __VA_ARGS__)
#define RS_PREFIX180(pre, macro, ...) pre##macro; RS_PREFIX179(pre, __VA_ARGS__)
#define RS_PREFIX181(pre, macro, ...) pre##macro; RS_PREFIX180(pre, __VA_ARGS__)
#define RS_PREFIX182(pre, macro, ...) pre##macro; RS_PREFIX181(pre, __VA_ARGS__)
#define RS_PREFIX183(pre, macro, ...) pre##macro; RS_PREFIX182(pre, __VA_ARGS__)
#define RS_PREFIX184(pre, macro, ...) pre##macro; RS_PREFIX183(pre, __VA_ARGS__)
#define RS_PREFIX185(pre, macro, ...) pre##macro; RS_PREFIX184(pre, __VA_ARGS__)
#define RS_PREFIX186(pre, macro, ...) pre##macro; RS_PREFIX185(pre, __VA_ARGS__)
#define RS_PREFIX187(pre, macro, ...) pre##macro; RS_PREFIX186(pre, __VA_ARGS__)
#define RS_PREFIX188(pre, macro, ...) pre##macro; RS_PREFIX187(pre, __VA_ARGS__)
#define RS_PREFIX189(pre, macro, ...) pre##macro; RS_PREFIX188(pre, __VA_ARGS__)
#define RS_PREFIX190(pre, macro, ...) pre##macro; RS_PREFIX189(pre, __VA_ARGS__)
#define RS_PREFIX191(pre, macro, ...) pre##macro; RS_PREFIX190(pre, __VA_ARGS__)
#define RS_PREFIX192(pre, macro, ...) pre##macro; RS_PREFIX191(pre, __VA_ARGS__)
#define RS_PREFIX193(pre, macro, ...) pre##macro; RS_PREFIX192(pre, __VA_ARGS__)
#define RS_PREFIX194(pre, macro, ...) pre##macro; RS_PREFIX193(pre, __VA_ARGS__)
#define RS_PREFIX195(pre, macro, ...) pre##macro; RS_PREFIX194(pre, __VA_ARGS__)
#define RS_PREFIX196(pre, macro, ...) pre##macro; RS_PREFIX195(pre, __VA_ARGS__)
#define RS_PREFIX197(pre, macro, ...) pre##macro; RS_PREFIX196(pre, __VA_ARGS__)
#define RS_PREFIX198(pre, macro, ...) pre##macro; RS_PREFIX197(pre, __VA_ARGS__)
#define RS_PREFIX199(pre, macro, ...) pre##macro; RS_PREFIX198(pre, __VA_ARGS__)
#define RS_PREFIX200(pre, macro, ...) pre##macro; RS_PREFIX199(pre, __VA_ARGS__)
#define RS_PREFIX201(pre, macro, ...) pre##macro; RS_PREFIX200(pre, __VA_ARGS__)
#define RS_PREFIX202(pre, macro, ...) pre##macro; RS_PREFIX201(pre, __VA_ARGS__)
#define RS_PREFIX203(pre, macro, ...) pre##macro; RS_PREFIX202(pre, __VA_ARGS__)
#define RS_PREFIX204(pre, macro, ...) pre##macro; RS_PREFIX203(pre, __VA_ARGS__)
#define RS_PREFIX205(pre, macro, ...) pre##macro; RS_PREFIX204(pre, __VA_ARGS__)
#define RS_PREFIX206(pre, macro, ...) pre##macro; RS_PREFIX205(pre, __VA_ARGS__)
#define RS_PREFIX207(pre, macro, ...) pre##macro; RS_PREFIX206(pre, __VA_ARGS__)
#define RS_PREFIX208(pre, macro, ...) pre##macro; RS_PREFIX207(pre, __VA_ARGS__)
#define RS_PREFIX209(pre, macro, ...) pre##macro; RS_PREFIX208(pre, __VA_ARGS__)
#define RS_PREFIX210(pre, macro, ...) pre##macro; RS_PREFIX209(pre, __VA_ARGS__)
#define RS_PREFIX211(pre, macro, ...) pre##macro; RS_PREFIX210(pre, __VA_ARGS__)
#define RS_PREFIX212(pre, macro, ...) pre##macro; RS_PREFIX211(pre, __VA_ARGS__)
#define RS_PREFIX213(pre, macro, ...) pre##macro; RS_PREFIX212(pre, __VA_ARGS__)
#define RS_PREFIX214(pre, macro, ...) pre##macro; RS_PREFIX213(pre, __VA_ARGS__)
#define RS_PREFIX215(pre, macro, ...) pre##macro; RS_PREFIX214(pre, __VA_ARGS__)
#define RS_PREFIX216(pre, macro, ...) pre##macro; RS_PREFIX215(pre, __VA_ARGS__)
#define RS_PREFIX217(pre, macro, ...) pre##macro; RS_PREFIX216(pre, __VA_ARGS__)
#define RS_PREFIX218(pre, macro, ...) pre##macro; RS_PREFIX217(pre, __VA_ARGS__)
#define RS_PREFIX219(pre, macro, ...) pre##macro; RS_PREFIX218(pre, __VA_ARGS__)
#define RS_PREFIX220(pre, macro, ...) pre##macro; RS_PREFIX219(pre, __VA_ARGS__)
#define RS_PREFIX221(pre, macro, ...) pre##macro; RS_PREFIX220(pre, __VA_ARGS__)
#define RS_PREFIX222(pre, macro, ...) pre##macro; RS_PREFIX221(pre, __VA_ARGS__)
#define RS_PREFIX223(pre, macro, ...) pre##macro; RS_PREFIX222(pre, __VA_ARGS__)
#define RS_PREFIX224(pre, macro, ...) pre##macro; RS_PREFIX223(pre, __VA_ARGS__)
#define RS_PREFIX225(pre, macro, ...) pre##macro; RS_PREFIX224(pre, __VA_ARGS__)
#define RS_PREFIX226(pre, macro, ...) pre##macro; RS_PREFIX225(pre, __VA_ARGS__)
#define RS_PREFIX227(pre, macro, ...) pre##macro; RS_PREFIX226(pre, __VA_ARGS__)
#define RS_PREFIX228(pre, macro, ...) pre##macro; RS_PREFIX227(pre, __VA_ARGS__)
#define RS_PREFIX229(pre, macro, ...) pre##macro; RS_PREFIX228(pre, __VA_ARGS__)
#define RS_PREFIX230(pre, macro, ...) pre##macro; RS_PREFIX229(pre, __VA_ARGS__)
#define RS_PREFIX231(pre, macro, ...) pre##macro; RS_PREFIX230(pre, __VA_ARGS__)
#define RS_PREFIX232(pre, macro, ...) pre##macro; RS_PREFIX231(pre, __VA_ARGS__)
#define RS_PREFIX233(pre, macro, ...) pre##macro; RS_PREFIX232(pre, __VA_ARGS__)
#define RS_PREFIX234(pre, macro, ...) pre##macro; RS_PREFIX233(pre, __VA_ARGS__)
#define RS_PREFIX235(pre, macro, ...) pre##macro; RS_PREFIX234(pre, __VA_ARGS__)
#define RS_PREFIX236(pre, macro, ...) pre##macro; RS_PREFIX235(pre, __VA_ARGS__)
#define RS_PREFIX237(pre, macro, ...) pre##macro; RS_PREFIX236(pre, __VA_ARGS__)
#define RS_PREFIX238(pre, macro, ...) pre##macro; RS_PREFIX237(pre, __VA_ARGS__)
#define RS_PREFIX239(pre, macro, ...) pre##macro; RS_PREFIX238(pre, __VA_ARGS__)
#define RS_PREFIX240(pre, macro, ...) pre##macro; RS_PREFIX239(pre, __VA_ARGS__)
#define RS_PREFIX241(pre, macro, ...) pre##macro; RS_PREFIX240(pre, __VA_ARGS__)
#define RS_PREFIX242(pre, macro, ...) pre##macro; RS_PREFIX241(pre, __VA_ARGS__)
#define RS_PREFIX243(pre, macro, ...) pre##macro; RS_PREFIX242(pre, __VA_ARGS__)
#define RS_PREFIX244(pre, macro, ...) pre##macro; RS_PREFIX243(pre, __VA_ARGS__)
#define RS_PREFIX245(pre, macro, ...) pre##macro; RS_PREFIX244(pre, __VA_ARGS__)
#define RS_PREFIX246(pre, macro, ...) pre##macro; RS_PREFIX245(pre, __VA_ARGS__)
#define RS_PREFIX247(pre, macro, ...) pre##macro; RS_PREFIX246(pre, __VA_ARGS__)
#define RS_PREFIX248(pre, macro, ...) pre##macro; RS_PREFIX247(pre, __VA_ARGS__)
#define RS_PREFIX249(pre, macro, ...) pre##macro; RS_PREFIX248(pre, __VA_ARGS__)
#define RS_PREFIX250(pre, macro, ...) pre##macro; RS_PREFIX249(pre, __VA_ARGS__)
#define RS_PREFIX251(pre, macro, ...) pre##macro; RS_PREFIX250(pre, __VA_ARGS__)
#define RS_PREFIX252(pre, macro, ...) pre##macro; RS_PREFIX251(pre, __VA_ARGS__)
#define RS_PREFIX253(pre, macro, ...) pre##macro; RS_PREFIX252(pre, __VA_ARGS__)
#define RS_PREFIX254(pre, macro, ...) pre##macro; RS_PREFIX253(pre, __VA_ARGS__)
#define RS_PREFIX255(pre, macro, ...) pre##macro; RS_PREFIX254(pre, __VA_ARGS__)
#define RS_PREFIX256(pre, macro, ...) pre##macro; RS_PREFIX255(pre, __VA_ARGS__)

#define RS_APPLY_EACH(macro, ...) RS_MACRIFY_EACH(RS_256_256( \
    RS_MACRIF001, RS_MACRIF002, RS_MACRIF003, RS_MACRIF004, RS_MACRIF005, \
    RS_MACRIF006, RS_MACRIF007, RS_MACRIF008, RS_MACRIF009, RS_MACRIF010, \
    RS_MACRIF011, RS_MACRIF012, RS_MACRIF013, RS_MACRIF014, RS_MACRIF015, \
    RS_MACRIF016, RS_MACRIF017, RS_MACRIF018, RS_MACRIF019, RS_MACRIF020, \
    RS_MACRIF021, RS_MACRIF022, RS_MACRIF023, RS_MACRIF024, RS_MACRIF025, \
    RS_MACRIF026, RS_MACRIF027, RS_MACRIF028, RS_MACRIF029, RS_MACRIF030, \
    RS_MACRIF031, RS_MACRIF032, RS_MACRIF033, RS_MACRIF034, RS_MACRIF035, \
    RS_MACRIF036, RS_MACRIF037, RS_MACRIF038, RS_MACRIF039, RS_MACRIF040, \
    RS_MACRIF041, RS_MACRIF042, RS_MACRIF043, RS_MACRIF044, RS_MACRIF045, \
    RS_MACRIF046, RS_MACRIF047, RS_MACRIF048, RS_MACRIF049, RS_MACRIF050, \
    RS_MACRIF051, RS_MACRIF052, RS_MACRIF053, RS_MACRIF054, RS_MACRIF055, \
    RS_MACRIF056, RS_MACRIF057, RS_MACRIF058, RS_MACRIF059, RS_MACRIF060, \
    RS_MACRIF061, RS_MACRIF062, RS_MACRIF063, RS_MACRIF064, RS_MACRIF065, \
    RS_MACRIF066, RS_MACRIF067, RS_MACRIF068, RS_MACRIF069, RS_MACRIF070, \
    RS_MACRIF071, RS_MACRIF072, RS_MACRIF073, RS_MACRIF074, RS_MACRIF075, \
    RS_MACRIF076, RS_MACRIF077, RS_MACRIF078, RS_MACRIF079, RS_MACRIF080, \
    RS_MACRIF081, RS_MACRIF082, RS_MACRIF083, RS_MACRIF084, RS_MACRIF085, \
    RS_MACRIF086, RS_MACRIF087, RS_MACRIF088, RS_MACRIF089, RS_MACRIF090, \
    RS_MACRIF091, RS_MACRIF092, RS_MACRIF093, RS_MACRIF094, RS_MACRIF095, \
    RS_MACRIF096, RS_MACRIF097, RS_MACRIF098, RS_MACRIF099, RS_MACRIF100, \
    RS_MACRIF101, RS_MACRIF102, RS_MACRIF103, RS_MACRIF104, RS_MACRIF105, \
    RS_MACRIF106, RS_MACRIF107, RS_MACRIF108, RS_MACRIF109, RS_MACRIF110, \
    RS_MACRIF111, RS_MACRIF112, RS_MACRIF113, RS_MACRIF114, RS_MACRIF115, \
    RS_MACRIF116, RS_MACRIF117, RS_MACRIF118, RS_MACRIF119, RS_MACRIF120, \
    RS_MACRIF121, RS_MACRIF122, RS_MACRIF123, RS_MACRIF124, RS_MACRIF125, \
    RS_MACRIF126, RS_MACRIF127, RS_MACRIF128, RS_MACRIF129, RS_MACRIF130, \
    RS_MACRIF131, RS_MACRIF132, RS_MACRIF133, RS_MACRIF134, RS_MACRIF135, \
    RS_MACRIF136, RS_MACRIF137, RS_MACRIF138, RS_MACRIF139, RS_MACRIF140, \
    RS_MACRIF141, RS_MACRIF142, RS_MACRIF143, RS_MACRIF144, RS_MACRIF145, \
    RS_MACRIF146, RS_MACRIF147, RS_MACRIF148, RS_MACRIF149, RS_MACRIF150, \
    RS_MACRIF151, RS_MACRIF152, RS_MACRIF153, RS_MACRIF154, RS_MACRIF155, \
    RS_MACRIF156, RS_MACRIF157, RS_MACRIF158, RS_MACRIF159, RS_MACRIF160, \
    RS_MACRIF161, RS_MACRIF162, RS_MACRIF163, RS_MACRIF164, RS_MACRIF165, \
    RS_MACRIF166, RS_MACRIF167, RS_MACRIF168, RS_MACRIF169, RS_MACRIF170, \
    RS_MACRIF171, RS_MACRIF172, RS_MACRIF173, RS_MACRIF174, RS_MACRIF175, \
    RS_MACRIF176, RS_MACRIF177, RS_MACRIF178, RS_MACRIF179, RS_MACRIF180, \
    RS_MACRIF181, RS_MACRIF182, RS_MACRIF183, RS_MACRIF184, RS_MACRIF185, \
    RS_MACRIF186, RS_MACRIF187, RS_MACRIF188, RS_MACRIF189, RS_MACRIF190, \
    RS_MACRIF191, RS_MACRIF192, RS_MACRIF193, RS_MACRIF194, RS_MACRIF195, \
    RS_MACRIF196, RS_MACRIF197, RS_MACRIF198, RS_MACRIF199, RS_MACRIF200, \
    RS_MACRIF201, RS_MACRIF202, RS_MACRIF203, RS_MACRIF204, RS_MACRIF205, \
    RS_MACRIF206, RS_MACRIF207, RS_MACRIF208, RS_MACRIF209, RS_MACRIF210, \
    RS_MACRIF211, RS_MACRIF212, RS_MACRIF213, RS_MACRIF214, RS_MACRIF215, \
    RS_MACRIF216, RS_MACRIF217, RS_MACRIF218, RS_MACRIF219, RS_MACRIF220, \
    RS_MACRIF221, RS_MACRIF222, RS_MACRIF223, RS_MACRIF224, RS_MACRIF225, \
    RS_MACRIF226, RS_MACRIF227, RS_MACRIF228, RS_MACRIF229, RS_MACRIF230, \
    RS_MACRIF231, RS_MACRIF232, RS_MACRIF233, RS_MACRIF234, RS_MACRIF235, \
    RS_MACRIF236, RS_MACRIF237, RS_MACRIF238, RS_MACRIF239, RS_MACRIF240, \
    RS_MACRIF241, RS_MACRIF242, RS_MACRIF243, RS_MACRIF244, RS_MACRIF245, \
    RS_MACRIF246, RS_MACRIF247, RS_MACRIF248, RS_MACRIF249, RS_MACRIF250, \
    RS_MACRIF251, RS_MACRIF252, RS_MACRIF253, RS_MACRIF254, RS_MACRIF255, \
    RS_MACRIF256, __VA_ARGS__), macro, __VA_ARGS__)

#define RS_MACRIF001(macro, arg) macro(arg)
#define RS_MACRIF002(macro, a1, a2) macro(a1); macro(a2)
#define RS_MACRIF003(macro, a1, a2, a3) macro(a1); macro(a2); macro(a3)
#define RS_MACRIF004(macro, a, ...) macro(a); RS_MACRIF003(macro, __VA_ARGS__)
#define RS_MACRIF005(macro, a, ...) macro(a); RS_MACRIF004(macro, __VA_ARGS__)
#define RS_MACRIF006(macro, a, ...) macro(a); RS_MACRIF005(macro, __VA_ARGS__)
#define RS_MACRIF007(macro, a, ...) macro(a); RS_MACRIF006(macro, __VA_ARGS__)
#define RS_MACRIF008(macro, a, ...) macro(a); RS_MACRIF007(macro, __VA_ARGS__)
#define RS_MACRIF009(macro, a, ...) macro(a); RS_MACRIF008(macro, __VA_ARGS__)
#define RS_MACRIF010(macro, a, ...) macro(a); RS_MACRIF009(macro, __VA_ARGS__)
#define RS_MACRIF011(macro, a, ...) macro(a); RS_MACRIF010(macro, __VA_ARGS__)
#define RS_MACRIF012(macro, a, ...) macro(a); RS_MACRIF011(macro, __VA_ARGS__)
#define RS_MACRIF013(macro, a, ...) macro(a); RS_MACRIF012(macro, __VA_ARGS__)
#define RS_MACRIF014(macro, a, ...) macro(a); RS_MACRIF013(macro, __VA_ARGS__)
#define RS_MACRIF015(macro, a, ...) macro(a); RS_MACRIF014(macro, __VA_ARGS__)
#define RS_MACRIF016(macro, a, ...) macro(a); RS_MACRIF015(macro, __VA_ARGS__)
#define RS_MACRIF017(macro, a, ...) macro(a); RS_MACRIF016(macro, __VA_ARGS__)
#define RS_MACRIF018(macro, a, ...) macro(a); RS_MACRIF017(macro, __VA_ARGS__)
#define RS_MACRIF019(macro, a, ...) macro(a); RS_MACRIF018(macro, __VA_ARGS__)
#define RS_MACRIF020(macro, a, ...) macro(a); RS_MACRIF019(macro, __VA_ARGS__)
#define RS_MACRIF021(macro, a, ...) macro(a); RS_MACRIF020(macro, __VA_ARGS__)
#define RS_MACRIF022(macro, a, ...) macro(a); RS_MACRIF021(macro, __VA_ARGS__)
#define RS_MACRIF023(macro, a, ...) macro(a); RS_MACRIF022(macro, __VA_ARGS__)
#define RS_MACRIF024(macro, a, ...) macro(a); RS_MACRIF023(macro, __VA_ARGS__)
#define RS_MACRIF025(macro, a, ...) macro(a); RS_MACRIF024(macro, __VA_ARGS__)
#define RS_MACRIF026(macro, a, ...) macro(a); RS_MACRIF025(macro, __VA_ARGS__)
#define RS_MACRIF027(macro, a, ...) macro(a); RS_MACRIF026(macro, __VA_ARGS__)
#define RS_MACRIF028(macro, a, ...) macro(a); RS_MACRIF027(macro, __VA_ARGS__)
#define RS_MACRIF029(macro, a, ...) macro(a); RS_MACRIF028(macro, __VA_ARGS__)
#define RS_MACRIF030(macro, a, ...) macro(a); RS_MACRIF029(macro, __VA_ARGS__)
#define RS_MACRIF031(macro, a, ...) macro(a); RS_MACRIF030(macro, __VA_ARGS__)
#define RS_MACRIF032(macro, a, ...) macro(a); RS_MACRIF031(macro, __VA_ARGS__)
#define RS_MACRIF033(macro, a, ...) macro(a); RS_MACRIF032(macro, __VA_ARGS__)
#define RS_MACRIF034(macro, a, ...) macro(a); RS_MACRIF033(macro, __VA_ARGS__)
#define RS_MACRIF035(macro, a, ...) macro(a); RS_MACRIF034(macro, __VA_ARGS__)
#define RS_MACRIF036(macro, a, ...) macro(a); RS_MACRIF035(macro, __VA_ARGS__)
#define RS_MACRIF037(macro, a, ...) macro(a); RS_MACRIF036(macro, __VA_ARGS__)
#define RS_MACRIF038(macro, a, ...) macro(a); RS_MACRIF037(macro, __VA_ARGS__)
#define RS_MACRIF039(macro, a, ...) macro(a); RS_MACRIF038(macro, __VA_ARGS__)
#define RS_MACRIF040(macro, a, ...) macro(a); RS_MACRIF039(macro, __VA_ARGS__)
#define RS_MACRIF041(macro, a, ...) macro(a); RS_MACRIF040(macro, __VA_ARGS__)
#define RS_MACRIF042(macro, a, ...) macro(a); RS_MACRIF041(macro, __VA_ARGS__)
#define RS_MACRIF043(macro, a, ...) macro(a); RS_MACRIF042(macro, __VA_ARGS__)
#define RS_MACRIF044(macro, a, ...) macro(a); RS_MACRIF043(macro, __VA_ARGS__)
#define RS_MACRIF045(macro, a, ...) macro(a); RS_MACRIF044(macro, __VA_ARGS__)
#define RS_MACRIF046(macro, a, ...) macro(a); RS_MACRIF045(macro, __VA_ARGS__)
#define RS_MACRIF047(macro, a, ...) macro(a); RS_MACRIF046(macro, __VA_ARGS__)
#define RS_MACRIF048(macro, a, ...) macro(a); RS_MACRIF047(macro, __VA_ARGS__)
#define RS_MACRIF049(macro, a, ...) macro(a); RS_MACRIF048(macro, __VA_ARGS__)
#define RS_MACRIF050(macro, a, ...) macro(a); RS_MACRIF049(macro, __VA_ARGS__)
#define RS_MACRIF051(macro, a, ...) macro(a); RS_MACRIF050(macro, __VA_ARGS__)
#define RS_MACRIF052(macro, a, ...) macro(a); RS_MACRIF051(macro, __VA_ARGS__)
#define RS_MACRIF053(macro, a, ...) macro(a); RS_MACRIF052(macro, __VA_ARGS__)
#define RS_MACRIF054(macro, a, ...) macro(a); RS_MACRIF053(macro, __VA_ARGS__)
#define RS_MACRIF055(macro, a, ...) macro(a); RS_MACRIF054(macro, __VA_ARGS__)
#define RS_MACRIF056(macro, a, ...) macro(a); RS_MACRIF055(macro, __VA_ARGS__)
#define RS_MACRIF057(macro, a, ...) macro(a); RS_MACRIF056(macro, __VA_ARGS__)
#define RS_MACRIF058(macro, a, ...) macro(a); RS_MACRIF057(macro, __VA_ARGS__)
#define RS_MACRIF059(macro, a, ...) macro(a); RS_MACRIF058(macro, __VA_ARGS__)
#define RS_MACRIF060(macro, a, ...) macro(a); RS_MACRIF059(macro, __VA_ARGS__)
#define RS_MACRIF061(macro, a, ...) macro(a); RS_MACRIF060(macro, __VA_ARGS__)
#define RS_MACRIF062(macro, a, ...) macro(a); RS_MACRIF061(macro, __VA_ARGS__)
#define RS_MACRIF063(macro, a, ...) macro(a); RS_MACRIF062(macro, __VA_ARGS__)
#define RS_MACRIF064(macro, a, ...) macro(a); RS_MACRIF063(macro, __VA_ARGS__)
#define RS_MACRIF065(macro, a, ...) macro(a); RS_MACRIF064(macro, __VA_ARGS__)
#define RS_MACRIF066(macro, a, ...) macro(a); RS_MACRIF065(macro, __VA_ARGS__)
#define RS_MACRIF067(macro, a, ...) macro(a); RS_MACRIF066(macro, __VA_ARGS__)
#define RS_MACRIF068(macro, a, ...) macro(a); RS_MACRIF067(macro, __VA_ARGS__)
#define RS_MACRIF069(macro, a, ...) macro(a); RS_MACRIF068(macro, __VA_ARGS__)
#define RS_MACRIF070(macro, a, ...) macro(a); RS_MACRIF069(macro, __VA_ARGS__)
#define RS_MACRIF071(macro, a, ...) macro(a); RS_MACRIF070(macro, __VA_ARGS__)
#define RS_MACRIF072(macro, a, ...) macro(a); RS_MACRIF071(macro, __VA_ARGS__)
#define RS_MACRIF073(macro, a, ...) macro(a); RS_MACRIF072(macro, __VA_ARGS__)
#define RS_MACRIF074(macro, a, ...) macro(a); RS_MACRIF073(macro, __VA_ARGS__)
#define RS_MACRIF075(macro, a, ...) macro(a); RS_MACRIF074(macro, __VA_ARGS__)
#define RS_MACRIF076(macro, a, ...) macro(a); RS_MACRIF075(macro, __VA_ARGS__)
#define RS_MACRIF077(macro, a, ...) macro(a); RS_MACRIF076(macro, __VA_ARGS__)
#define RS_MACRIF078(macro, a, ...) macro(a); RS_MACRIF077(macro, __VA_ARGS__)
#define RS_MACRIF079(macro, a, ...) macro(a); RS_MACRIF078(macro, __VA_ARGS__)
#define RS_MACRIF080(macro, a, ...) macro(a); RS_MACRIF079(macro, __VA_ARGS__)
#define RS_MACRIF081(macro, a, ...) macro(a); RS_MACRIF080(macro, __VA_ARGS__)
#define RS_MACRIF082(macro, a, ...) macro(a); RS_MACRIF081(macro, __VA_ARGS__)
#define RS_MACRIF083(macro, a, ...) macro(a); RS_MACRIF082(macro, __VA_ARGS__)
#define RS_MACRIF084(macro, a, ...) macro(a); RS_MACRIF083(macro, __VA_ARGS__)
#define RS_MACRIF085(macro, a, ...) macro(a); RS_MACRIF084(macro, __VA_ARGS__)
#define RS_MACRIF086(macro, a, ...) macro(a); RS_MACRIF085(macro, __VA_ARGS__)
#define RS_MACRIF087(macro, a, ...) macro(a); RS_MACRIF086(macro, __VA_ARGS__)
#define RS_MACRIF088(macro, a, ...) macro(a); RS_MACRIF087(macro, __VA_ARGS__)
#define RS_MACRIF089(macro, a, ...) macro(a); RS_MACRIF088(macro, __VA_ARGS__)
#define RS_MACRIF090(macro, a, ...) macro(a); RS_MACRIF089(macro, __VA_ARGS__)
#define RS_MACRIF091(macro, a, ...) macro(a); RS_MACRIF090(macro, __VA_ARGS__)
#define RS_MACRIF092(macro, a, ...) macro(a); RS_MACRIF091(macro, __VA_ARGS__)
#define RS_MACRIF093(macro, a, ...) macro(a); RS_MACRIF092(macro, __VA_ARGS__)
#define RS_MACRIF094(macro, a, ...) macro(a); RS_MACRIF093(macro, __VA_ARGS__)
#define RS_MACRIF095(macro, a, ...) macro(a); RS_MACRIF094(macro, __VA_ARGS__)
#define RS_MACRIF096(macro, a, ...) macro(a); RS_MACRIF095(macro, __VA_ARGS__)
#define RS_MACRIF097(macro, a, ...) macro(a); RS_MACRIF096(macro, __VA_ARGS__)
#define RS_MACRIF098(macro, a, ...) macro(a); RS_MACRIF097(macro, __VA_ARGS__)
#define RS_MACRIF099(macro, a, ...) macro(a); RS_MACRIF098(macro, __VA_ARGS__)
#define RS_MACRIF100(macro, a, ...) macro(a); RS_MACRIF099(macro, __VA_ARGS__)
#define RS_MACRIF101(macro, a, ...) macro(a); RS_MACRIF100(macro, __VA_ARGS__)
#define RS_MACRIF102(macro, a, ...) macro(a); RS_MACRIF101(macro, __VA_ARGS__)
#define RS_MACRIF103(macro, a, ...) macro(a); RS_MACRIF102(macro, __VA_ARGS__)
#define RS_MACRIF104(macro, a, ...) macro(a); RS_MACRIF103(macro, __VA_ARGS__)
#define RS_MACRIF105(macro, a, ...) macro(a); RS_MACRIF104(macro, __VA_ARGS__)
#define RS_MACRIF106(macro, a, ...) macro(a); RS_MACRIF105(macro, __VA_ARGS__)
#define RS_MACRIF107(macro, a, ...) macro(a); RS_MACRIF106(macro, __VA_ARGS__)
#define RS_MACRIF108(macro, a, ...) macro(a); RS_MACRIF107(macro, __VA_ARGS__)
#define RS_MACRIF109(macro, a, ...) macro(a); RS_MACRIF108(macro, __VA_ARGS__)
#define RS_MACRIF110(macro, a, ...) macro(a); RS_MACRIF109(macro, __VA_ARGS__)
#define RS_MACRIF111(macro, a, ...) macro(a); RS_MACRIF110(macro, __VA_ARGS__)
#define RS_MACRIF112(macro, a, ...) macro(a); RS_MACRIF111(macro, __VA_ARGS__)
#define RS_MACRIF113(macro, a, ...) macro(a); RS_MACRIF112(macro, __VA_ARGS__)
#define RS_MACRIF114(macro, a, ...) macro(a); RS_MACRIF113(macro, __VA_ARGS__)
#define RS_MACRIF115(macro, a, ...) macro(a); RS_MACRIF114(macro, __VA_ARGS__)
#define RS_MACRIF116(macro, a, ...) macro(a); RS_MACRIF115(macro, __VA_ARGS__)
#define RS_MACRIF117(macro, a, ...) macro(a); RS_MACRIF116(macro, __VA_ARGS__)
#define RS_MACRIF118(macro, a, ...) macro(a); RS_MACRIF117(macro, __VA_ARGS__)
#define RS_MACRIF119(macro, a, ...) macro(a); RS_MACRIF118(macro, __VA_ARGS__)
#define RS_MACRIF120(macro, a, ...) macro(a); RS_MACRIF119(macro, __VA_ARGS__)
#define RS_MACRIF121(macro, a, ...) macro(a); RS_MACRIF120(macro, __VA_ARGS__)
#define RS_MACRIF122(macro, a, ...) macro(a); RS_MACRIF121(macro, __VA_ARGS__)
#define RS_MACRIF123(macro, a, ...) macro(a); RS_MACRIF122(macro, __VA_ARGS__)
#define RS_MACRIF124(macro, a, ...) macro(a); RS_MACRIF123(macro, __VA_ARGS__)
#define RS_MACRIF125(macro, a, ...) macro(a); RS_MACRIF124(macro, __VA_ARGS__)
#define RS_MACRIF126(macro, a, ...) macro(a); RS_MACRIF125(macro, __VA_ARGS__)
#define RS_MACRIF127(macro, a, ...) macro(a); RS_MACRIF126(macro, __VA_ARGS__)
#define RS_MACRIF128(macro, a, ...) macro(a); RS_MACRIF127(macro, __VA_ARGS__)
#define RS_MACRIF129(macro, a, ...) macro(a); RS_MACRIF128(macro, __VA_ARGS__)
#define RS_MACRIF130(macro, a, ...) macro(a); RS_MACRIF129(macro, __VA_ARGS__)
#define RS_MACRIF131(macro, a, ...) macro(a); RS_MACRIF130(macro, __VA_ARGS__)
#define RS_MACRIF132(macro, a, ...) macro(a); RS_MACRIF131(macro, __VA_ARGS__)
#define RS_MACRIF133(macro, a, ...) macro(a); RS_MACRIF132(macro, __VA_ARGS__)
#define RS_MACRIF134(macro, a, ...) macro(a); RS_MACRIF133(macro, __VA_ARGS__)
#define RS_MACRIF135(macro, a, ...) macro(a); RS_MACRIF134(macro, __VA_ARGS__)
#define RS_MACRIF136(macro, a, ...) macro(a); RS_MACRIF135(macro, __VA_ARGS__)
#define RS_MACRIF137(macro, a, ...) macro(a); RS_MACRIF136(macro, __VA_ARGS__)
#define RS_MACRIF138(macro, a, ...) macro(a); RS_MACRIF137(macro, __VA_ARGS__)
#define RS_MACRIF139(macro, a, ...) macro(a); RS_MACRIF138(macro, __VA_ARGS__)
#define RS_MACRIF140(macro, a, ...) macro(a); RS_MACRIF139(macro, __VA_ARGS__)
#define RS_MACRIF141(macro, a, ...) macro(a); RS_MACRIF140(macro, __VA_ARGS__)
#define RS_MACRIF142(macro, a, ...) macro(a); RS_MACRIF141(macro, __VA_ARGS__)
#define RS_MACRIF143(macro, a, ...) macro(a); RS_MACRIF142(macro, __VA_ARGS__)
#define RS_MACRIF144(macro, a, ...) macro(a); RS_MACRIF143(macro, __VA_ARGS__)
#define RS_MACRIF145(macro, a, ...) macro(a); RS_MACRIF144(macro, __VA_ARGS__)
#define RS_MACRIF146(macro, a, ...) macro(a); RS_MACRIF145(macro, __VA_ARGS__)
#define RS_MACRIF147(macro, a, ...) macro(a); RS_MACRIF146(macro, __VA_ARGS__)
#define RS_MACRIF148(macro, a, ...) macro(a); RS_MACRIF147(macro, __VA_ARGS__)
#define RS_MACRIF149(macro, a, ...) macro(a); RS_MACRIF148(macro, __VA_ARGS__)
#define RS_MACRIF150(macro, a, ...) macro(a); RS_MACRIF149(macro, __VA_ARGS__)
#define RS_MACRIF151(macro, a, ...) macro(a); RS_MACRIF150(macro, __VA_ARGS__)
#define RS_MACRIF152(macro, a, ...) macro(a); RS_MACRIF151(macro, __VA_ARGS__)
#define RS_MACRIF153(macro, a, ...) macro(a); RS_MACRIF152(macro, __VA_ARGS__)
#define RS_MACRIF154(macro, a, ...) macro(a); RS_MACRIF153(macro, __VA_ARGS__)
#define RS_MACRIF155(macro, a, ...) macro(a); RS_MACRIF154(macro, __VA_ARGS__)
#define RS_MACRIF156(macro, a, ...) macro(a); RS_MACRIF155(macro, __VA_ARGS__)
#define RS_MACRIF157(macro, a, ...) macro(a); RS_MACRIF156(macro, __VA_ARGS__)
#define RS_MACRIF158(macro, a, ...) macro(a); RS_MACRIF157(macro, __VA_ARGS__)
#define RS_MACRIF159(macro, a, ...) macro(a); RS_MACRIF158(macro, __VA_ARGS__)
#define RS_MACRIF160(macro, a, ...) macro(a); RS_MACRIF159(macro, __VA_ARGS__)
#define RS_MACRIF161(macro, a, ...) macro(a); RS_MACRIF160(macro, __VA_ARGS__)
#define RS_MACRIF162(macro, a, ...) macro(a); RS_MACRIF161(macro, __VA_ARGS__)
#define RS_MACRIF163(macro, a, ...) macro(a); RS_MACRIF162(macro, __VA_ARGS__)
#define RS_MACRIF164(macro, a, ...) macro(a); RS_MACRIF163(macro, __VA_ARGS__)
#define RS_MACRIF165(macro, a, ...) macro(a); RS_MACRIF164(macro, __VA_ARGS__)
#define RS_MACRIF166(macro, a, ...) macro(a); RS_MACRIF165(macro, __VA_ARGS__)
#define RS_MACRIF167(macro, a, ...) macro(a); RS_MACRIF166(macro, __VA_ARGS__)
#define RS_MACRIF168(macro, a, ...) macro(a); RS_MACRIF167(macro, __VA_ARGS__)
#define RS_MACRIF169(macro, a, ...) macro(a); RS_MACRIF168(macro, __VA_ARGS__)
#define RS_MACRIF170(macro, a, ...) macro(a); RS_MACRIF169(macro, __VA_ARGS__)
#define RS_MACRIF171(macro, a, ...) macro(a); RS_MACRIF170(macro, __VA_ARGS__)
#define RS_MACRIF172(macro, a, ...) macro(a); RS_MACRIF171(macro, __VA_ARGS__)
#define RS_MACRIF173(macro, a, ...) macro(a); RS_MACRIF172(macro, __VA_ARGS__)
#define RS_MACRIF174(macro, a, ...) macro(a); RS_MACRIF173(macro, __VA_ARGS__)
#define RS_MACRIF175(macro, a, ...) macro(a); RS_MACRIF174(macro, __VA_ARGS__)
#define RS_MACRIF176(macro, a, ...) macro(a); RS_MACRIF175(macro, __VA_ARGS__)
#define RS_MACRIF177(macro, a, ...) macro(a); RS_MACRIF176(macro, __VA_ARGS__)
#define RS_MACRIF178(macro, a, ...) macro(a); RS_MACRIF177(macro, __VA_ARGS__)
#define RS_MACRIF179(macro, a, ...) macro(a); RS_MACRIF178(macro, __VA_ARGS__)
#define RS_MACRIF180(macro, a, ...) macro(a); RS_MACRIF179(macro, __VA_ARGS__)
#define RS_MACRIF181(macro, a, ...) macro(a); RS_MACRIF180(macro, __VA_ARGS__)
#define RS_MACRIF182(macro, a, ...) macro(a); RS_MACRIF181(macro, __VA_ARGS__)
#define RS_MACRIF183(macro, a, ...) macro(a); RS_MACRIF182(macro, __VA_ARGS__)
#define RS_MACRIF184(macro, a, ...) macro(a); RS_MACRIF183(macro, __VA_ARGS__)
#define RS_MACRIF185(macro, a, ...) macro(a); RS_MACRIF184(macro, __VA_ARGS__)
#define RS_MACRIF186(macro, a, ...) macro(a); RS_MACRIF185(macro, __VA_ARGS__)
#define RS_MACRIF187(macro, a, ...) macro(a); RS_MACRIF186(macro, __VA_ARGS__)
#define RS_MACRIF188(macro, a, ...) macro(a); RS_MACRIF187(macro, __VA_ARGS__)
#define RS_MACRIF189(macro, a, ...) macro(a); RS_MACRIF188(macro, __VA_ARGS__)
#define RS_MACRIF190(macro, a, ...) macro(a); RS_MACRIF189(macro, __VA_ARGS__)
#define RS_MACRIF191(macro, a, ...) macro(a); RS_MACRIF190(macro, __VA_ARGS__)
#define RS_MACRIF192(macro, a, ...) macro(a); RS_MACRIF191(macro, __VA_ARGS__)
#define RS_MACRIF193(macro, a, ...) macro(a); RS_MACRIF192(macro, __VA_ARGS__)
#define RS_MACRIF194(macro, a, ...) macro(a); RS_MACRIF193(macro, __VA_ARGS__)
#define RS_MACRIF195(macro, a, ...) macro(a); RS_MACRIF194(macro, __VA_ARGS__)
#define RS_MACRIF196(macro, a, ...) macro(a); RS_MACRIF195(macro, __VA_ARGS__)
#define RS_MACRIF197(macro, a, ...) macro(a); RS_MACRIF196(macro, __VA_ARGS__)
#define RS_MACRIF198(macro, a, ...) macro(a); RS_MACRIF197(macro, __VA_ARGS__)
#define RS_MACRIF199(macro, a, ...) macro(a); RS_MACRIF198(macro, __VA_ARGS__)
#define RS_MACRIF200(macro, a, ...) macro(a); RS_MACRIF199(macro, __VA_ARGS__)
#define RS_MACRIF201(macro, a, ...) macro(a); RS_MACRIF200(macro, __VA_ARGS__)
#define RS_MACRIF202(macro, a, ...) macro(a); RS_MACRIF201(macro, __VA_ARGS__)
#define RS_MACRIF203(macro, a, ...) macro(a); RS_MACRIF202(macro, __VA_ARGS__)
#define RS_MACRIF204(macro, a, ...) macro(a); RS_MACRIF203(macro, __VA_ARGS__)
#define RS_MACRIF205(macro, a, ...) macro(a); RS_MACRIF204(macro, __VA_ARGS__)
#define RS_MACRIF206(macro, a, ...) macro(a); RS_MACRIF205(macro, __VA_ARGS__)
#define RS_MACRIF207(macro, a, ...) macro(a); RS_MACRIF206(macro, __VA_ARGS__)
#define RS_MACRIF208(macro, a, ...) macro(a); RS_MACRIF207(macro, __VA_ARGS__)
#define RS_MACRIF209(macro, a, ...) macro(a); RS_MACRIF208(macro, __VA_ARGS__)
#define RS_MACRIF210(macro, a, ...) macro(a); RS_MACRIF209(macro, __VA_ARGS__)
#define RS_MACRIF211(macro, a, ...) macro(a); RS_MACRIF210(macro, __VA_ARGS__)
#define RS_MACRIF212(macro, a, ...) macro(a); RS_MACRIF211(macro, __VA_ARGS__)
#define RS_MACRIF213(macro, a, ...) macro(a); RS_MACRIF212(macro, __VA_ARGS__)
#define RS_MACRIF214(macro, a, ...) macro(a); RS_MACRIF213(macro, __VA_ARGS__)
#define RS_MACRIF215(macro, a, ...) macro(a); RS_MACRIF214(macro, __VA_ARGS__)
#define RS_MACRIF216(macro, a, ...) macro(a); RS_MACRIF215(macro, __VA_ARGS__)
#define RS_MACRIF217(macro, a, ...) macro(a); RS_MACRIF216(macro, __VA_ARGS__)
#define RS_MACRIF218(macro, a, ...) macro(a); RS_MACRIF217(macro, __VA_ARGS__)
#define RS_MACRIF219(macro, a, ...) macro(a); RS_MACRIF218(macro, __VA_ARGS__)
#define RS_MACRIF220(macro, a, ...) macro(a); RS_MACRIF219(macro, __VA_ARGS__)
#define RS_MACRIF221(macro, a, ...) macro(a); RS_MACRIF220(macro, __VA_ARGS__)
#define RS_MACRIF222(macro, a, ...) macro(a); RS_MACRIF221(macro, __VA_ARGS__)
#define RS_MACRIF223(macro, a, ...) macro(a); RS_MACRIF222(macro, __VA_ARGS__)
#define RS_MACRIF224(macro, a, ...) macro(a); RS_MACRIF223(macro, __VA_ARGS__)
#define RS_MACRIF225(macro, a, ...) macro(a); RS_MACRIF224(macro, __VA_ARGS__)
#define RS_MACRIF226(macro, a, ...) macro(a); RS_MACRIF225(macro, __VA_ARGS__)
#define RS_MACRIF227(macro, a, ...) macro(a); RS_MACRIF226(macro, __VA_ARGS__)
#define RS_MACRIF228(macro, a, ...) macro(a); RS_MACRIF227(macro, __VA_ARGS__)
#define RS_MACRIF229(macro, a, ...) macro(a); RS_MACRIF228(macro, __VA_ARGS__)
#define RS_MACRIF230(macro, a, ...) macro(a); RS_MACRIF229(macro, __VA_ARGS__)
#define RS_MACRIF231(macro, a, ...) macro(a); RS_MACRIF230(macro, __VA_ARGS__)
#define RS_MACRIF232(macro, a, ...) macro(a); RS_MACRIF231(macro, __VA_ARGS__)
#define RS_MACRIF233(macro, a, ...) macro(a); RS_MACRIF232(macro, __VA_ARGS__)
#define RS_MACRIF234(macro, a, ...) macro(a); RS_MACRIF233(macro, __VA_ARGS__)
#define RS_MACRIF235(macro, a, ...) macro(a); RS_MACRIF234(macro, __VA_ARGS__)
#define RS_MACRIF236(macro, a, ...) macro(a); RS_MACRIF235(macro, __VA_ARGS__)
#define RS_MACRIF237(macro, a, ...) macro(a); RS_MACRIF236(macro, __VA_ARGS__)
#define RS_MACRIF238(macro, a, ...) macro(a); RS_MACRIF237(macro, __VA_ARGS__)
#define RS_MACRIF239(macro, a, ...) macro(a); RS_MACRIF238(macro, __VA_ARGS__)
#define RS_MACRIF240(macro, a, ...) macro(a); RS_MACRIF239(macro, __VA_ARGS__)
#define RS_MACRIF241(macro, a, ...) macro(a); RS_MACRIF240(macro, __VA_ARGS__)
#define RS_MACRIF242(macro, a, ...) macro(a); RS_MACRIF241(macro, __VA_ARGS__)
#define RS_MACRIF243(macro, a, ...) macro(a); RS_MACRIF242(macro, __VA_ARGS__)
#define RS_MACRIF244(macro, a, ...) macro(a); RS_MACRIF243(macro, __VA_ARGS__)
#define RS_MACRIF245(macro, a, ...) macro(a); RS_MACRIF244(macro, __VA_ARGS__)
#define RS_MACRIF246(macro, a, ...) macro(a); RS_MACRIF245(macro, __VA_ARGS__)
#define RS_MACRIF247(macro, a, ...) macro(a); RS_MACRIF246(macro, __VA_ARGS__)
#define RS_MACRIF248(macro, a, ...) macro(a); RS_MACRIF247(macro, __VA_ARGS__)
#define RS_MACRIF249(macro, a, ...) macro(a); RS_MACRIF248(macro, __VA_ARGS__)
#define RS_MACRIF250(macro, a, ...) macro(a); RS_MACRIF249(macro, __VA_ARGS__)
#define RS_MACRIF251(macro, a, ...) macro(a); RS_MACRIF250(macro, __VA_ARGS__)
#define RS_MACRIF252(macro, a, ...) macro(a); RS_MACRIF251(macro, __VA_ARGS__)
#define RS_MACRIF253(macro, a, ...) macro(a); RS_MACRIF252(macro, __VA_ARGS__)
#define RS_MACRIF254(macro, a, ...) macro(a); RS_MACRIF253(macro, __VA_ARGS__)
#define RS_MACRIF255(macro, a, ...) macro(a); RS_MACRIF254(macro, __VA_ARGS__)
#define RS_MACRIF256(macro, a, ...) macro(a); RS_MACRIF255(macro, __VA_ARGS__)
