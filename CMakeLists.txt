# SPDX-License-Identifier: AGPL-3.0-only
# StrataZip: maximum-ratio archiving. Build: cmake -B build && cmake --build build
cmake_minimum_required(VERSION 3.19)
project(StrataZip VERSION 1.2.0 DESCRIPTION "Maximum-ratio file and directory archiver" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Concurrent)

# zlib 1.3.1 and libsais, bundled unchanged (src/zlib/README.md, src/sais/): deflate streams are
# made again bit for bit, so the deflate must be the same on every machine. Z_PREFIX keeps zlib's
# symbols apart from the system zlib that Qt links.
add_library(stratazip_c STATIC
    src/zlib/adler32.c
    src/zlib/crc32.c
    src/zlib/deflate.c
    src/zlib/inffast.c
    src/zlib/inflate.c
    src/zlib/inftrees.c
    src/zlib/trees.c
    src/zlib/zutil.c
    src/sais/libsais.c
)
set_target_properties(stratazip_c PROPERTIES LINKER_LANGUAGE C)
target_compile_definitions(stratazip_c PRIVATE Z_PREFIX)

add_executable(stratazip
    src/cuttest.cpp
    src/drivetest.cpp
    src/formattest.cpp
    src/historytest.cpp
    src/keccak.cpp
    src/liketest.cpp
    src/loosetest.cpp
    src/main.cpp
    src/mldsa.cpp
    src/mount.cpp
    src/recompress.cpp
    src/seal.cpp
    src/sealcurve.cpp
    src/sealmlkem.cpp
    src/sealprim.cpp
    src/sealtest.cpp
    src/sealtest2.cpp
    src/search.cpp
    src/searchtest.cpp
    src/sha256.cpp
    src/shards.cpp
    src/shardtest.cpp
    src/stratazip.cpp
    src/sync.cpp
    src/synctest.cpp
    src/xorkernels.cpp
    src/bwt.h
    src/bwt2.h
    src/cm10.h
    src/cm9.h
    src/golden.h
    src/keccak.h
    src/lstm.h
    src/lz.h
    src/mldsa.h
    src/mldsa_acvp.h
    src/mount.h
    src/picture.h
    src/recompress.h
    src/seal.h
    src/sealprim.h
    src/search.h
    src/sha256.h
    src/shards.h
    src/simd.h
    src/stratazip.h
    src/sync.h
    src/tables.h
    src/testswitch.h
    src/words.h
    src/x86model.h
    src/xorkernels.h
)
target_link_libraries(stratazip PRIVATE stratazip_c Qt6::Core Qt6::Concurrent)
target_compile_definitions(stratazip PRIVATE STRATAZIP_VERSION="${PROJECT_VERSION}" STRATAZIP_RELEASE Z_PREFIX)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # No fused multiply-add and no fast-math: the strongest level's small neural model must give the
    # same bits on every machine. Archives are the same bytes on x86-64 and ARM64 (the self-test's
    # golden archives prove it); x86-64 takes SSE where it has it, others the plain paths.
    target_compile_options(stratazip PRIVATE -ffp-contract=off $<$<CONFIG:Release>:-O3>)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        target_compile_options(stratazip PRIVATE -march=x86-64-v2)
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS stratazip RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md LICENSE COMMERCIAL.md COMMERCIAL-LICENSE.md THIRD-PARTY-NOTICES.md CHANGELOG.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Self-test: ctest runs the quick tier (seconds; the golden archives among it). --test=full is the
# whole of it (about an hour).
enable_testing()
add_test(NAME selftest COMMAND stratazip --test)

# Packages: cpack -G DEB (Debian, Ubuntu, Kubuntu) or cpack -G TGZ.
set(CPACK_PACKAGE_NAME "stratazip")
set(CPACK_PACKAGE_VENDOR "StrataZip")
set(CPACK_PACKAGE_CONTACT "StrataZip <hello@stratazip.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
# Dependencies are written out by hand, not found by dpkg-shlibdeps: the Qt libraries are
# named differently across releases (Ubuntu 24.04 has libqt6concurrent6t64, 26.04 has
# libqt6concurrent6), and a package built on one release must install on the others.
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libc6 (>= 2.34), libstdc++6 (>= 11), libgcc-s1, libqt6core6t64 (>= 6.4) | libqt6core6 (>= 6.4), libqt6concurrent6t64 (>= 6.4) | libqt6concurrent6 (>= 6.4)")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/thomholden/StrataZip")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
include(CPack)
