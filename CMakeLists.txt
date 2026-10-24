# SPDX-License-Identifier: AGPL-3.0-only
# StrataZip: maximum-ratio archiving. Build: cmake -B build && cmake --build build
cmake_minimum_required(VERSION 3.19)
project(StrataZip VERSION 1.0.0 DESCRIPTION "Maximum-ratio file and directory archiver" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Concurrent)

# The codec uses SSE2/SSSE3/SSE4.1 intrinsics, with run-time checks for anything newer
# (carry-less multiply, SHA-NI, AVX2): x86-64 only for now. x86-64-v2 is any x86-64
# processor from about 2009 on.
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    message(FATAL_ERROR "StrataZip currently builds for x86-64 only (found ${CMAKE_SYSTEM_PROCESSOR}).")
endif()

add_executable(stratazip
    src/main.cpp
    src/stratazip.cpp  src/stratazip.h
    src/sha256.cpp     src/sha256.h
    src/xorkernels.cpp src/xorkernels.h
)
target_link_libraries(stratazip PRIVATE Qt6::Core Qt6::Concurrent)
target_compile_definitions(stratazip PRIVATE STRATAZIP_VERSION="${PROJECT_VERSION}")
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(stratazip PRIVATE -march=x86-64-v2 $<$<CONFIG:Release>:-O3>)
endif()

include(GNUInstallDirs)
install(TARGETS stratazip RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md LICENSE COMMERCIAL.md COMMERCIAL-LICENSE.md THIRD-PARTY-NOTICES.md CHANGELOG.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Self-test: ctest runs the built-in checks (several minutes; they include the strongest level).
enable_testing()
add_test(NAME selftest COMMAND stratazip --test)

# Packages: cpack -G DEB (Debian, Ubuntu, Kubuntu) or cpack -G TGZ.
set(CPACK_PACKAGE_NAME "stratazip")
set(CPACK_PACKAGE_VENDOR "StrataZip")
set(CPACK_PACKAGE_CONTACT "StrataZip <hello@stratazip.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)             # the Qt packages, found by dpkg-shlibdeps
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/thomholden/StrataZip")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
include(CPack)
