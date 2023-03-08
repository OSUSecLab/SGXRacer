# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper mecro to either sign an SGX enclave binary or to generate and sign
# an OP-TEE-compatible enclave binary.
#
# Usage:
#
#  add_enclave(<TARGET target>
#              [<UUID uuid>]
#              [CXX]
#              <SOURCES sources>
#              [<CONFIG config>]
#              [<KEY key>])
#
# For SGX enclaves:
# Given <target> and <config>, this function adds custom commands to
# generate a signing key if key is not specified and call `oesign` to
# sign the target, resulting in `<target>.signed`. It also adds
# `<target>_signed` as an imported target so that it can be referenced
# later in the CMake graph.
#
# For OP-TEE enclaves:
# Given <target> and <uuid>, this function adds custom commands to
# generate and sign an OP-TEE Trusted Application (TA), the equivalent
# of an enclave for ARM TrustZone. TA binaries must follow a specific
# layout to be loadable by OP-TEE's loader. This macro helps ensure that
# that layout is indeed followed, adding a `<target>.ta` target to generate
# the final TA binary. Additionally, TA binaries must be named with a UUID.
# As such, while the CMake target names remain in sync with <target>, the
# resulting binaries use <uuid> plus their corresponding extension as their
# on-disk name.
#
# The target is always linked to `oeenclave`, and if the optional flag
# `CXX` is passed, it is also linked to `oelibcxx`
#
# NOTE: This must be a macro! To generate TA binaries, a custom linker
#       command is necessary. The only way to control the linker command
#       is for it to appear at the bottom of the CMakeLists.txt file that
#       calls for the generation of the TA. Making add_enclave and/or
#       add_enclave_optee into a function breaks their functionality.
#
# TODO: (1) Replace the name guessing logic.
# TODO: (2) Setup the dependency using `${BIN}_signed` instead of the
# default custom target.
# TODO: (3) Validate arguments into this function
macro(add_enclave)
  set(options CXX)
  set(oneValueArgs TARGET UUID CONFIG KEY)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(ENCLAVE
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN})

  if(OE_SGX)
    add_enclave_sgx(
      CXX ${ENCLAVE_CXX}
      TARGET ${ENCLAVE_TARGET}
      CONFIG ${ENCLAVE_CONFIG}
      KEY ${ENCLAVE_KEY}
      SOURCES ${ENCLAVE_SOURCES})
  elseif(OE_TRUSTZONE)
    add_enclave_optee(
      CXX ${ENCLAVE_CXX}
      TARGET ${ENCLAVE_TARGET}
      UUID ${ENCLAVE_UUID}
      KEY ${ENCLAVE_KEY}
      SOURCES ${ENCLAVE_SOURCES})
  endif()
endmacro()

function(add_enclave_sgx)
  set(options CXX)
  set(oneValueArgs TARGET CONFIG KEY)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(ENCLAVE
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN})

  add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
  target_link_libraries(${ENCLAVE_TARGET} oeenclave)
  if (ENCLAVE_CXX)
    target_link_libraries(${ENCLAVE_TARGET} oelibcxx)
  endif ()

  # Cross-compile if needed.
  if (USE_CLANGW)
    maybe_build_using_clangw(${ENCLAVE_TARGET})

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}" PARENT_SCOPE)

    # Propagate library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_CXX_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)

    # Propagate linker variables
    set(CMAKE_EXECUTABLE_SUFFIX "${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE}" PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE}" PARENT_SCOPE)

    # Propagate cpmpiler variables
    set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}" PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}" PARENT_SCOPE)
  endif()

   if (NOT ENCLAVE_CONFIG)
      # Since the config is not specified, the enclave wont be signed.
      return()
   endif ()

  # Generate the signing key.
  if(NOT ENCLAVE_KEY)
     add_custom_command(OUTPUT ${ENCLAVE_TARGET}-private.pem
       COMMAND openssl genrsa -out ${ENCLAVE_TARGET}-private.pem -3 3072)
     set(ENCLAVE_KEY  ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_TARGET}-private.pem)
  endif()

  # TODO: Get this name intelligently (somehow use $<TARGET_FILE> with
  # `.signed` injected).
  set(SIGNED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_TARGET}.signed)

  # Sign the enclave using `oesign`.
  if(ENCLAVE_CONFIG)
    add_custom_command(OUTPUT ${SIGNED_LOCATION}
      COMMAND oesign sign -e $<TARGET_FILE:${ENCLAVE_TARGET}> -c ${ENCLAVE_CONFIG} -k ${ENCLAVE_KEY}
      DEPENDS oesign ${ENCLAVE_TARGET} ${ENCLAVE_CONFIG} ${ENCLAVE_KEY}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  endif()

  # Import the generated signed enclave so we can reference it with
  # `$<TARGET_FILE>` later.
  add_library(${ENCLAVE_TARGET}_signed SHARED IMPORTED GLOBAL)
  set_target_properties(${ENCLAVE_TARGET}_signed PROPERTIES
    IMPORTED_LOCATION ${SIGNED_LOCATION})

  # Add a custom target with `ALL` semantics so these targets are always built.
  add_custom_target(${ENCLAVE_TARGET}_signed_target ALL DEPENDS ${SIGNED_LOCATION})
endfunction()

macro(add_enclave_optee)
   set(options CXX)
   set(oneValueArgs TARGET UUID KEY)
   set(multiValueArgs SOURCES)
   cmake_parse_arguments(ENCLAVE
     "${options}"
     "${oneValueArgs}"
     "${multiValueArgs}"
     ${ARGN})

  # Set up the linker flags exactly as we need them such that the resulting
  # binary be compatible with OP-TEE's loader.
  set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
  set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
  set(CMAKE_EXE_EXPORTS_C_FLAG)

  string(REPLACE "gcc" "ld" LINKER ${CMAKE_C_COMPILER})
  set(CMAKE_C_LINK_EXECUTABLE "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> <LINK_LIBRARIES> -lgcc -o <TARGET>")
  set(CMAKE_CXX_LINK_EXECUTABLE "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> <LINK_LIBRARIES> -lgcc -o <TARGET>")

  # Generate linker script from template.
  string(REPLACE "gcc" "cpp" C_PREPROCESSOR ${CMAKE_C_COMPILER})
  set(TA_LINKER_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/ta.ld)
  set(TA_LINKER_SCRIPT ${TA_LINKER_SCRIPT} PARENT_SCOPE)
  add_custom_target(${ENCLAVE_TARGET}.ld
    COMMAND
      ${C_PREPROCESSOR} -Wp,-P -DASM=1 -DARM64 -nostdinc ${OE_TZ_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE} > ${TA_LINKER_SCRIPT}
    SOURCES ${OE_TZ_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE}
    DEPENDS ${OE_TZ_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE}
    BYPRODUCTS ${TA_LINKER_SCRIPT})

  # Ask GCC where is libgcc.
  execute_process(
    COMMAND ${CMAKE_C_COMPILER}
      ${OE_TZ_TA_C_FLAGS}
      -print-libgcc-file-name
    OUTPUT_VARIABLE LIBGCC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  get_filename_component(LIBGCC_PATH ${LIBGCC_PATH} DIRECTORY)

  # Set up the target.
  add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
  set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES OUTPUT_NAME ${ENCLAVE_UUID})
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES SUFFIX ".elf")
  add_dependencies(${ENCLAVE_TARGET} ${ENCLAVE_TARGET}.ld)
  target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/optee)
  target_link_libraries(${ENCLAVE_TARGET} oeenclave)
  if(ENCLAVE_CXX)
    target_link_libraries(${ENCLAVE_TARGET} oelibcxx)
  endif()

  # Strip unneeded bits.
  string(REPLACE "gcc" "objcopy" OBJCOPY ${CMAKE_C_COMPILER})
  add_custom_target(${ENCLAVE_TARGET}.stripped.elf
    COMMAND
      ${OBJCOPY}
        --strip-unneeded $<TARGET_FILE:${ENCLAVE_TARGET}>
        $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
    BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf)
  add_dependencies(${ENCLAVE_TARGET}.stripped.elf ${ENCLAVE_TARGET})

  # Sign the TA with the given key, or with the default key if none was given.
  if(NOT ENCLAVE_KEY)
    set(ENCLAVE_KEY ${OE_TZ_TA_DEV_KIT_DEFAULT_SIGNING_KEY})
  endif()
  add_custom_target(${ENCLAVE_TARGET}.ta ALL
    COMMAND
      ${OE_TZ_TA_DEV_KIT_SIGN_TOOL}
        --key ${ENCLAVE_KEY}
        --uuid ${ENCLAVE_UUID}
        --version 0
        --in $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
        --out $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta
    BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta)
  add_dependencies(${ENCLAVE_TARGET}.ta ${ENCLAVE_TARGET}.stripped.elf)

  # Set linker options.
  # NOTE: This has to be at the end, apparently:
  #       https://gitlab.kitware.com/cmake/cmake/issues/17210
  set(CMAKE_EXE_LINKER_FLAGS "-T ${TA_LINKER_SCRIPT} -L${LIBGCC_PATH}")
  if(ENCLAVE_CXX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --eh-frame-hdr --entry=_start")
  endif()
endmacro()
