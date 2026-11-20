#################################################################
#  Date             23/01/2020                                  #
#  Author           Chi Thanh NGUYEN                            #
#                                                               #
#  Copyright (c) 2020 nChain Limited. All rights reserved       #
#################################################################

include(FindBoostHelper)
HelpFindBoost(unit_test_framework)
if (NOT TARGET Boost::unit_test_framework)
  message(FATAL_ERROR "Boost::unit_test_framework is required but not found")
endif()

macro(bdk_add_unit_test _targetName)
  if(NOT TARGET ${_targetName})
      message(FATAL_ERROR " [${_targetName}] is not a TARGET")
  endif()
  bdkLinkTargetToBoost(${_targetName} Boost::unit_test_framework)
  set_target_properties(${_targetName} PROPERTIES  FOLDER "test/unit" DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})

  if(CMAKE_CONFIGURATION_TYPES)
    set(_tpost_fix ${CMAKE_DEBUG_POSTFIX})
    ## Note at the moment, on Windows Py Module can be loaded only in release build. There are problem in debug build
    add_test(NAME ${_targetName} COMMAND $<TARGET_FILE:${_targetName}> --report_format=HRF --report_level=detailed --log_format=JUNIT --log_sink=$<TARGET_FILE:${_targetName}>.xml ${ARGN} CONFIGURATIONS Release)
    add_test(NAME ${_targetName}${_tpost_fix} COMMAND $<TARGET_FILE:${_targetName}> --report_format=HRF --report_level=detailed --log_format=JUNIT --log_sink=$<TARGET_FILE:${_targetName}>.xml ${ARGN} CONFIGURATIONS Debug)
  else()
    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
      set(_tpost_fix ${CMAKE_DEBUG_POSTFIX})
    endif()
    add_test(NAME ${_targetName}${_tpost_fix} COMMAND $<TARGET_FILE:${_targetName}> --report_format=HRF --report_level=detailed --log_format=JUNIT --log_sink=$<TARGET_FILE:${_targetName}>.xml ${ARGN})
  endif()
endmacro()

## Like bdk_add_unit_test, but test cases labelled `integration` in Boost (those
## that write files or read the live system) run as a second entry,
## <target>_integration, labelled `integration` in CTest. `ctest -LE integration`
## runs only the pure unit tests, `ctest -L integration` only these.
macro(bdk_add_unit_and_integration_test _targetName)
  bdk_add_unit_test(${_targetName} --run_test=!@integration)
  set(_integration_args --run_test=@integration --report_format=HRF --report_level=detailed --log_format=JUNIT --log_sink=$<TARGET_FILE:${_targetName}>_integration.xml)
  if(CMAKE_CONFIGURATION_TYPES)
    add_test(NAME ${_targetName}_integration COMMAND $<TARGET_FILE:${_targetName}> ${_integration_args} CONFIGURATIONS Release)
    add_test(NAME ${_targetName}${CMAKE_DEBUG_POSTFIX}_integration COMMAND $<TARGET_FILE:${_targetName}> ${_integration_args} CONFIGURATIONS Debug)
    set_tests_properties(${_targetName}_integration ${_targetName}${CMAKE_DEBUG_POSTFIX}_integration PROPERTIES LABELS integration)
  else()
    set(_integration_name ${_targetName}_integration)
    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
      set(_integration_name ${_targetName}${CMAKE_DEBUG_POSTFIX}_integration)
    endif()
    add_test(NAME ${_integration_name} COMMAND $<TARGET_FILE:${_targetName}> ${_integration_args})
    set_tests_properties(${_integration_name} PROPERTIES LABELS integration)
  endif()
endmacro()

if(BDK_BUILD_CORE_TESTS)## Broken now as dependencies has been reduce to minimal
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/core")
endif()

## Test binding modules
if(BUILD_MODULE_GOLANG AND NOT MSVC)
  add_subdirectory(golang)
  ## The cgo shim itself, exercised natively against the static-GoBDK target
  add_subdirectory(gobdkshim)
else()
  message(STATUS "Testing Golang module has been disabled")
endif()

if(BUILD_MODULE_RUST AND NOT MSVC)
  add_subdirectory(rust)
else()
  message(STATUS "Testing Rust module has been disabled")
endif()