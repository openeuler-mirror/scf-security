if(NOT DEFINED ARTIFACT OR NOT EXISTS "${ARTIFACT}")
    message(FATAL_ERROR "Hardening check artifact does not exist: ${ARTIFACT}")
endif()
if(NOT DEFINED READELF OR NOT EXISTS "${READELF}")
    message(FATAL_ERROR "Hardening check readelf does not exist: ${READELF}")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -E env LC_ALL=C ${READELF} -h -W -l -d ${ARTIFACT}
    RESULT_VARIABLE _readelf_result
    OUTPUT_VARIABLE _readelf_output
    ERROR_VARIABLE _readelf_error
)
if(NOT _readelf_result EQUAL 0)
    message(FATAL_ERROR "readelf failed for ${ARTIFACT}: ${_readelf_error}")
endif()

string(FIND "${_readelf_output}" "GNU_RELRO" _relro_index)
if(_relro_index EQUAL -1)
    message(FATAL_ERROR "${ARTIFACT} is missing GNU_RELRO")
endif()

string(REGEX MATCH "GNU_STACK[^\n]*[RWX ]*E[ \t]" _executable_stack "${_readelf_output}")
if(_executable_stack)
    message(FATAL_ERROR "${ARTIFACT} has an executable GNU_STACK")
endif()
string(FIND "${_readelf_output}" "GNU_STACK" _stack_index)
if(_stack_index EQUAL -1)
    message(FATAL_ERROR "${ARTIFACT} is missing GNU_STACK")
endif()

string(FIND "${_readelf_output}" "BIND_NOW" _bind_now_index)
string(REGEX MATCH "FLAGS_1[^\n]*NOW" _now_flag "${_readelf_output}")
if(_bind_now_index EQUAL -1 AND NOT _now_flag)
    message(FATAL_ERROR "${ARTIFACT} is missing BIND_NOW")
endif()

if(REQUIRE_PIE)
    string(REGEX MATCH "Type:[ \t]+DYN([ \t(]|$)" _pie_type "${_readelf_output}")
    if(NOT _pie_type)
        message(FATAL_ERROR "${ARTIFACT} is not a PIE executable")
    endif()
endif()

message(STATUS "Hardening check passed: ${ARTIFACT}")
