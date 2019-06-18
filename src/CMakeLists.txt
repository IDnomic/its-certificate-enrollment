# set (TOP_TTCN /home/vtarasov/projects/idnomic/innovation/its-pki-lib/gerrithub.titan.core)
# include $(TOP)/Makefile.cfg

add_definitions(-DPLATFORM=LINUX -DLINUX)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL_LIBCRYPTO REQUIRED libcrypto)
pkg_check_modules(TTCN3 REQUIRED ttcn3-nomain)
pkg_check_modules(YAML_CPP REQUIRED yaml-cpp)
pkg_check_modules(LIBETSITS102941 REQUIRED EtsiTs102941)
# message("Libs: ${OPENSSL_LIBCRYPTO_LIBRARIES}, ${TTCN3_LIBRARIES}, ${YAML_CPP_LIBRARIES}")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -DITS_PKI_DEBUG")
message("CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG}")

set(LIBITSENROLLMENT_SRC library/pki-its-cmd-args.cpp library/pki-its-debug.cpp library/pki-its-etsi.cpp library/pki-its-internal-data.cpp library/pki-its-work.cpp library/utils.cpp library/utils-openssl.cpp library/utils-ttcn.cpp)

include_directories(./include ${PROJECT_BINARY_DIR} ${OPENSSL_LIBCRYPTO_INCLUDE_DIRS} ${TTCN3_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS} ${LIBETSITS102941_INCLUDE_DIRS})

add_library(libitsenrollment_dynamic SHARED ${LIBITSENROLLMENT_SRC})
add_library(libitsenrollment_static STATIC  ${LIBITSENROLLMENT_SRC})

set_target_properties(libitsenrollment_dynamic PROPERTIES OUTPUT_NAME "itsenrollment")
set_target_properties(libitsenrollment_dynamic PROPERTIES VERSION 1.2 SOVERSION 1)

# target_link_libraries(testapp ${SDL2_LIBRARIES})
target_include_directories(libitsenrollment_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_INCLUDE_DIRS})
target_compile_options(libitsenrollment_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_CFLAGS_OTHER})

set_target_properties(libitsenrollment_static PROPERTIES OUTPUT_NAME "itsenrollment")

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

install(TARGETS libitsenrollment_dynamic libitsenrollment_static
        LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include/its
        ARCHIVE DESTINATION lib)

install(DIRECTORY include/its/
	DESTINATION include/its/)

# library that holds sources to test
add_library(test_itsenrollment "")
target_sources(
    test_itsenrollment
    PRIVATE
	library/pki-its-cmd-args.cpp
	library/pki-its-debug.cpp
	library/pki-its-etsi.cpp
	library/pki-its-internal-data.cpp
	library/pki-its-work.cpp
	library/utils.cpp
	library/utils-openssl.cpp
	library/utils-ttcn.cpp
    PUBLIC
    	${CMAKE_CURRENT_LIST_DIR}/include/its/its-asn1-modules.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/pki-its-cmd-args.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/pki-its-debug.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/pki-its-etsi.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/pki-its-internal-data.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/pki-its-work.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils-openssl.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils-ttcn.hh
    )

target_include_directories(
    test_itsenrollment
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include/its
    )
