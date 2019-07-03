# set (TOP_TTCN /home/vtarasov/projects/idnomic/innovation/its-pki-lib/gerrithub.titan.core)
# include $(TOP)/Makefile.cfg

add_definitions(-DPLATFORM=LINUX -DLINUX)

macro(install_symlink filepath sympath)
	install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
	install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
endmacro(install_symlink)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL_LIBCRYPTO REQUIRED libcrypto)
pkg_check_modules(TTCN3 REQUIRED ttcn3-nomain)
pkg_check_modules(YAML_CPP REQUIRED yaml-cpp)
pkg_check_modules(ETSITS102941 REQUIRED EtsiTs102941)
# message("Libs: ${OPENSSL_LIBCRYPTO_LIBRARIES}, ${TTCN3_LIBRARIES}, ${YAML_CPP_LIBRARIES}")

set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG} -DITS_PKI_DEBUG)
message("CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG}")

set(LIBITSPKI_SRC library/itspki-debug.cpp library/itspki-etsi.cpp library/itspki-internal-data.cpp library/itspki-session.cpp library/utils.cpp library/utils-openssl.cpp library/utils-ttcn.cpp)

include_directories(./include ${PROJECT_BINARY_DIR} ${OPENSSL_LIBCRYPTO_INCLUDE_DIRS} ${TTCN3_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS} ${ETSITS102941_INCLUDE_DIRS})

add_library(libitspki_dynamic SHARED ${LIBITSPKI_SRC})
add_library(libitspki_static STATIC  ${LIBITSPKI_SRC})
add_library(libitspki_debug_dynamic SHARED ${LIBITSPKI_SRC})
add_library(libitspki_debug_static STATIC  ${LIBITSPKI_SRC})

set_target_properties(libitspki_dynamic PROPERTIES OUTPUT_NAME "itspki")
set_target_properties(libitspki_dynamic PROPERTIES VERSION 1.2 SOVERSION 1)
set_target_properties(libitspki_debug_dynamic PROPERTIES OUTPUT_NAME "itspki-debug")
set_target_properties(libitspki_debug_dynamic PROPERTIES VERSION 1.2 SOVERSION 1)

# target_link_libraries(testapp ${SDL2_LIBRARIES})
target_include_directories(libitspki_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_INCLUDE_DIRS})
target_compile_options(libitspki_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_CFLAGS_OTHER})
target_include_directories(libitspki_debug_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_INCLUDE_DIRS})
target_compile_options(libitspki_debug_dynamic PUBLIC ${OPENSSL_LIBCRYPTO_CFLAGS_OTHER} -DITS_PKI_DEBUG)

set_target_properties(libitspki_static PROPERTIES OUTPUT_NAME "itspki")
set_target_properties(libitspki_debug_static PROPERTIES OUTPUT_NAME "itspki-debug")
target_compile_options(libitspki_debug_static PUBLIC ${OPENSSL_LIBCRYPTO_CFLAGS_OTHER} -DITS_PKI_DEBUG)

# set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.pc.cmakein ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)

install(TARGETS libitspki_dynamic libitspki_static  libitspki_debug_dynamic libitspki_debug_static 
        LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include/its
        ARCHIVE DESTINATION lib)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libitspki.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")

install_symlink("${INSTALL_PKGCONFIG_DIR}/${PROJECT_NAME}.pc" "/usr/local/lib/pkgconfig/${PROJECT_NAME}.pc")

install(DIRECTORY include/its/ DESTINATION include/its/)

message ("CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}, CMAKE_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR}")

# library that holds sources to test
add_library(test_itspki "")
target_sources(
    test_itspki
    PRIVATE
	library/itspki-debug.cpp
	library/itspki-etsi.cpp
	library/itspki-internal-data.cpp
	library/itspki-session.cpp
	library/utils.cpp
	library/utils-openssl.cpp
	library/utils-ttcn.cpp
    PUBLIC
    	${CMAKE_CURRENT_LIST_DIR}/include/its/its-asn1-modules.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/itspki-debug.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/itspki-etsi.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/itspki-internal-data.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/itspki-session.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils-openssl.hh
	${CMAKE_CURRENT_LIST_DIR}/include/its/utils-ttcn.hh
    )

target_include_directories(
    test_itspki
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include/its
    )
