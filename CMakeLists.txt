cmake_minimum_required(VERSION 3.0.0)
project(rss_nn LANGUAGES C CXX)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)


# set(CMAKE_C_COMPILER             "/usr/bin/clang-11")
# set(CMAKE_C_COMPILER             "/usr/bin/clang")
set(CMAKE_C_FLAGS                "-pthread -O3 -fomit-frame-pointer -march=native -Wall -ffast-math -fopenmp -std=c99")
set(CMAKE_C_FLAGS_DEBUG          "-g")
set(CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE        "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")


set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_COMPILER             "/usr/bin/clang++-11")
# set(CMAKE_CXX_COMPILER             "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS                "-pthread -O3 -fomit-frame-pointer -march=native -Wall -ffast-math -fopenmp")
set(CMAKE_CXX_FLAGS_DEBUG          "-g3 -Wall")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -DNDEBUG")
# set(CMAKE_CXX_FLAGS_RELEASE        "-Ofast")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
#-msse4.2 -mavx -mavx2 -mpclmul -maes

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
# set(CMAKE_BUILD_PARALLEL_LEVEL 8)


# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")   # Add more flags here
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -march=native")
# set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -Wall")

find_package(OpenSSL REQUIRED)
find_package(CryptoPP REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")

INCLUDE_DIRECTORIES(
  "${CMAKE_SOURCE_DIR}/include"
)

file(GLOB SERVERSOURCES 
                "src/ServerMain.cpp"
                "src/connection/*.cpp"
                "src/server_extension/*.cpp"
                "src/protocols_basic/*.cpp"
                "src/utilities/*.cpp"
                "src/utilities/*.c"
                "src/FSS/*.cpp"
                "src/Cass/*.cpp"
)

file(GLOB CLIENTSOURCES 
                "src/ClientMain.cpp"
                "src/PRP/*.cpp"
                "src/client_extension/*.cpp"
                "src/utilities/*.cpp"
                "src/utilities/*.c"
                "src/FSS/*.cpp"
)

add_executable(server ${SERVERSOURCES})
set_target_properties(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(client ${CLIENTSOURCES})
set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# 静态库
add_library(static_lib STATIC IMPORTED)
set_target_properties(static_lib PROPERTIES IMPORTED_LOCATION "../library/libcrypto.a")
target_link_libraries(server 
  ${OPENSSL_LIBRARIES} 
  ${CRYPTOPP_LIBRARIES}
  dl
  ssl
  gmpxx
  gmp
  pthread
  boost_thread
  boost_system
  static_lib
  cassandra
  tcmalloc
)
target_link_libraries(client 
  ${OPENSSL_LIBRARIES} 
  ${CRYPTOPP_LIBRARIES}
  dl
  ssl
  gmpxx
  gmp
  pthread
  boost_thread
  boost_system
  static_lib
  tcmalloc
)

# install(TARGETS rss_nn
#         DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/)


add_custom_target(clean-all
  make clean && rm -fR ${CMAKE_BINARY_DIR}/CMakeCache.txt
                       ${CMAKE_BINARY_DIR}/cmake_install.cmake
                       ${CMAKE_BINARY_DIR}/Makefile
                       ${CMAKE_BINARY_DIR}/CMakeFiles
             && rmdir  ${CMAKE_BINARY_DIR}/build
)