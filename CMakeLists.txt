cmake_minimum_required(VERSION 3.14)
project(secpack VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBLZMA REQUIRED liblzma)
find_package(OpenSSL REQUIRED)

add_executable(secpack
  src/main.cpp
  src/crypto.cpp
  src/compress.cpp
  src/tar.cpp
)

target_include_directories(secpack PRIVATE include ${LIBLZMA_INCLUDE_DIRS})

target_link_libraries(secpack PRIVATE OpenSSL::Crypto ${LIBLZMA_LIBRARIES})

install(TARGETS secpack RUNTIME DESTINATION bin)

# GUI option
option(SECPACK_BUILD_GUI "Build Qt6 GUI application" ON)
if(SECPACK_BUILD_GUI)
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTORCC ON)
  set(CMAKE_AUTOUIC ON)
  find_package(Qt6 COMPONENTS Widgets REQUIRED)
  add_executable(secpack_gui
    gui/main.cpp
    gui/MainWindow.cpp
    src/crypto.cpp
    src/compress.cpp
    src/tar.cpp
  )
  target_include_directories(secpack_gui PRIVATE include ${LIBLZMA_INCLUDE_DIRS} gui)
  target_link_libraries(secpack_gui PRIVATE Qt6::Widgets OpenSSL::Crypto ${LIBLZMA_LIBRARIES})
  install(TARGETS secpack_gui RUNTIME DESTINATION bin)
endif()

