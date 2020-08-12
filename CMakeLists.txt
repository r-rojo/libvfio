cmake_minimum_required(VERSION 3.0)

set(LIBVFIO_INCLUDE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    CACHE PATH "Path to libvfio include")
option(LIBVFIO_BUILD_PYTHON_BINDINGS "Build python bindings" OFF)
if(LIBVFIO_BUILD_PYTHON_BINDINGS)
    add_subdirectory(thirdparty)
endif()
add_subdirectory(src)
