cmake_minimum_required(VERSION 3.0)

option(LIBVFIO_BUILD_PYTHON_BINDINGS "Build python bindings" OFF)
if(LIBVFIO_BUILD_PYTHON_BINDINGS)
    add_subdirectory(thirdparty)
endif()
add_subdirectory(src)
