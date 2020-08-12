set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
include_directories(${LIBVFIO_INCLUDE})
add_library(vfiocpp SHARED
    vfiocpp.cpp
    )

add_library(vfiocpp-static STATIC
    vfiocpp.cpp
    )

if (LIBVFIO_BUILD_PYTHON_BINDINGS)
    set(PYBIND11_CPP_STANDARD -std=c++11)
    pybind11_add_module(vfio_driver THIN_LTO vfiocpp.cpp vfio_driver.cpp)
    set_target_properties(vfio_driver PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
                                                 SUFFIX ".so")
endif()
