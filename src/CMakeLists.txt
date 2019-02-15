set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
set(PYBIND11_CPP_STANDARD -std=c++11)
include_directories(${CMAKE_SOURCE_DIR}/include)
add_library(vfiocpp SHARED
    vfiocpp.cpp
    )

pybind11_add_module(vfio_driver THIN_LTO vfiocpp.cpp vfio_driver.cpp)
set_target_properties(vfio_driver PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
                                             SUFFIX ".so")
