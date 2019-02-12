set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
include_directories(${CMAKE_SOURCE_DIR}/include)
add_library(vfiocpp SHARED
    vfiocpp.cpp
    )
