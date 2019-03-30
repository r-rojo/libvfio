#include "vfiocpp.h"
#include <pybind11/pybind11.h>

namespace py = pybind11;
using namespace vfio;

PYBIND11_MODULE(vfio_driver, m) {
  py::class_<device, device::ptr_t> pydevice(m, "device", "");
  pydevice.def_static("open", &device::open)
      .def("descriptor", &device::descriptor)
      .def_property_readonly("num_regions", &device::num_regions)
      .def_property_readonly("regions", &device::regions);

  py::class_<region, region::ptr_t> pyregion(m, "region", "");
  pyregion.def("write32", &region::write32)
      .def("write64", &region::write64)
      .def("read32", &region::read32)
      .def("read64", &region::read64);
}
