#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "vfiocpp.h"

namespace py = pybind11;
using namespace vfio;

#ifdef LIBVFIO_EMBED
#include <pybind11/embed.h>
PYBIND11_EMBEDDED_MODULE(libvfio, m)
#else
PYBIND11_MODULE(vfio, m)
#endif
{
  py::class_<device, device::ptr_t> pydevice(m, "device", "");
  pydevice.def_static("open", &device::open)
      .def_static("open_pciaddress", &device::open_pciaddress)
      .def("descriptor", &device::descriptor)
      .def("close", &device::close)
      .def("__getitem__", &device::config_read<uint32_t>)
      .def("__setitem__", &device::config_write<uint32_t>)
      .def("config_read32", &device::config_read<uint32_t>)
      .def("config_write32", &device::config_write<uint32_t>)
      .def("config_read16", &device::config_read<uint16_t>)
      .def("config_write16", &device::config_write<uint16_t>)
      .def("config_read8", &device::config_read<uint8_t>)
      .def("config_write8", &device::config_write<uint8_t>)
      .def("__repr__", &device::pci_address)
      .def_property_readonly("pci_address", &device::pci_address)
      .def_property_readonly("num_regions", &device::num_regions)
      .def_property_readonly("regions", &device::regions);

  py::class_<region, region::ptr_t> pyregion(m, "region", "");
  pyregion.def("write32", &region::write32)
      .def("write64", &region::write64)
      .def("read32", &region::read32)
      .def("read64", &region::read64)
      .def("close", &region::close)
      .def("index", &region::index)
      .def("__repr__", [](region::ptr_t r){ return std::to_string(r->index()); })
      .def("__len__", &region::size);

  py::class_<system_buffer, system_buffer::ptr_t> pybuffer(m, "system_buffer", "");
  pybuffer
      .def_static("allocate", &system_buffer::allocate, "allocate a shared buffer")
      .def_property_readonly("size", &system_buffer::size)
      .def_property_readonly("address", &system_buffer::address)
      .def_property_readonly("io_address", &system_buffer::io_address)
      .def("carve", &system_buffer::carve)
      .def("__getitem__", &system_buffer::get_uint64)
      .def("__setitem__", &system_buffer::set_uint64)
      .def("read8", &system_buffer::get<uint8_t>)
      .def("read16", &system_buffer::get<uint16_t>)
      .def("read32", &system_buffer::get<uint32_t>)
      .def("read64", &system_buffer::get<uint64_t>)
      .def("fill8", &system_buffer::fill<uint8_t>)
      .def("fill16", &system_buffer::fill<uint16_t>)
      .def("fill32", &system_buffer::fill<uint32_t>)
      .def("fill64", &system_buffer::fill<uint64_t>)
      .def("compare", &system_buffer::compare);

}
