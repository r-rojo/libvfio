#include <linux/vfio.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <iostream>
#include <mutex>
#include "vfiocpp.h"

namespace vfio {

std::mutex c_mutex;

container::ptr_t instance_(0);

container::container(int fd) : fd_(fd) {}
container::~container() {
  if (fd_ >= -1) {
    ::close(fd_);
  }
}

container::ptr_t container::instance() {
  std::lock_guard<std::mutex> lock(c_mutex);
  if (!instance_) {
    int fd = ::open("/dev/vfio/vfio", O_RDWR);
    if (fd < 0) {
      std::cerr << "error opening vfio device\n";
      return nullptr;
    }

    instance_.reset(new container(fd));
    if (ioctl(fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
      std::cerr << "unknown vfio api version\n";
      instance_.reset();
    }

    if (!ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
      std::cerr << "iommu driver not supported\n";
      instance_.reset();
    }
  }
  return instance_;
}

system_buffer::~system_buffer() {
  if (addr_) {
    munmap(addr_, size_);
    addr_ = nullptr;
  }
}

system_buffer::ptr_t system_buffer::allocate(size_t sz) {
  void *addr =
      mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  if (!addr) {
    std::cerr << "error allocating buffer of size: " << sz << "\n";
    return nullptr;
  }

  struct vfio_iommu_type1_dma_map dma_map;

  dma_map.vaddr = reinterpret_cast<uint64_t>(addr);
  dma_map.size = sz;
  dma_map.iova = 0;
  dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
  if (ioctl(container::instance()->descriptor(), VFIO_IOMMU_MAP_DMA,
            &dma_map)) {
    std::cerr << "error mapping dma map\n";
    return nullptr;
  }
  return system_buffer::ptr_t(new system_buffer(addr, dma_map.iova, sz));
}

device::device(int container, int group_fd, int device_fd)
    : group_fd_(group_fd), device_fd_(device_fd), container_(container) {}
device::~device() {
  ioctl(device_fd_, VFIO_DEVICE_RESET);
  ::close(group_fd_);
}

device::ptr_t device::open(const std::string &path,
                           const std::string &pciinfo) {
  int group_fd = ::open(path.c_str(), O_RDWR);
  if (group_fd < 0) {
    std::cerr << "error opening vfio group: " << path << "\n";
    return nullptr;
  }

  struct vfio_group_status group_status;
  ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
    std::cerr << "group is not viable\n";
  }

  auto container_ptr = container::instance();
  if (!container_ptr) {
    std::cerr << "error getting container\n";
    return nullptr;
  }

  int container_fd = container_ptr->descriptor();
  if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd)) {
    std::cerr << "erroo setting group container\n";
    return nullptr;
  }

  int device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, pciinfo.c_str());
  struct vfio_device_info device_info = {.argsz = sizeof(device_info)};
  if (ioctl(device_fd, VFIO_DEVICE_GET_INFO, &device_info)) {
    std::cerr << "error getting device info\n";
    return nullptr;
  }

  device::ptr_t ptr(new device(group_fd, device_fd, container_fd));
  return ptr;
}

}  // end of namespace vfio
