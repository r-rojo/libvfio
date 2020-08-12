#include <linux/vfio.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <mutex>
#include <stdexcept>
#include "vfiocpp.h"

namespace vfio {


region::sparse_info_list
vfio_get_sparse_info(int device_fd, const struct vfio_region_info &rinfo)
{
  region::sparse_info_list sparse_list(0);

  std::vector<uint8_t> buffer(rinfo.argsz);
  struct vfio_region_info *rinfo_ptr =
    new(buffer.data()) struct vfio_region_info(rinfo);
  if (rinfo.flags & VFIO_REGION_INFO_FLAG_CAPS) {
    if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, rinfo_ptr)) {
      std::cerr << "failed to get region info again: " << strerror(errno) << "\n";
      return sparse_list;
    }
    struct vfio_info_cap_header *hdr = reinterpret_cast<vfio_info_cap_header*>(
      reinterpret_cast<uint8_t*>(rinfo_ptr) + rinfo_ptr->cap_offset);
    if (hdr->id == VFIO_REGION_INFO_CAP_SPARSE_MMAP) {
      auto sparse =
        reinterpret_cast<struct vfio_region_info_cap_sparse_mmap*>(hdr);
      for (uint32_t i = 0; i < sparse->nr_areas; ++i) {
        region::sparse_info_t info;
        info.index = i;
        info.offset = sparse->areas[i].offset;
        info.size = sparse->areas[i].size;
        sparse_list.push_back(info);

        //std::cout << "sparse: " << i
        //          << " offset: " << sparse->areas[i].offset
        //          << " size: " << sparse->areas[i].size
        //          << "\n";

      }

    }
  }
  return sparse_list;
}



std::mutex c_mutex;

container::ptr_t container::instance_(0);

container::container(int fd) : fd_(fd) {}
container::~container() {
  if (fd_ > -1) {
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

void container::discover_info()
{
  // get info to get the size
  struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
  if (ioctl(fd_, VFIO_IOMMU_GET_INFO, &iommu_info)) {
    std::cerr << "error getting iova range: \"" << strerror(errno) << "\"\n";
    return;
  }

  // now that we have the size, make a temporary buffer big enough
  std::vector<uint8_t> buffer(iommu_info.argsz);
  struct vfio_iommu_type1_info *info_ptr = reinterpret_cast<vfio_iommu_type1_info*>(buffer.data());
  info_ptr->argsz = iommu_info.argsz;
  if (ioctl(fd_, VFIO_IOMMU_GET_INFO, info_ptr)) {
    std::cerr << "error getting iova range: \"" << strerror(errno) << "\"\n";
  }

  struct vfio_info_cap_header *hdr =
    reinterpret_cast<struct vfio_info_cap_header*>(
      reinterpret_cast<uint8_t*>(info_ptr) + info_ptr->cap_offset);

  while(true) {
    if (hdr->id == VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE) {
      struct vfio_iommu_type1_info_cap_iova_range *io_range =
        reinterpret_cast<vfio_iommu_type1_info_cap_iova_range*>(hdr);
      for (uint32_t i = 0; i < io_range->nr_iovas; ++i) {
        const struct vfio_iova_range &r = io_range->iova_ranges[i];
        iova_ranges_.push_back(
            iova_range_t(r.start, r.end));
      }
    }
    if (hdr->next)
      hdr = reinterpret_cast<struct vfio_info_cap_header*>(buffer.data() + hdr->next);
    else
      break;
  }
}

bool container::reserve(uint64_t &size, uint64_t &iova)
{
  if (iova_ranges_.empty())
    discover_info();

  if (size == 0) {
    std::cerr << "size must be greater than zero\n";
    return false;
  }

  static uint64_t page_size = sysconf(_SC_PAGE_SIZE);
  size = page_size + ((size-1) & ~(page_size-1));
  for (auto & r : iova_ranges_) {
    if (r.next + size <= r.end) {
      iova = r.next;
      r.next += size;
      return true;
    }
  }
  return false;
}

bool container::unreserve(uint64_t iova)
{
  // TODO: optimize
  return false;
}

system_buffer::system_buffer(uint8_t *addr, uint64_t iova, size_t sz)
    : addr_(addr), iova_(iova), size_(sz), parent_(0), next_(0) {}

system_buffer::~system_buffer() {
  if (addr_ && !parent_) {
    struct vfio_iommu_type1_dma_unmap unmap {
      .argsz = sizeof(unmap)
    };
    unmap.iova = iova_;
    unmap.size = size_;
    if (ioctl(container::instance()->descriptor(), VFIO_IOMMU_UNMAP_DMA,
              &unmap)) {
      std::cerr << "error unmapping buffer from iommu\n";
    }
    munmap(addr_, size_);
    addr_ = nullptr;
  }
}

system_buffer::ptr_t system_buffer::allocate(size_t sz) {
  void *addr =
      mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, 0, 0);
  if (!addr) {
    std::cerr << "error allocating buffer of size: " << sz << "\n";
    return nullptr;
  }
  system_buffer::ptr_t ptr(0);
  auto c = container::instance();
  auto container_fd = c->descriptor();
  struct vfio_iommu_type1_dma_map dma_map;
  uint64_t iova;
  if (c->reserve(sz, iova)) {
    dma_map.vaddr = reinterpret_cast<uint64_t>(addr);
    dma_map.size = sz;
    dma_map.iova = iova;
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    if (ioctl(container_fd, VFIO_IOMMU_MAP_DMA, &dma_map))
      std::cerr << "error mapping dma map: \"" << strerror(errno) << "\"\n";
    else
      ptr.reset(new system_buffer(static_cast<uint8_t*>(addr), dma_map.iova, sz));
  }

  if (!ptr) {
    munmap(addr, sz);
  }
  return ptr;
}

system_buffer::ptr_t system_buffer::carve(size_t size)
{
  system_buffer::ptr_t child(0);
  if (next_ + size < size_) {
    child.reset(new system_buffer(addr_ + next_, iova_ + next_, size));
    child->parent_ = shared_from_this();
    next_ += size;
  }
  return child;
}

region::~region()
{
  close();
}

region::ptr_t region::map(uint32_t index, int fd, uint64_t offset, size_t sz) {
  ptr_t ptr(0);
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED;
  void *addr = mmap(0, sz, prot, flags, fd, static_cast<off_t>(offset));
  if (!addr || addr == MAP_FAILED) {
    std::cerr << "error mapping region: " << strerror(errno) << "\n";
  } else {
    ptr.reset(new region(index, reinterpret_cast<uint8_t *>(addr), sz));
  }

  return ptr;
}

region::ptr_t region::map_sparse(uint32_t index, int fd, uint64_t offset, size_t sz, const sparse_info_list &sparse) {
  ptr_t ptr(0);
  // allocate a buffer to map into
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_ANONYMOUS | MAP_PRIVATE;
  void *addr = mmap(0, sz, prot, flags, -1, 0);
  if (!addr || addr == MAP_FAILED) {
    std::cerr << "error mapping region: " << strerror(errno) << "\n";
    return nullptr;
  }

  for (const auto &info : sparse) {
    flags = MAP_FIXED | MAP_SHARED;
    auto map = mmap(reinterpret_cast<uint8_t*>(addr) + info.offset,
        info.size, prot, flags, fd, offset+info.offset);
    if (!map || map == MAP_FAILED) {
      std::cerr << "error mapping region: " << strerror(errno) << "\n";
    }
  }

  ptr.reset(new region(index, reinterpret_cast<uint8_t *>(addr), sz, sparse));

  return ptr;
}

#define ASSERT_OFFSET(_sz, _offset)                        \
  do {                                                     \
    if (_offset > _sz) {                                   \
      throw std::length_error("offset greater than size"); \
    }                                                      \
  } while (0)

void region::write32(uint64_t offset, uint32_t value) {
  ASSERT_OFFSET(size_, offset);
  *reinterpret_cast<uint32_t *>(ptr_ + offset) = value;
}

void region::write64(uint64_t offset, uint64_t value) {
  *reinterpret_cast<uint64_t *>(ptr_ + offset) = value;
}

uint32_t region::read32(uint64_t offset) {
  return *reinterpret_cast<uint32_t *>(ptr_ + offset);
}

uint64_t region::read64(uint64_t offset) {
  return *reinterpret_cast<uint64_t *>(ptr_ + offset);
}

void region::close() {
  if (ptr_) {
    for (const auto &info : sparse_) {
      munmap(ptr_ + info.offset, info.size);
    }
    munmap(ptr_, size_);
  }
}

device::device(int container, int group_fd, int device_fd)
    : group_fd_(group_fd), device_fd_(device_fd), container_(container), command_(0) {
    
}

device::~device() {
  close();
}

device::ptr_t device::open_pciaddress(const std::string &pciinfo) {
  std::string path = "/sys/bus/pci/devices/" + pciinfo + "/iommu_group";
  char buf[256];
  ssize_t l = readlink(path.c_str(), buf, sizeof(buf));
  if (l > 0) {
    std::string link(buf, l);
    auto group = "/dev/vfio/" + link.substr(link.rfind("/")+1);
    struct stat st;
    if (stat(group.c_str(), &st)) {
        std::cerr << "error accessing vfio device: " << group << "\n";
    } else {
      return device::open(group, pciinfo);
    }
  }
  if (l < 0) {
    std::cerr << "error reading link: " << strerror(errno) << std::endl;
  }
  return device::ptr_t(0);
}

device::ptr_t device::open(const std::string &path,
                           const std::string &pciinfo) {
  auto container_ptr = container::instance();
  if (!container_ptr) {
    std::cerr << "error getting container\n";
    return nullptr;
  }

  int group_fd = ::open(path.c_str(), O_RDWR);
  if (group_fd < 0) {
    std::cerr << "error opening vfio group: " << path << "\n";
    return nullptr;
  }

  struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
  ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
    std::cerr << "group is not viable\n";
  }

  int container_fd = container_ptr->descriptor();
  if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd)) {
    std::cerr << "error setting group container\n";
    return nullptr;
  }

  if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
    std::cerr << "error setting iommu: " << strerror(errno) << "\n";
    return nullptr;
  }

	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	if (ioctl(container_fd, VFIO_IOMMU_GET_INFO, &iommu_info) < 0) {
    std::cerr << "error getting iommu imfo: " << strerror(errno) << "\n";
		return nullptr;
	}

  int device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, pciinfo.c_str());
  if (device_fd < 0) {
		std::cerr << "error getting device fd: " << strerror(errno) << "\n";
		return nullptr;
	}

  struct vfio_device_info device_info = {.argsz = sizeof(device_info)};
  if (ioctl(device_fd, VFIO_DEVICE_GET_INFO, &device_info)) {
    std::cerr << "error getting device info\n";
    return nullptr;
  }

  // get config space
  struct vfio_region_info cfg_space = {.argsz = sizeof(cfg_space)};
  cfg_space.index = VFIO_PCI_CONFIG_REGION_INDEX;
  if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &cfg_space)) {
    std::cerr << "Error getting config space, aborting\n";
    return nullptr;
  }

  device::ptr_t ptr(new device(container_fd, group_fd, device_fd));
  ptr->cfg_offset_ = cfg_space.offset;

  for (uint32_t i = 0; i < device_info.num_regions; ++i) {
    struct vfio_region_info rinfo = {.argsz = sizeof(rinfo)};
    rinfo.index = i;
    if (!ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &rinfo)) {
      if (rinfo.flags & VFIO_REGION_INFO_FLAG_MMAP) {
        region::ptr_t rptr(0);
        auto sparse_info = vfio_get_sparse_info(device_fd, rinfo);
        if (sparse_info.empty()) {
          rptr = region::map(i, device_fd, rinfo.offset, rinfo.size);
        } else {
          rptr = region::map_sparse(i, device_fd, rinfo.offset, rinfo.size, sparse_info);
        }
        if (rptr) {
          ptr->regions_.push_back(rptr);
        }
      }
    }
  }
  ptr->pci_address_ = pciinfo;
  return ptr;
}

void device::close() {
  for (auto r : regions_) {
    r->close();
  }

  regions_.clear();
  if (group_fd_ > 0 && device_fd_ > 0) {
    // device fds must be released before unsetting the group from container
    ::close(device_fd_);
    if (ioctl(group_fd_, VFIO_GROUP_UNSET_CONTAINER)) {
      std::cerr << "error unsetting group container: " << strerror(errno) << "\n";
    }
    ::close(group_fd_);
    device_fd_ = -1;
    group_fd_ = -1;
  }
}

}  // end of namespace vfio
