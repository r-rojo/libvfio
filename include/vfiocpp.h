#include <map>
#include <memory>
#include <vector>
#include <sstream>

namespace {
static inline void assert_config_op(uint64_t offset,
                                    ssize_t expected,
                                    ssize_t actual,
                                    const char *op)
{
  if (actual != expected) {
    std::stringstream ss;
    ss << "error: [pci_config:" << op << " @0x" << std::hex << offset
       << " expected " << std::dec << expected
       << ", processed " << actual << "\n";
    throw std::length_error(ss.str().c_str());
  }
}

}

namespace vfio {

class container {
 public:
  typedef std::shared_ptr<container> ptr_t;
  container() = delete;
  ~container();

  static ptr_t instance();
  int descriptor() { return fd_; }
  bool reserve(uint64_t &size, uint64_t &iova);
  bool unreserve(uint64_t iova);

 private:
  struct iova_range_t
  {
    iova_range_t(uint64_t s, uint64_t e):
      start(s), end(e), next(s){}
    uint64_t start;
    uint64_t end;
    uint64_t next;
  };

  container(int fd);
  void discover_info();
  static ptr_t instance_;
  int fd_;
  std::vector<iova_range_t> iova_ranges_;

};

class system_buffer : public std::enable_shared_from_this<system_buffer> {
 public:
  typedef std::shared_ptr<system_buffer> ptr_t;
  system_buffer() = delete;
  ~system_buffer();
  static system_buffer::ptr_t allocate(size_t size);
  size_t size() { return size_; }
  void *address() { return addr_; }
  uint64_t io_address() { return iova_; }

  template<typename T>
  T get(uint64_t offset)
  {
    return *(reinterpret_cast<T*>(addr_ + offset));
  }

  uint64_t get_uint64(uint64_t offset) { return *(reinterpret_cast<uint64_t*>(addr_) + offset/sizeof(uint64_t)); }
  void set_uint64(uint64_t offset, uint64_t value) {
    *(reinterpret_cast<uint64_t*>(addr_) + offset/sizeof(uint64_t)) = value;
  }

  system_buffer::ptr_t carve(size_t size);

  template<typename T>
  void fill(T value)
  {
    for (T *ptr = reinterpret_cast<T*>(addr_);
         ptr < reinterpret_cast<T*>(addr_ + size_); ++ptr)
      *ptr = value;

  }

  size_t compare(ptr_t other)
  {
    for(size_t i = 0; i < std::min(size_, other->size_); ++i)
      if (*(addr_+i) != *(other->addr_+i))
        return i;
    return size_;
  }

 private:
  system_buffer(uint8_t *addr, uint64_t iova, size_t sz);
  uint8_t *addr_;
  uint64_t iova_;
  size_t size_;
  ptr_t parent_;
  size_t next_;
};

class region {
 public:
  struct sparse_info_t
  {
    uint32_t index;
    uint32_t offset;
    uint32_t size;
  };
  typedef std::vector<sparse_info_t> sparse_info_list;

  typedef std::shared_ptr<region> ptr_t;
  ~region();
  region() = delete;
  uint8_t *ptr() { return ptr_; }

  static ptr_t map(uint32_t index, int fd, uint64_t offset, size_t sz);
  static ptr_t map_sparse(uint32_t index, int fd, uint64_t offset, size_t sz, const sparse_info_list &list);

  uint32_t index() { return index_; }
  void write32(uint64_t offset, uint32_t value);
  void write64(uint64_t offset, uint64_t value);
  uint32_t read32(uint64_t offset);
  uint64_t read64(uint64_t offset);
  size_t size() { return size_; }
  void close();

 private:
  region(uint32_t index, uint8_t *ptr, size_t sz) : index_(index), ptr_(ptr), size_(sz) {}
  region(uint32_t index, uint8_t *ptr, size_t sz, const sparse_info_list &info) : index_(index), ptr_(ptr), size_(sz), sparse_(info) {}
  uint32_t index_;
  uint8_t *ptr_;
  size_t size_;
  sparse_info_list sparse_;
};

class device {
 public:
  typedef std::shared_ptr<device> ptr_t;
  device() = delete;
  ~device();

  static ptr_t open(const std::string &path, const std::string &pciinfo);
  static ptr_t open_pciaddress(const std::string &pciinfo);
  void close();

  std::string pci_address() {
    return pci_address_;
  }

  int descriptor() { return device_fd_; }

  const std::vector<region::ptr_t> &regions() const { return regions_; }
  size_t num_regions() const { return regions_.size(); }
  template<typename T>
  T config_read(uint64_t offset)
  {
    T value(0);
    auto num_bytes = pread(device_fd_, &value, sizeof(T), cfg_offset_ + offset);
    assert_config_op(offset, sizeof(T), num_bytes, "read");
    return value;

  }

  template<typename T>
  void config_write(uint64_t offset, T value)
  {
    auto num_bytes = pwrite(device_fd_, &value, sizeof(T), cfg_offset_ + offset);
    assert_config_op(offset, sizeof(T), num_bytes, "write");
  }

 private:
  device(int container, int group_fd, int device_fd);
  bool setup(uint64_t cfg_offset);
  void restore();
  std::string pci_address_;
  int group_fd_;
  int device_fd_;
  int container_;
  std::vector<region::ptr_t> regions_;
  uint64_t cfg_offset_;
  uint16_t command_;
};

}  // end of namespace vfio
