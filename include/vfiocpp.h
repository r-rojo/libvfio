#include <map>
#include <memory>
#include <vector>

namespace vfio {

class container {
public:
  typedef std::shared_ptr<container> ptr_t;
  container() = delete;
  ~container();

  static ptr_t instance();
  int descriptor() { return fd_; }

private:
  container(int fd);
  static ptr_t instance_;
  int fd_;
};

class system_buffer {
public:
  typedef std::shared_ptr<system_buffer> ptr_t;
  system_buffer() = delete;
  ~system_buffer();
  system_buffer::ptr_t allocate(size_t size);

private:
  system_buffer(void *addr, uint64_t iova, size_t sz);
  void *addr_;
  uint64_t iova_;
  size_t size_;
};

class region {
public:
  typedef std::shared_ptr<region> ptr_t;
  region() = delete;
  uint8_t *ptr();

  static ptr_t map(int fd, uint64_t offset, size_t sz);

  void write32(uint64_t offset, uint32_t value);
  void write64(uint64_t offset, uint64_t value);
  uint32_t read32(uint64_t offset);
  uint64_t read64(uint64_t offset);

private:
  region(uint8_t *ptr, size_t sz) : ptr_(ptr), size_(sz) {}
  uint8_t *ptr_;
  size_t size_;
};

class device {

public:
  typedef std::shared_ptr<device> ptr_t;
  device() = delete;
  ~device();

  static ptr_t open(const std::string &path, const std::string &pciinfo);

  int descriptor() { return device_fd_; }

  size_t num_regions() const { return regions_.size(); }
private:
  device(int container, int group_fd, int device_fd);
  int group_fd_;
  int device_fd_;
  int container_;
  std::vector<region::ptr_t> regions_;
};


} // end of namespace vfio
