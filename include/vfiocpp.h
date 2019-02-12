#include <map>
#include <memory>

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

class device {
  typedef std::shared_ptr<device> ptr_t;

 public:
  device() = delete;
  ~device();

  static ptr_t open(const std::string &path, const std::string &pciinfo);

 private:
  device(int container, int group_fd, int device_fd);
  int group_fd_;
  int device_fd_;
  int container_;
};

}  // end of namespace vfio
