#ifndef __MEMORY_BASE_H__
#define __MEMORY_BASE_H__

#include <memory>

template<typename T>
struct c_deleter
{
  using type = void(*)(T*);
};

/* Creates a unique_ptr from the given pointer */
template<typename T>
std::unique_ptr<T, typename c_deleter<T>::type> to_unique(T* ptr = nullptr) {
  return std::unique_ptr<T, typename c_deleter<T>::type>(ptr, c_deleter<T>::del);
}

/* Creates a unique_ptr from the given pointer and deleter */
template<typename T, typename D>
std::unique_ptr<T, D> to_unique(T* ptr, D deleter) {
  return std::unique_ptr<T, D>(ptr, deleter);
}

/* unique_ptr type with automatically deduced deleter type */
template<typename T, typename D = typename c_deleter<T>::type>
using c_unique_ptr = std::unique_ptr<T, D>;

/* Creates a shared_ptr from the given pointer */
template<typename T>
std::shared_ptr<T> to_shared(T* ptr) {
  return std::shared_ptr<T>(ptr, c_deleter<T>::del);
}

/* Creates a shared_ptr from the given pointer and deleter */
template<typename T, typename D>
std::shared_ptr<T> to_shared(T* ptr, D deleter) {
  return std::shared_ptr<T>(ptr, deleter);
}

/* Type alias for consistency */
template<typename T>
using c_shared_ptr = std::shared_ptr<T>;

#endif
