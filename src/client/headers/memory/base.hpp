#ifndef __MIST_HEADERS_MEMORY_BASE_HPP__
#define __MIST_HEADERS_MEMORY_BASE_HPP__

#include <memory>

template<typename T>
struct c_deleter
{
  using type = void(*)(T*);
};

/* c_unique_ptr class inheriting from std::unique_ptr, with a default
   destructor */
template<typename T, typename D = typename c_deleter<T>::type>
class c_unique_ptr : public std::unique_ptr<T, D>
{
public:
  c_unique_ptr() : std::unique_ptr<T, D>(nullptr, c_deleter<T>::del) {}
  c_unique_ptr(T *ptr) : std::unique_ptr<T, D>(ptr, c_deleter<T>::del) {}
  c_unique_ptr(T *ptr, D deleter) : std::unique_ptr<T, D>(ptr, deleter) {}
  using std::unique_ptr<T, D>::operator=;
};

/* c_shared_ptr class inheriting from std::shared_ptr, with a default
   destructor */
template<typename T, typename D = typename c_deleter<T>::type>
class c_shared_ptr : public std::shared_ptr<T>
{
public:
  c_shared_ptr() : std::shared_ptr<T>(nullptr, c_deleter<T>::del) {}
  c_shared_ptr(T *ptr) : std::shared_ptr<T>(ptr, c_deleter<T>::del) {}
  c_shared_ptr(T *ptr, D deleter) : std::shared_ptr<T>(ptr, deleter) {}
  using std::shared_ptr<T>::operator=;
};

/* Creates a c_unique_ptr from the given pointer */
template<typename T>
c_unique_ptr<T, typename c_deleter<T>::type> to_unique(T* ptr = nullptr) {
  return c_unique_ptr<T, typename c_deleter<T>::type>(ptr, c_deleter<T>::del);
}

/* Creates a c_unique_ptr from the given pointer and deleter */
template<typename T, typename D>
c_unique_ptr<T, D> to_unique(T* ptr, D deleter) {
  return c_unique_ptr<T, D>(ptr, deleter);
}

/* Creates a c_shared_ptr from the given pointer */
template<typename T>
c_shared_ptr<T> to_shared(T* ptr) {
  return std::shared_ptr<T>(ptr, c_deleter<T>::del);
}

/* Creates a c_shared_ptr from the given pointer and deleter */
template<typename T, typename D>
c_shared_ptr<T> to_shared(T* ptr, D deleter) {
  return c_shared_ptr<T>(ptr, deleter);
}

#endif
