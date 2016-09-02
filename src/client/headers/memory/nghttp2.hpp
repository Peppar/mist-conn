#ifndef __MEMORY_NGHTTP2_HPP__
#define __MEMORY_NGHTTP2_HPP__

#include "memory/base.hpp"

#include <nghttp2/nghttp2.h>

template<>
struct c_deleter<nghttp2_session>
{
  using type = void(*)(nghttp2_session*);
  static void del(nghttp2_session *ptr)
  {
    nghttp2_session_del(ptr);
  }
};

template<>
struct c_deleter<nghttp2_session_callbacks>
{
  using type = void(*)(nghttp2_session_callbacks*);
  static void del(nghttp2_session_callbacks *ptr)
  {
    nghttp2_session_callbacks_del(ptr);
  }
};

template<>
struct c_deleter<nghttp2_option>
{
  using type = void(*)(nghttp2_option*);
  static void del(nghttp2_option *ptr)
  {
    nghttp2_option_del(ptr);
  }
};

#endif
