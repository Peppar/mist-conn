#pragma once

#include <cstddef>
#include <string>
#include <type_traits>

#include <nan.h>

namespace mist
{
namespace nodemod
{

extern v8::Isolate* isolate;

namespace detail
{

template<typename T, typename Enable = void>
struct NodeValueConverter
{
  static v8::Local<v8::Value> conv(T v)
  {
    static_assert(false, "No converter for this type");
    return v8::Local<v8::Value>();
  }
};

template<typename T, typename Enable = void>
struct NodeValueDecayHelper;

template<typename T>
struct NodeValueDecayHelper<T,
  typename std::enable_if<std::is_reference<T>::value>::type>
{
  using type = typename std::add_pointer<
    typename std::add_const<typename std::decay_t<T>>::type>::type;

  static type decay(T value) { return &value; }
};

template<typename T>
struct NodeValueDecayHelper<T,
  typename std::enable_if<!std::is_reference<T>::value>::type>
{
  using type = typename std::add_const<typename std::decay_t<T>>::type;

  static type decay(T value) { return value; }
};

template<typename T>
using node_decay_t = typename NodeValueDecayHelper<T>::type;

template<typename T>
node_decay_t<T> nodeDecay(T value)
{
  return NodeValueDecayHelper<T>::decay(value);
}

template<>
struct NodeValueConverter<const std::string*>
{
  static v8::Local<v8::Value> conv(const std::string* v)
  {
    return Nan::New(*v).ToLocalChecked();
  }
};

template<>
struct NodeValueConverter<const std::string>
{
  static v8::Local<v8::Value> conv(const std::string& v)
  {
    return Nan::New(v).ToLocalChecked();
  }
  static std::string convBack(v8::Local<v8::Value> v)
  {
    v8::Local<v8::String> str(Nan::To<v8::String>(v).ToLocalChecked());
    return std::string(*v8::String::Utf8Value(str));
  }
};

template<>
struct NodeValueConverter<const char* const>
{
  static v8::Local<v8::Value> conv(const char* const v)
  {
    return Nan::New(v).ToLocalChecked();
  }
};

template<typename T>
struct NodeValueConverter<T,
  typename std::enable_if<std::is_integral<T>::value>::type>
{
  static v8::Local<v8::Value> conv(T v)
  {
    return Nan::New(v);
  }
  static T convBack(v8::Local<v8::Value> v)
  {
    return v->IntegerValue();
  }
};

template<typename T>
struct NodeValueConverter<T,
  typename std::enable_if<std::is_floating_point<T>::value>::type>
{
  static v8::Local<v8::Value> conv(T v)
  {
    return Nan::New(v);
  }
  static T convBack(v8::Local<v8::Value> v)
  {
    return v->NumberValue();
  }
};

} // namespace detail

template<typename T>
v8::Local<v8::Value> conv(T v)
{
  return detail::NodeValueConverter<detail::node_decay_t<T>>::conv(
    detail::nodeDecay<T>(v));
}

template<typename T>
T convBack(v8::Local<v8::Value> v)
{
  return detail::NodeValueConverter<detail::node_decay_t<T>>::convBack(v);
}

} // namespace nodemod
} // namespace mist
