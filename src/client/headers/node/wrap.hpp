#pragma once

#include <map>
#include <type_traits>
#include <functional>
#include <memory>

#include <nan.h>
#include <node.h>
#include <v8.h>

namespace mist
{
namespace nodemod
{

extern v8::Isolate* isolate;

template<typename K, typename V>
class PersistentMap
{
public:
  using local_type = v8::Local<V>;
  using persistent_type = CopyablePersistent<V>;

private:
  static_assert(!std::is_reference<K>::value, "Key may not be reference");
  std::map<K, persistent_type> _m;

public:
  bool hasKey(K key)
  {
    //return false;
    return _m.find(key) != _m.end();
  }
  local_type operator[](K key)
  {
    //return local_type();
    return Nan::New<V>(_m[key]);
  }
  void insert(K key, local_type obj)
  {
    _m.insert(std::make_pair(key, persistent_type(obj)));
  }
};

namespace detail
{

template<typename T, typename Enable = void>
struct PointerTraits
{
};

template<typename T>
struct PointerTraits<T,
  typename std::enable_if<std::is_reference<T>::value>::type>
{
  using type = std::add_pointer_t<std::remove_reference_t<T>>;
  static type getPointer(T ptr)
  {
    return &ptr;
  }
};

template<typename T>
struct PointerTraits<T,
  typename std::enable_if<std::is_pointer<T>::value>::type>
{
  using type = T;
  static type getPointer(T ptr)
  {
    return ptr;
  }
};

template<typename T>
struct PointerTraits<std::shared_ptr<T>>
{
  using type = std::add_pointer_t<T>;
  static type getPointer(std::shared_ptr<T> ptr)
  {
    return ptr.get();
  }
};

template<typename T>
struct PointerTraits<std::unique_ptr<T>>
{
  using type = std::add_pointer_t<T>;
  static type getPointer(std::unique_ptr<T> ptr)
  {
    return ptr.get();
  }
};

} // namespace detail

template<typename T, typename Ptr>
class NodeWrap : public Nan::ObjectWrap
{
protected:

  using pointer_type = typename detail::PointerTraits<Ptr>::type;
  using element_type = Ptr;

private:

  static Nan::Persistent<v8::Function> _ctor;
  Ptr _self;

protected:

  static v8::Local<v8::FunctionTemplate>
  defaultTemplate(const char* className)
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(
      [](const Nan::FunctionCallbackInfo<v8::Value>& info) -> void
    {
      info.GetReturnValue().Set(info.This());
      if (!info.IsConstructCall())
        isolate->ThrowException(v8::String::NewFromUtf8(isolate,
          "This class cannot be constructed in this way"));
    });
    tpl->SetClassName(Nan::New(className).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    return tpl;
  }

  //template<typename Args...>
  //v8::Local<v8::Object>
  //static newInstance(FunctionCallbackInfo<v8::Value>& info, Args&& args...)
  //{
  //  T *obj = new T(std::forward<Args>(args)...);
  //  obj->Wrap(info.This());
  //}

  NodeWrap() {}
  NodeWrap(Ptr s) : _self(std::move(s)) {}

  static T* wrapper(v8::Local<v8::Object> obj) {
    return Nan::ObjectWrap::Unwrap<T>(obj);
  }

  void setSelf(Ptr s) { _self = std::move(s); }
  
  static Nan::Persistent<v8::Function> &constructor() { return _ctor; }

  using wrapped_method_type = void(T::*)
    (const Nan::FunctionCallbackInfo<v8::Value>& info);

  template<wrapped_method_type m>
  static void Method(
    const Nan::FunctionCallbackInfo<v8::Value>& info)
  {
    T* obj = ObjectWrap::Unwrap<T>(info.This());
    (obj->*m)(info);
  }

public:

  element_type self() { return _self; }

  static element_type self(v8::Local<v8::Object> obj) {
    return wrapper(obj)->self();
  }

};

template<typename T, typename Ptr>
Nan::Persistent<v8::Function> NodeWrap<T, Ptr>::_ctor;

template<typename T, typename Ptr>
class NodeWrapSingleton : public NodeWrap<T, Ptr>
{
private:

  using NodeWrap<T, Ptr>::pointer_type;
  static_assert(std::is_pointer<pointer_type>::value, "Oops");
  static_assert(!std::is_reference<pointer_type>::value, "Oops");
  static PersistentMap<pointer_type, v8::Object> _objMap;

public:

  v8::Local<v8::Object> object()
  {
    return _objMap[self()];
  }

  static v8::Local<v8::Object> object(Ptr key)
  {
    auto ptrKey = detail::PointerTraits<Ptr>::getPointer(key);
    if (!_objMap.hasKey(ptrKey)) {
      v8::Local<v8::Function> ctor = Nan::New(constructor());
      v8::Local<v8::Object> obj = ctor->NewInstance(0, nullptr);
      T* wrapper = new T(key);
      wrapper->Wrap(obj);
      //T* 
      //v8::Local<v8::Object> obj = ctor->NewInstance(0, nullptr);
      //T* wrapper = Nan::ObjectWrap::Unwrap<T>(obj);
      _objMap.insert(ptrKey, obj);
    }
    return _objMap[ptrKey];
  }

protected:

  NodeWrapSingleton() : NodeWrap() {}
  NodeWrapSingleton(Ptr s) : NodeWrap(std::move(s)) {}

  void setObject(v8::Local<v8::Object> obj)
  {
    _objMap.insert(self(), obj)
  }

};

template<typename T, typename Ptr>
PersistentMap<typename NodeWrapSingleton<T, Ptr>::pointer_type, v8::Object>
NodeWrapSingleton<T, Ptr>::_objMap;

} // namespace nodemod
} // namespace mist
