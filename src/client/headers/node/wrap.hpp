#pragma once

#include <map>
#include <type_traits>
#include <functional>
#include <memory>

#include <nan.h>

template<typename K, typename V>
class PersistentMap
{
public:
  using local_type = v8::Local<V>;
  using persistent_type = CopyablePersistent<V>;

private:
  std::map<K, persistent_type> _objMap;

public:
  bool hasKey(K key)
  {
    return _objMap.find(key) != _objMap.end();
  }
  local_type operator[](K key)
  {
    return Nan::New<V>(_objMap[key]);
  }
  void insert(K key, local_type obj)
  {
    _objMap.insert(std::make_pair(key, persistent_type(obj)));
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
  typename std::enable_if<std::is_pointer<T>::value>::type>
{
  using type = T;
  static T getPointer(T ptr)
  {
    return ptr;
  }
};

template<typename T>
struct PointerTraits<std::shared_ptr<T>>
{
  using type = T*;
  static T* getPointer(std::shared_ptr<T> ptr)
  {
    return ptr.get();
  }
};

template<typename T>
struct PointerTraits<std::unique_ptr<T>>
{
  using type = T*;
  static T* getPointer(std::unique_ptr<T> ptr)
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

  NodeWrap() {}
  NodeWrap(Ptr s) : _self(std::move(s)) {}

  static T* wrapper(v8::Local<v8::Object> obj) {
    return Nan::ObjectWrap::Unwrap<T>(obj);
  }

  void setSelf(Ptr s) { _self = std::move(s); }

  static Nan::Persistent<v8::Function> &constructor() { return _ctor; }

  using wrapped_method_type = void(T::*)
    (const Nan::FunctionCallbackInfo<v8::Value>& args);

  template<wrapped_method_type m>
  static void Method(
    const Nan::FunctionCallbackInfo<v8::Value>& args)
  {
    T* obj = ObjectWrap::Unwrap<T>(args.This());
    (obj->*m)(args);
  }

public:

  element_type self() { assert(_self); return _self; }

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

  static PersistentMap<element_type, v8::Object> _objMap;

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
      T* wrapper = Nan::ObjectWrap::Unwrap<T>(obj);
      wrapper->setSelf(std::move(key));
      _objMap.insert(ptrKey, obj);
    }
    return _objMap[ptrKey];
  }

protected:

  void setObject(v8::Local<v8::Object> obj)
  {
    _objMap.insert(self(), obj)
  }

};

template<typename T, typename Ptr>
PersistentMap<typename NodeWrapSingleton<T, Ptr>::element_type, v8::Object>
NodeWrapSingleton<T, Ptr>::_objMap;
