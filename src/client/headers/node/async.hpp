#pragma once

#include <functional>

#include <nan.h>

void asyncCall(std::function<void()> callback);

template<typename T>
using CopyablePersistent
  = Nan::Persistent<T, v8::CopyablePersistentTraits<T>>;

namespace detail
{

template<int...>
struct seq {};

template<int N, int... S>
struct gens : gens<N - 1, N - 1, S...> {};

template<int... S>
struct gens<0, S...> {
  typedef seq<S...> type;
};

template<typename... Args>
struct MakeAsyncCallbackHelper
{
  using packed_args_type = std::tuple<Args...>;
  using callback_type = std::function<void(v8::Local<v8::Function>, Args...)>;

  template<int... S>
  static void call(callback_type cb, v8::Local<v8::Function> func,
    packed_args_type args, seq<S...>)
  {
    cb(std::move(func), std::get<S>(args)...);
  }

  template<int... S>
  static void callNode(v8::Local<v8::Function> func,
    packed_args_type args, seq<S...>)
  {
    Nan::Callback cb(func);
    std::array<v8::Local<v8::Value>, sizeof...(Args)> nodeArgs{
      conv<std::tuple_element<S, packed_args_type>::type>(
        std::get<S>(args))...
    };
    cb(nodeArgs.size(), nodeArgs.data());
  }

  static std::function<void(Args...)> make(v8::Local<v8::Function> func,
    callback_type cb)
  {
    Nan::HandleScope scope;
    auto pfunc(std::make_shared<Nan::Persistent<v8::Function>>(func));
    return
      [pfunc, cb(std::move(cb))]
    (Args&&... args)
    {
      packed_args_type packed{ std::forward<Args>(args)... };
      asyncCall(
        [cb, pfunc, packed(std::move(packed))]() mutable
      {
        Nan::HandleScope scope;
        call(std::move(cb), Nan::New(*pfunc), std::move(packed),
          typename gens<sizeof...(Args)>::type());
      });
    };
  }

  static std::function<void(Args...)> makeAuto(v8::Local<v8::Function> func)
  {
    Nan::HandleScope scope;
    auto pfunc(std::make_shared<Nan::Persistent<v8::Function>>(func));
    return
      [pfunc](Args&&... args)
    {
      packed_args_type packed{ std::forward<Args>(args)... };
      asyncCall(
        [pfunc, packed(std::move(packed))]() mutable
      {
        Nan::HandleScope scope;
        callNode(Nan::New(*pfunc), std::move(packed),
          typename gens<sizeof...(Args)>::type());
      });
    };
  }
};

} // namespace detail

template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func,
  std::function<void(v8::Local<v8::Function>, Args...)> cb)
{
  return detail::MakeAsyncCallbackHelper<Args...>::make(std::move(func),
    std::move(cb));
}

template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func)
{
  return detail::MakeAsyncCallbackHelper<Args...>::makeAuto(std::move(func));
}
