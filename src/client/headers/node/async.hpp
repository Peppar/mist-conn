#pragma once

#include <functional>

#include <nan.h>

void asyncCall(std::function<void()> callback);

template<typename T>
using CopyablePersistent
  = Nan::Persistent<T, v8::CopyablePersistentTraits<T>>;
/*
template<typename... Args,
typename std::enable_if<sizeof...(Args) == 0>::type* = nullptr>
void
asyncCallNode(CopyablePersistent<v8::Function> pfunc)
{
asyncCall([pfunc]() mutable
{
v8::HandleScope scope(globalIsolate);
Nan::Callback cb(Nan::New(pfunc));
cb(0, nullptr);
});
}

template<typename... Args,
typename std::enable_if<sizeof...(Args) == 0>::type* = nullptr>
void
asyncCallNode(v8::Local<v8::Function> func)
{
asyncCallNode(CopyablePersistent<v8::Function>(func));
}

template<typename... Args,
typename std::enable_if<sizeof...(Args) != 0>::type* = nullptr>
void
asyncCallNode(CopyablePersistent<v8::Function> pfunc, Args&&... args)
{
// We need to keep a vector of persistent arguments throughout the call
std::vector<CopyablePersistent<v8::Value>> pargs
{ CopyablePersistent<v8::Value>(args)... };
asyncCall(
[pfunc, pargs(std::move(pargs))]() mutable
{
constexpr const std::size_t argCount = sizeof...(Args);

v8::HandleScope scope(globalIsolate);
Nan::Callback cb(Nan::New(pfunc));
std::vector<v8::Local<v8::Value>> arguments(argCount);
std::transform(pargs.begin(), pargs.end(), arguments.begin(),
&Nan::New<v8::Value>);
cb(arguments.size(), arguments.data());
});
}

template<typename... Args,
typename std::enable_if<sizeof...(Args) != 0>::type* = nullptr>
void
asyncCallNode(v8::Local<v8::Function> func, Args&&... args)
{
v8::HandleScope scope(globalIsolate);
asyncCallNode(CopyablePersistent<v8::Function>(func),
std::forward<Args>(args)...);
}*/

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

  template<int ...S>
  static void call(callback_type cb, v8::Local<v8::Function> func,
    packed_args_type args, seq<S...>)
  {
    cb(std::move(func), std::get<S>(args)...);
  }

  template<int ...S>
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

}

template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func,
  std::function<void(v8::Local<v8::Function>, Args...)> cb)
{
  return ::detail::MakeAsyncCallbackHelper<Args...>::make(std::move(func),
    std::move(cb));
}

template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func)
{
  return ::detail::MakeAsyncCallbackHelper<Args...>::makeAuto(std::move(func));
}

/*
template<typename Ret, typename... Args>
setPrototypeMethod(v8::Local<v8::FunctionTemplate> tpl, const char* name,
Ret(*func)(Args...))
{

}
SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
setOnPeerConnectionStatus);
static NAN_METHOD(setOnPeerConnectionStatus)
{
Nan::HandleScope scope;
auto func = v8::Local<v8::Function>::Cast(info[0]);

self(info.Holder()).setOnPeerConnectionStatus(
makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(func));
}
*/
