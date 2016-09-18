// #ifdef _BUILD_NODE_MODULE

#include <string>
#include <type_traits>
#include <iostream>

#include <prio.h>

//#include <node.h>
//#include <v8.h>
#include <nan.h>

#include <boost/asio/ip/address.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "conn.hpp"
#include "io/io_context.hpp"
#include "io/ssl_context.hpp"
#include "conn.hpp"

namespace
{

v8::Isolate* globalIsolate;

void parseIPAddress(PRNetAddr* addr, const std::string& str,
  std::uint16_t port, boost::system::error_code ec)
{
  ec.clear();
  auto address(boost::asio::ip::address::address::from_string(str, ec));
  if (ec)
    return;
  if (address.is_v4()) {
    auto v4(address.to_v4());
    auto bytes = v4.to_bytes();
    addr->inet.family = AF_INET;
    std::copy(bytes.begin(), bytes.end(),
      reinterpret_cast<unsigned char*>(&addr->inet.ip));
    addr->inet.port = PR_htons(port);
  } else {
    auto v6(address.to_v6());
    auto bytes = v6.to_bytes();
    addr->inet.family = AF_INET6;
    std::copy(bytes.begin(), bytes.end(),
      reinterpret_cast<unsigned char*>(&addr->ipv6.ip));
    addr->ipv6.port = PR_htons(port);
  }
}

mist::io::IOContext ioCtx;
std::unique_ptr<mist::io::SSLContext> sslCtx;
std::unique_ptr<mist::ConnectContext> connCtx;

template<typename T,
  typename std::enable_if<
    std::is_same<std::remove_cv<T>, std::string>::value>::type* = nullptr>
T
fromV8(v8::Handle<v8::Value> v)
{
  v8::String::Utf8Value str(v);
  return std::string(*str, str.length());
}

template<typename T,
  typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
T
fromV8(v8::Handle<v8::Value> v)
{
  return static_cast<T>(v->IntegerValue());
}

template<typename T,
  typename std::enable_if<
    std::is_same<std::remove_cv<T>, std::string>::value>::type* = nullptr>
v8::Local<v8::Value>
toNode(T v)
{
  return Nan::New(v);
}

template<typename T,
  typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
v8::Local<v8::Value>
toNode(T v)
{
  return Nan::New(v);
}

struct AsyncCall
{
  uv_async_t handle;
  std::function<void()> callback;

  AsyncCall(std::function<void()> callback)
    : callback(std::move(callback))
  {
    handle.data = this;
  };
  
  static void operator delete(void *p)
  {
    /* TODO: This custom operator delete is either really cool or really awful.
    Find out which one it is */
    AsyncCall *ac = static_cast<AsyncCall*>(p);
    
    /* libuv requires that uv_close be called before freeing handle memory */
    uv_close(reinterpret_cast<uv_handle_t*>(&ac->handle),
      [](uv_handle_t *handle)
    {
      /* Avoid calling destructor here; it was called for the first delete */
      ::operator delete(static_cast<AsyncCall*>(handle->data));
    });
  }
};

void
asyncCall(std::function<void()> callback)
{
  AsyncCall *ac = new AsyncCall(std::move(callback));
  uv_async_init(uv_default_loop(), &ac->handle,
    [](uv_async_t *handle)
  {
    std::unique_ptr<AsyncCall> ac(static_cast<AsyncCall*>(handle->data));
    ac->callback();
  });
  uv_async_send(&ac->handle);
}

template<typename T>
using CopyablePersistent
  = Nan::Persistent<T, v8::CopyablePersistentTraits<T>>;

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
/*
template<typename... Args>
struct callbackPack
{
  CopyablePersistent<v8::Function> callback;
  std::array<CopyablePersistent<v8::Value>, sizeof...Args> args;

  callbackPack(v8::Handle<v8::Function> callback, Args&&... args)
    : callback(CopyablePersistent<v8::Function>(callback))
    , args{ CopyablePersistent<v8::Value>(args)... }
  {
  }
};
*/

//template<typename... Args,
//  typename std::enable_if<sizeof...(Args) != 0>::type* = nullptr>
//  void
//  asyncCallNode(v8::Local<v8::Function> func, Args&&... args)
//{
//  //constexpr const std::size_t argCount = sizeof...(Args);
//
//  /* We need to keep a vector of persistent arguments throughout the call */
//  std::vector<CopyablePersistent<v8::Value>> pargs
//  { CopyablePersistent<v8::Value>(args)... };
//  asyncCall(
//    [pfunc(CopyablePersistent<v8::Function>(func)),
//    pargs(std::move(pargs))]() mutable
//  {
//    constexpr const std::size_t argCount = sizeof...(Args);
//
//    v8::Isolate *isolate = v8::Isolate::GetCurrent();
//    v8::HandleScope handle_scope(isolate);
//
//    //auto cb(Nan::Callback(Nan::New(pfunc)));
//    std::vector<v8::Local<v8::Value>> arguments(argCount);
//    std::transform(pargs.begin(), pargs.end(), arguments.begin(),
//      &Nan::New<v8::Local<v8::Object>>);
//    //cb(argCount, arguments.data());
//  });
//}

template<typename... Args,
  typename std::enable_if<sizeof...(Args) != 0>::type* = nullptr>
void
asyncCallNode(CopyablePersistent<v8::Function> pfunc, Args&&... args)
{
  /* We need to keep a vector of persistent arguments throughout the call */
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
}

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
    cb(std::move(func), std::get<S>(args) ...);
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
};

template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func,
  std::function<void(v8::Local<v8::Function>, Args...)> cb)
{
  return MakeAsyncCallbackHelper<Args...>::make(std::move(func),
    std::move(cb));
}

//template<int ...S>
//void callFunc(std::tuple<packedArgs>seq<S...>) {
//  func(std::get<S>(params) ...);
//}

/*template<typename... Args>
std::function<void(Args...)>
makeAsyncCallback(v8::Local<v8::Function> func,
  std::function<v8::Local<v8::Function>, void(Args...)>)
{
  //  asyncCallNode(pfunc, Nan::New<v8::String>(onionAddress).ToLocalChecked());
  v8::HandleScope scope(globalIsolate);
  return
    [pfunc(CopyablePersistent<v8::Function>(func))]
    (Args&&... args) -> void
    {
      std::tuple<Args...> packedArgs{ std::forward<Args>(args)... };
      //v8::HandleScope scope(globalIsolate);
      asyncCall([pfunc, packedArgs]()
      {
        Nan::Callback cb(Nan::New(pfunc));
        //std::vector<v8::Handle<v8::Value>> nodeArgs(sizeof...(Args));
        //std::transform(packgedArgs.begin(), packedArgs.end(), )
        asyncCallNode(Nan::New(pfunc), toNode<Args>(args)...);
      });
    };
}*/

} // namespace

class Quorve : public Nan::ObjectWrap
{
private:

  double value_;

  static inline Nan::Persistent<v8::Function> &constructor()
  {
    static Nan::Persistent<v8::Function> my_constructor;
    return my_constructor;
  }

  explicit Quorve(double value = 0) : value_(value) {}
  ~Quorve() {}

public:
 
  static const char *ClassName() { return "MyObject"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    SetPrototypeMethod(tpl, "getHandle", GetHandle);
    SetPrototypeMethod(tpl, "callMe", CallMe);
    SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

private:
 
  static NAN_METHOD(New)
  {
    if (info.IsConstructCall()) {
      double value = info[0]->IsUndefined() ? 0 : Nan::To<double>(info[0]).FromJust();
      Quorve *obj = new Quorve(value);
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    } else {
      const int argc = 1;
      v8::Local<v8::Value> argv[argc] = {info[0]};
      v8::Local<v8::Function> cons = Nan::New(constructor());
      info.GetReturnValue().Set(cons->NewInstance(argc, argv));
    }
  }

  static NAN_METHOD(GetHandle)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(CallMe)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    auto callback = v8::Local<v8::Function>::Cast(info[0]);
    asyncCallNode(callback);
    //info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(GetValue)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }
};

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

class PeerSingleton
{
private:

  friend class Peer;

  Nan::Persistent<v8::Function> _ctor;
  PersistentMap<mist::Peer*, v8::Object> _objMap;

} _peerSingleton;

class Peer : public Nan::ObjectWrap
{
private:

  mist::Peer* _self;

  Peer() {}
  ~Peer() {}

public:

  mist::Peer* self() { return _self; }

  static const char *ClassName() { return "Peer"; }

  static v8::Local<v8::Object> FromPtr(mist::Peer* peer)
  {
    if (!_peerSingleton._objMap.hasKey(peer)) {
      v8::Local<v8::Function> ctor = Nan::New(_peerSingleton._ctor);
      v8::Local<v8::Object> obj = ctor->NewInstance(0, nullptr);
      Peer* self = Nan::ObjectWrap::Unwrap<Peer>(obj);
      self->_self = peer;
      _peerSingleton._objMap.insert(peer, obj);
    }
    return _peerSingleton._objMap[peer];
  }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    //SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
    //  setOnPeerConnectionStatus);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    _peerSingleton._ctor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

private:

  static NAN_METHOD(New)
  {
    if (info.IsConstructCall()) {
      Peer *obj = new Peer();
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    } else {
      /* TODO: Throw */
      const int argc = 1;
      v8::Local<v8::Value> argv[argc] = { info[0] };
      v8::Local<v8::Function> ctor = Nan::New(_peerSingleton._ctor);
      info.GetReturnValue().Set(ctor->NewInstance(argc, argv));
    }
  }
};

class ServiceSingleton
{
private:

  friend class Service;

  Nan::Persistent<v8::Function> _ctor;

} _serviceSingleton;

class Service : public Nan::ObjectWrap
{
private:

  std::shared_ptr<mist::Service> _self;

  Service(std::shared_ptr<mist::Service> self) : _self(self) {}

public:

  static const char *ClassName() { return "Service"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
      setOnPeerConnectionStatus);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    _serviceSingleton._ctor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

private:

  static NAN_METHOD(New)
  {
    if (info.IsConstructCall()) {
      std::string name(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
      Service *obj = new Service(connCtx->newService(name));
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    } else {
      const int argc = 1;
      v8::Local<v8::Value> argv[argc] = { info[0] };
      v8::Local<v8::Function> ctor = Nan::New(_serviceSingleton._ctor);
      info.GetReturnValue().Set(ctor->NewInstance(argc, argv));
    }
  }
  /*
  void setOnPeerConnectionStatus(peer_connection_status_callback cb);

  void setOnPeerRequest(peer_request_callback cb);

  void submit(Peer &peer, std::string method, std::string path,
    peer_submit_callback cb);

  void setOnWebSocket(peer_websocket_callback cb);

  void openWebSocket(Peer& peer, std::string path,
    peer_websocket_callback cb);*/

  static NAN_METHOD(setOnPeerConnectionStatus)
  {
    Nan::HandleScope scope;
    mist::Service& self = *(Nan::ObjectWrap::Unwrap<Service>(info.Holder())->_self);

    auto func = v8::Local<v8::Function>::Cast(info[0]);
    self.setOnPeerConnectionStatus(
      makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(
        func, [](v8::Local<v8::Function> func, mist::Peer& peer,
          mist::Peer::ConnectionStatus status) -> void
      {
        Nan::HandleScope scope;
        Nan::Callback cb(func);
        std::vector<v8::Local<v8::Value>> parameters {
          Peer::FromPtr(&peer), Nan::New(static_cast<int>(status))
        };
        cb(parameters.size(), parameters.data());
      }));

    /*std::function<void(v8::Local<v8::Function>,
       int, int)> fn = [](v8::Local<v8::Function> f, int a, int b) -> void
    {
    };
    self.setOnPeerConnectionStatus(
      makeAsyncCallback<int, int>(
        func, fn));*/
/*      [pfunc(CopyablePersistent<v8::Function>(func))]
      (mist::Peer& peer, mist::Peer::ConnectionStatus status)
    {
      // TODO: Some kind of lock here..?
      v8::HandleScope scope(globalIsolate);
      asyncCallNode(pfunc, Peer::FromPtr(&peer),
      Nan::New(static_cast<int>(status)));
    });*/
  }

  /*
  static NAN_METHOD(setOnPeerRequest)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    auto callback = v8::Local<v8::Function>::Cast(info[0]);
    asyncCallNode(callback);
    //info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(submit)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }
  static NAN_METHOD(setOnWebSocket)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }
  static NAN_METHOD(openWebSocket)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }*/
};


//class enable_object_from_this : public Nan::ObjectWrap
//{
//private:
//  static 
//
//public:
//  
//
//protected:
//  
//  wrapObject
//  static NAN_METHOD(New)
//  {
//    if (info.IsConstructCall()) {
//      std::string name(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
//      Service *obj = new Service(connCtx->newService(name));
//      obj->Wrap(info.This());
//      info.GetReturnValue().Set(info.This());
//    } else {
//      const int argc = 1;
//      v8::Local<v8::Value> argv[argc] = { info[0] };
//      v8::Local<v8::Function> cons = Nan::New(constructor());
//      info.GetReturnValue().Set(cons->NewInstance(argc, argv));
//    }
//  }
//  toWrapper();
//};



/*
class Quorve
{
private:
  std::string _hej;
  
public:
  Quorve(std::string hej) : _hej(hej) {}
  ~Quorve() { std::cerr << "Hej " << _hej << std::endl; }
  
};*/
NAN_METHOD(initializeNSS)
{
  Nan::HandleScope scope;

  std::string dbDir(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
  //std::string nickname(*v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked()));

  sslCtx = std::make_unique<mist::io::SSLContext>(ioCtx, dbDir);
  connCtx = std::make_unique<mist::ConnectContext>(*sslCtx);

  /* Start the IO event loop in a separate thread */
  ioCtx.queueJob([]() { ioCtx.exec(); });

  //auto rv = Nan::New("world").ToLocalChecked();
  //info.GetReturnValue().Set(rv);
}

//Peer& addPeer(const std::string& derPublicKey, const std::string& nickname);

NAN_METHOD(loadPKCS12)
{
  Nan::HandleScope scope;

  std::string data(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
  std::string password(*v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked()));

  sslCtx->loadPKCS12(data, password);
}

NAN_METHOD(loadPKCS12File)
{
  Nan::HandleScope scope;

  std::string filename(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
  std::string password(*v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked()));

  sslCtx->loadPKCS12File(filename, password);
}

NAN_METHOD(serveDirect)
{
  Nan::HandleScope scope;

  std::uint16_t incomingPort(info[0]->IntegerValue());

  connCtx->serveDirect(incomingPort);
}

NAN_METHOD(startServeTor)
{
  Nan::HandleScope scope;

  try {
    std::uint16_t torIncomingPort(info[0]->IntegerValue());
    std::uint16_t torOutgoingPort(info[1]->IntegerValue());
    std::uint16_t controlPort(info[2]->IntegerValue());
    std::string executableName(*v8::String::Utf8Value(Nan::To<v8::String>(info[3]).ToLocalChecked()));
    std::string workingDir(*v8::String::Utf8Value(Nan::To<v8::String>(info[4]).ToLocalChecked()));
    std::cerr
      << torIncomingPort
      << " " << torOutgoingPort
      << " " << controlPort
      << " " << executableName
      << " " << workingDir << std::endl;
    connCtx->startServeTor(torIncomingPort, torOutgoingPort, controlPort, executableName, workingDir);
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }

  //auto rv = Nan::New("world").ToLocalChecked();
  //info.GetReturnValue().Set(rv);
}

NAN_METHOD(connectPeerDirect)
{
  Nan::HandleScope scope;

  v8::Local<v8::Object> obj(v8::Local<v8::Object>::Cast(info[0]));

  mist::Peer& peer = *Nan::ObjectWrap::Unwrap<Peer>(obj)->self();

  PRNetAddr addr;
  {
    boost::system::error_code ec;
    std::string addrStr(*v8::String::Utf8Value(
      Nan::To<v8::String>(info[1]).ToLocalChecked()));
    std::uint16_t port(info[2]->IntegerValue());
    parseIPAddress(&addr, addrStr, port, ec);
    if (ec)
      BOOST_THROW_EXCEPTION(boost::system::system_error(ec,
        "Unable to parse IP address"));
  }

  connCtx->connectPeerDirect(peer, &addr);
}

NAN_METHOD(connectPeerTor)
{
  Nan::HandleScope scope;

  auto obj(v8::Local<v8::Object>::Cast(info[0]));
  mist::Peer& peer = *Nan::ObjectWrap::Unwrap<Peer>(obj)->self();

  connCtx->connectPeerTor(peer);
}

NAN_METHOD(addPeer)
{
  Nan::HandleScope scope;
  // Peer&(const std::string& derPublicKey, const std::string& nickname);
  std::string derPublicKey(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
  std::string nickname(*v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked()));
  mist::Peer& peer = connCtx->addPeer(derPublicKey, nickname);
  v8::Local<v8::Object> nodePeer = Peer::FromPtr(&peer);
  info.GetReturnValue().Set(nodePeer);
}

NAN_METHOD(onionAddress)
{
  Nan::HandleScope scope;

  try {
    auto func = v8::Local<v8::Function>::Cast(info[0]);
    connCtx->onionAddress(
      [pfunc(CopyablePersistent<v8::Function>(func))]
      (const std::string& onionAddress)
    {
      Nan::HandleScope scope;
      asyncCallNode(pfunc, Nan::New<v8::String>(onionAddress).ToLocalChecked());
    });
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}
/*
void
makeQuorve(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  //v8::Local<v8::External> request_ptr = External::New(GetIsolate(), request);
  // Store the request pointer in the JavaScript wrapper.
  //result->SetInternalField(0, request_ptr);
  
  v8::HandleScope handle_scope(isolate);
  //v8::Local<v8::Object> object = v8::Object::New(isolate);
  //Nan::Persistent<v8::Object> persistent(object);
  
  Quorve &quorve = make_node<Quorve>(isolate, "Quorve");

  args.GetReturnValue().Set(quorve.to_local(isolate));
}*/
/*
void
test(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::HandleScope handle_scope(isolate);
  AsyncCall::call(v8::Local<v8::Function>::Cast(args[0]),
    toV8<std::string>("Hejsan", isolate));
}*/

/*
void
hej(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::HandleScope scope(isolate);
  auto rv = v8::String::NewFromUtf8(isolate, "world");
  args.GetReturnValue().Set(rv);
}
*/

NAN_MODULE_INIT(Init)
{
  globalIsolate = v8::Isolate::GetCurrent();

  Nan::Set(target, Nan::New(Service::ClassName()).ToLocalChecked(),
    Nan::GetFunction(Service::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(Peer::ClassName()).ToLocalChecked(),
    Nan::GetFunction(Peer::Init()).ToLocalChecked());

  Nan::Set(target, Nan::New("initializeNSS").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(initializeNSS)).ToLocalChecked());
  Nan::Set(target, Nan::New("loadPKCS12").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(loadPKCS12)).ToLocalChecked());
  Nan::Set(target, Nan::New("loadPKCS12File").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(loadPKCS12File)).ToLocalChecked());
  Nan::Set(target, Nan::New("serveDirect").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(serveDirect)).ToLocalChecked());
  Nan::Set(target, Nan::New("startServeTor").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(startServeTor)).ToLocalChecked());
  Nan::Set(target, Nan::New("onionAddress").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(onionAddress)).ToLocalChecked());

  Nan::Set(target, Nan::New("addPeer").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(addPeer)).ToLocalChecked());
  Nan::Set(target, Nan::New("connectPeerDirect").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(connectPeerDirect)).ToLocalChecked());
  Nan::Set(target, Nan::New("connectPeerTor").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(connectPeerTor)).ToLocalChecked());
}
/*
void init(v8::Handle<v8::Object> exports) 
{
  NODE_SET_METHOD(exports, "initializeNSS", initializeNSS);
  NODE_SET_METHOD(exports, "makeQuorve", makeQuorve);
  NODE_SET_METHOD(exports, "test", test);
  
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::String> key =
    v8::String::NewFromUtf8(isolate, "hello",
      v8::String::kInternalizedString);
  exports->Set(key,
    v8::String::NewFromUtf8(isolate, "quorve"));
}*/

NODE_MODULE(mist_conn, Init)

// #endif
