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

namespace detail
{

template<typename T>
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
struct NodeValueConverter<const int>
{
  static v8::Local<v8::Value> conv(const int v)
  {
    return Nan::New(v);
  }
};

} // namespace detail

template<typename T>
v8::Local<v8::Value> conv(T v)
{
  return ::detail::NodeValueConverter<::detail::node_decay_t<T>>::conv(
    ::detail::nodeDecay<T>(v));
}

namespace detail
{

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

} // namespace detail

void
asyncCall(std::function<void()> callback)
{
  ::detail::AsyncCall *ac = new ::detail::AsyncCall(std::move(callback));
  uv_async_init(uv_default_loop(), &ac->handle,
    [](uv_async_t *handle)
  {
    std::unique_ptr<::detail::AsyncCall>
      ac(static_cast<::detail::AsyncCall*>(handle->data));
    ac->callback();
  });
  uv_async_send(&ac->handle);
}

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

/*
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
}*/

/*
template<typename T,
  typename std::enable_if<
    std::is_same<std::remove_cv<T>, std::string>::value>::type* = nullptr>
v8::Local<v8::Value>
nodeValueConvert(T v)
{
  return Nan::New(v);
}*/

/*
template<typename T,
  typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
v8::Local<v8::Value>
nodeValueConvert(T v)
{
  return Nan::New(v);
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
    //SetPrototypeMethod(tpl, "callMe", CallMe);
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
  /*
  static NAN_METHOD(CallMe)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    auto callback = v8::Local<v8::Function>::Cast(info[0]);
    asyncCallNode(callback);
    //info.GetReturnValue().Set(obj->handle());
  }*/

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

namespace detail
{

template<>
struct NodeValueConverter<const mist::Peer::ConnectionStatus>
{
  static v8::Local<v8::Value> conv(const mist::Peer::ConnectionStatus v)
  {
    return Nan::New(static_cast<int>(v));
  }
};

template<>
struct NodeValueConverter<const mist::Peer*>
{
  static v8::Local<v8::Value> conv(const mist::Peer* v)
  {
    return Peer::FromPtr(const_cast<mist::Peer*>(v));
  }
};

} // namespace detail

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
      makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(func));
      /*makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(
        func, [](v8::Local<v8::Function> func, mist::Peer& peer,
          mist::Peer::ConnectionStatus status) -> void
      {
        Nan::HandleScope scope;
        Nan::Callback cb(func);
        std::vector<v8::Local<v8::Value>> parameters {
          Peer::FromPtr(&peer), Nan::New(static_cast<int>(status))
        };
        cb(parameters.size(), parameters.data());
      }));*/
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
      makeAsyncCallback<const std::string&>(func));
    /*
      [pfunc(CopyablePersistent<v8::Function>(func))]
      (const std::string& onionAddress)
    {
      Nan::HandleScope scope;
      asyncCallNode(pfunc, Nan::New<v8::String>(onionAddress).ToLocalChecked());
    });*/
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
