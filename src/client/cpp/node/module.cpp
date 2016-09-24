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

#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

#include "io/io_context.hpp"
#include "io/socket.hpp"
#include "io/ssl_context.hpp"

#include "node/async.hpp"
#include "node/convert.hpp"

namespace
{

v8::Persistent<v8::Value> streamModule;

// Do whatever with the module
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

  static mist::Service& self(v8::Local<v8::Object> obj)
  {
    return *(Nan::ObjectWrap::Unwrap<Service>(obj)->_self);
  }

  mist::Service& self()
  {
    return *_self;
  }

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
      std::string name(convBack<std::string>(info[0]));
      //std::string name(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
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
    auto func = v8::Local<v8::Function>::Cast(info[0]);

    self(info.Holder()).setOnPeerConnectionStatus(
      makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(func));
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


template<typename T, typename O>
class NodeWrap : public Nan::ObjectWrap
{
protected:

  using element_type = std::add_pointer<O>;

private:

  static Nan::Persistent<v8::Function> _ctor;
  element_type _self;

protected:

  NodeWrap() : _self(nullptr) {}
  NodeWrap(element_type s) : _self(s) {}

  element_type self() { assert(_self); return _self; }
  void setSelf(element_type s) { _self = s; }

  static Nan::Persistent<v8::Function> &constructor() { return _ctor; }

  //typedef void (T::*Type)();
  using wrapped_method_type = v8::Local<v8::Value>(T::*)
    (const v8::FunctionCallbackInfo<v8::Value>& args);
  //using WrappedMethod = void(T::*)();
  
  //template <typename T, typename R, typename ...Args>
  //R proxycall(T & obj, R(T::*mf)(Args...), Args &&... args)
  //{
  //  return (obj.*mf)(std::forward<Args>(args)...);
  //}
  template<wrapped_method_type m>
  static v8::Local<v8::Value> Method(
    const v8::FunctionCallbackInfo<v8::Value>& args)
  {
    T* obj = ObjectWrap::Unwrap<T>(args.This());
    return (obj->*m)(args);
  }
};

template<typename T, typename O>
Nan::Persistent<v8::Function> NodeWrap<T, O>::_ctor;

template<typename T, typename O>
class NodeWrapSingleton : public NodeWrap<T, O>
{
protected:

  using key_type = std::add_pointer<std::add_const<O>>;

private:

  static PersistentMap<key_type, v8::Object> _objMap;

public:

  v8::Local<v8::Object> object()
  {
    return _objMap[self()];
  }

  static v8::Local<v8::Object> object(key_type key)
  {
    return _objMap[key];
  }

protected:

  void setObject(v8::Local<v8::Object> obj)
  {
    _objMap.insert(self(), obj)
  }

};

template<typename T, typename O>
PersistentMap<typename NodeWrapSingleton<T, O>::key_type, v8::Object>
NodeWrapSingleton<T, O>::_objMap;

//
//class ClientRequestSingleton
//{
//private:
//
//  friend class ClientRequest;
//
//  Nan::Persistent<v8::Function> _ctor;
//  PersistentMap<mist::ClientRequest*, v8::Object> _objMap;
//
//} _clientRequestSingleton;
//
//class ClientRequest : public Nan::ObjectWrap
//{
//private:
//
//  mist::h2::ClientRequest* _self;
//
//  ClientRequest() : _self(nullptr) {}
//
//public:
//
//  static mist::ClientRequest& self(v8::Local<v8::Object> obj)
//  {
//    return *(Nan::ObjectWrap::Unwrap<ClientRequest>(obj)->_self);
//  }
//
//  mist::ClientRequest& self()
//  {
//    return *_self;
//  }
//
//  static const char *ClassName() { return "ClientRequest"; }
//
//  static v8::Local<v8::FunctionTemplate> Init()
//  {
//    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
//    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
//    tpl->InstanceTemplate()->SetInternalFieldCount(1);
//
//    SetPrototypeMethod(tpl, "setOnResponse",
//      setOnResponse);
//    SetPrototypeMethod(tpl, "setOnPush",
//      setOnPush);
//    SetPrototypeMethod(tpl, "setOnRead",
//      setOnRead);
//    SetPrototypeMethod(tpl, "headers",
//      headers);
//    //SetPrototypeMethod(tpl, "callMe", CallMe);
//    //SetPrototypeMethod(tpl, "getValue", GetValue);
//
//    _serviceSingleton._ctor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
//    return tpl;
//  }
//
//private:
//
//  static NAN_METHOD(New)
//  {
//    if (info.IsConstructCall()) {
//      std::string name(convBack<std::string>(info[0]));
//      //std::string name(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
//      Service *obj = new Service(connCtx->newService(name));
//      obj->Wrap(info.This());
//      info.GetReturnValue().Set(info.This());
//    } else {
//      const int argc = 1;
//      v8::Local<v8::Value> argv[argc] = { info[0] };
//      v8::Local<v8::Function> ctor = Nan::New(_serviceSingleton._ctor);
//      info.GetReturnValue().Set(ctor->NewInstance(argc, argv));
//    }
//  }
//  
//  //void setOnPeerConnectionStatus(peer_connection_status_callback cb);
//
//  //void setOnPeerRequest(peer_request_callback cb);
//
//  //void submit(Peer &peer, std::string method, std::string path,
//  //peer_submit_callback cb);
//
//  //void setOnWebSocket(peer_websocket_callback cb);
//
//  //void openWebSocket(Peer& peer, std::string path,
//  //peer_websocket_callback cb);
//
//  static NAN_METHOD(setOnResponse)
//  {
//    Nan::HandleScope scope;
//    auto func = v8::Local<v8::Function>::Cast(info[0]);
//
//    self(info.Holder()).setOnResponse(
//      makeAsyncCallback<mist::h2::ClientResponse&>(func));
//  }
//
//  static NAN_METHOD(setOnPush)
//  {
//    Nan::HandleScope scope;
//    auto func = v8::Local<v8::Function>::Cast(info[0]);
//
//    self(info.Holder()).setOnPush(
//      makeAsyncCallback<mist::h2::ClientRequest&>(func));
//  }
//
//  static NAN_METHOD(setOnRead)
//  {
//    Nan::HandleScope scope;
//    auto func = v8::Local<v8::Function>::Cast(info[0]);
//
//    //self(info.Holder()).setOnResponse(
//    //  makeAsyncCallback<mist::h2::ClientResponse&>(func));
//  }
//
//  /*
//  static NAN_METHOD(setOnPeerRequest)
//  {
//  Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
//  auto callback = v8::Local<v8::Function>::Cast(info[0]);
//  asyncCallNode(callback);
//  //info.GetReturnValue().Set(obj->handle());
//  }
//
//  static NAN_METHOD(submit)
//  {
//  Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
//  info.GetReturnValue().Set(obj->value_);
//  }
//  static NAN_METHOD(setOnWebSocket)
//  {
//  Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
//  info.GetReturnValue().Set(obj->value_);
//  }
//  static NAN_METHOD(openWebSocket)
//  {
//  Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
//  info.GetReturnValue().Set(obj->value_);
//  }*/
//};


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
    //std::uint16_t torIncomingPort(info[0]->IntegerValue());
    std::uint16_t torIncomingPort(convBack<std::uint16_t>(info[0]));
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
    connCtx->onionAddress(makeAsyncCallback<const std::string&>(func));
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}

NAN_MODULE_INIT(Init)
{
  Nan::HandleScope scope;
  v8::Local<v8::Function> require = v8::Local<v8::Function>::Cast(
    target->Get(Nan::New("require").ToLocalChecked()));

  v8::Local<v8::Value> args[] = {
    Nan::New("stream").ToLocalChecked()
  };
  // v8::Local<v8::Value> 
  //streamModule = v8::Persistent<v8::Value>(v8::Isolate::GetCurrent(), require->Call(target, 1, args));

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
