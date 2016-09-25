#ifdef _BUILD_NODE_MODULE

#include <string>
#include <type_traits>
#include <iostream>

#include <prio.h>

#include <node.h>
#include <v8.h>
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
#include "node/wrap.hpp"

namespace
{

// This plugin works for this isolate only
v8::Isolate* isolate = nullptr;

CopyablePersistent<v8::Object> stream;

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

} // namespace

class Peer : public NodeWrapSingleton<Peer, mist::Peer*>
{
public:

  static const char *ClassName() { return "Peer"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    //SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
    //  setOnPeerConnectionStatus);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
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
      v8::Local<v8::Function> ctor = Nan::New(constructor());
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
    mist::Peer* ptr = const_cast<mist::Peer*>(v);
    v8::Local<v8::Object> obj(Peer::object(ptr));
    return obj;
  }
};

} // namespace detail

class Service : public NodeWrapSingleton<Service,
  std::shared_ptr<mist::Service>>
{
private:

  Service(std::shared_ptr<mist::Service> service)
  {
    setSelf(std::move(service));
  }

public:

  static const char *ClassName() { return "Service"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
      Method<&Service::setOnPeerConnectionStatus>);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

private:

  static NAN_METHOD(New)
  {
    if (info.IsConstructCall()) {
      std::string name(convBack<std::string>(info[0]));
      Service *obj = new Service(connCtx->newService(name));
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    } else {
      const int argc = 1;
      v8::Local<v8::Value> argv[argc] = { info[0] };
      v8::Local<v8::Function> ctor = Nan::New(constructor());
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

  void setOnPeerConnectionStatus(const Nan::FunctionCallbackInfo<v8::Value>& args)
  {
    Nan::HandleScope scope;

    auto func = args[0].As<v8::Function>();

    self()->setOnPeerConnectionStatus(
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

NAN_METHOD(initializeNSS)
{
  Nan::HandleScope scope;

  std::string dbDir(convBack<std::string>(info[0]));
  //std::string dbDir(*v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked()));
  //std::string nickname(*v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked()));

  sslCtx = std::make_unique<mist::io::SSLContext>(ioCtx, dbDir);
  connCtx = std::make_unique<mist::ConnectContext>(*sslCtx);

  /* Start the IO event loop in a separate thread */
  ioCtx.queueJob([]() { ioCtx.exec(); });

  //auto rv = Nan::New("world").ToLocalChecked();
  //info.GetReturnValue().Set(rv);
}

NAN_METHOD(loadPKCS12)
{
  Nan::HandleScope scope;

  std::string data(convBack<std::string>(info[0]));
  std::string password(convBack<std::string>(info[1]));

  sslCtx->loadPKCS12(data, password);
}

NAN_METHOD(loadPKCS12File)
{
  Nan::HandleScope scope;

  std::string filename(convBack<std::string>(info[0]));
  std::string password(convBack<std::string>(info[1]));

  sslCtx->loadPKCS12File(filename, password);
}

NAN_METHOD(serveDirect)
{
  Nan::HandleScope scope;

  std::uint16_t incomingPort(convBack<std::uint16_t>(info[0]));

  connCtx->serveDirect(incomingPort);
}

NAN_METHOD(startServeTor)
{
  Nan::HandleScope scope;

  try {

    std::uint16_t torIncomingPort(convBack<std::uint16_t>(info[0]));
    std::uint16_t torOutgoingPort(convBack<std::uint16_t>(info[1]));
    std::uint16_t controlPort(convBack<std::uint16_t>(info[2]));
    std::string executableName(convBack<std::string>(info[3]));
    std::string workingDir(convBack<std::string>(info[4]));

    std::cerr
      << torIncomingPort
      << " " << torOutgoingPort
      << " " << controlPort
      << " " << executableName
      << " " << workingDir << std::endl;
    connCtx->startServeTor(torIncomingPort, torOutgoingPort, controlPort,
      executableName, workingDir);
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}

NAN_METHOD(connectPeerDirect)
{
  Nan::HandleScope scope;

  mist::Peer& peer = *Peer::self(info[0].As<v8::Object>());

  PRNetAddr addr;
  {
    boost::system::error_code ec;

    std::string addrStr(convBack<std::string>(info[1]));
    std::uint16_t port(convBack<std::uint16_t>(info[2]));
    
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

  mist::Peer& peer = *Peer::self(info[0].As<v8::Object>());

  connCtx->connectPeerTor(peer);
}

NAN_METHOD(addPeer)
{
  Nan::HandleScope scope;

  std::string derPublicKey(convBack<std::string>(info[0]));
  std::string nickname(convBack<std::string>(info[1]));

  mist::Peer& peer = connCtx->addPeer(derPublicKey, nickname);

  v8::Local<v8::Object> nodePeer = Peer::object(&peer);

  info.GetReturnValue().Set(nodePeer);
}

NAN_METHOD(onionAddress)
{
  Nan::HandleScope scope;

  try {
    auto func = info[0].As<v8::Function>();
    connCtx->onionAddress(makeAsyncCallback<const std::string&>(func));
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}

v8::Local<v8::Object>
require(v8::Local<v8::Object> module, const std::string& path)
{
  v8::HandleScope scope(isolate);

  v8::Local<v8::Function> require
    = module->Get(conv("require")).As<v8::Function>();

  v8::Local<v8::Value> args[] = { conv(path) };

  return require->Call(module, 1, args).As<v8::Object>();
}

void
Init(v8::Local<v8::Object> target, v8::Local<v8::Object> module)
{
  isolate = target->GetIsolate();
  v8::HandleScope scope(isolate);

  stream = CopyablePersistent<v8::Object>(require(module, "stream"));

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

NODE_MODULE(mist_conn, Init)

// #endif
