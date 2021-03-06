// #ifdef _BUILD_NODE_MODULE

#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <type_traits>
#include <mutex>

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

namespace mist
{
namespace nodemod
{

// This plugin works for this isolate only
v8::Isolate* isolate = nullptr;

namespace
{

//CopyablePersistent<v8::Object> moduleStream_p;
//CopyablePersistent<v8::Object> moduleUtil_p;

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

v8::Local<v8::Object>
require(v8::Local<v8::Object> module, const std::string& path)
{
  v8::HandleScope scope(isolate);

  v8::Local<v8::Function> require
    = module->Get(conv("require")).As<v8::Function>();

  v8::Local<v8::Value> args[] = { conv(path) };

  return require->Call(module, 1, args).As<v8::Object>();
}

//void
//inherit(v8::Local<v8::Object> module, v8::Local<v8::Object> userClass,
//  v8::Local<v8::Object> baseClass)
//{
//  v8::Local<v8::Object> moduleUtil = Nan::New(moduleUtil_p);
//
//  v8::Local<v8::Function> inherit
//    = moduleUtil->Get(conv("inherit")).As<v8::Function>();
//
//  v8::Local<v8::Value> args[] = { userClass, baseClass };
//  inherit->Call(module, 2, args);
//}

class Peer : public NodeWrapSingleton<Peer, mist::Peer&>
{
public:

  Peer(mist::Peer& peer)
    : NodeWrapSingleton(peer) {}

  static const char* ClassName() { return "Peer"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    //SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
    //  setOnPeerConnectionStatus);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
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
    mist::Peer& ptr = *const_cast<mist::Peer*>(v);
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

  static const char* ClassName() { return "Service"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New(ClassName()).ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "setOnPeerConnectionStatus",
      Method<&Service::setOnPeerConnectionStatus>);
    Nan::SetPrototypeMethod(tpl, "setOnPeerRequest",
      Method<&Service::setOnPeerRequest>);
    Nan::SetPrototypeMethod(tpl, "submit",
      Method<&Service::submit>);
    //SetPrototypeMethod(tpl, "callMe", CallMe);
    //SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

private:

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::HandleScope scope(isolate);

    if (info.IsConstructCall()) {
      std::string name(convBack<std::string>(info[0]));
      Service* obj = new Service(connCtx->newService(name));
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    } else {
      isolate->ThrowException(v8::String::NewFromUtf8(isolate,
        "This class cannot be constructed in this way"));
    }
  }
  /*
  void setOnPeerConnectionStatus(peer_connection_status_callback cb);

  void setOnPeerRequest(peer_request_callback cb);


  void setOnWebSocket(peer_websocket_callback cb);

  void openWebSocket(Peer& peer, std::string path,
    peer_websocket_callback cb);*/

  void setOnPeerConnectionStatus(const Nan::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::HandleScope scope(isolate);

    auto func = info[0].As<v8::Function>();

    self()->setOnPeerConnectionStatus(
      makeAsyncCallback<mist::Peer&, mist::Peer::ConnectionStatus>(func));
  }

  void setOnPeerRequest(const Nan::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::HandleScope scope(isolate);

    auto func = info[0].As<v8::Function>();

    self()->setOnPeerRequest(
      makeAsyncCallback<mist::Peer&, mist::h2::ServerRequest&,
        std::string>(func));
  }

  void submit(const Nan::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::HandleScope scope(isolate);

    mist::Peer& peer = Peer::self(info[0].As<v8::Object>());
    std::string method = convBack<std::string>(info[1]);
    std::string path = convBack<std::string>(info[2]);
    auto func = info[3].As<v8::Function>();

    self()->submit(peer, method, path,
      makeAsyncCallback<mist::Peer&, mist::h2::ClientRequest&>(func));
  }

  /*
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



/*****************************************************************************
* ClientRequest, ClientResponse, ClientStream
*****************************************************************************/

class ClientStream
  : public NodeWrapSingleton<ClientStream, mist::h2::ClientStream&>
{
public:

  static const char* ClassName() { return "ClientStream"; }

  ClientStream(mist::h2::ClientStream& _self) : NodeWrapSingleton(_self) {}

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "request",
      Method<&ClientStream::request>);
    Nan::SetPrototypeMethod(tpl, "response",
      Method<&ClientStream::response>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void request(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void response(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

class ClientRequest
  : public NodeWrapSingleton<ClientRequest, mist::h2::ClientRequest&>
{
private:

  bool _inWrite;
  const char* _dataToWrite;
  std::size_t _lengthToWrite;
  CopyablePersistent<v8::Function> _callback;

public:

  ClientRequest(mist::h2::ClientRequest& _self)
    : NodeWrapSingleton(_self),
    _dataToWrite(nullptr), _lengthToWrite(0), _inWrite(false)
  {
    using namespace std::placeholders;
    self().setOnRead(std::bind(&ClientRequest::onRead, this, _1, _2, _3));
  }

  static const char *ClassName() { return "ClientRequest"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "setOnResponse",
      Method<&ClientRequest::setOnResponse>);
    Nan::SetPrototypeMethod(tpl, "setOnPush",
      Method<&ClientRequest::setOnPush>);
    Nan::SetPrototypeMethod(tpl, "headers",
      Method<&ClientRequest::headers>);
    Nan::SetPrototypeMethod(tpl, "_write",
      Method<&ClientRequest::_write>);
    Nan::SetPrototypeMethod(tpl, "stream",
      Method<&ClientRequest::stream>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void _write(const Nan::FunctionCallbackInfo<v8::Value>& info);
  ssize_t onRead(std::uint8_t* data, std::size_t length, std::uint32_t* flags);
  void setOnResponse(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void setOnPush(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void headers(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void stream(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

class ClientResponse
  : public NodeWrapSingleton<ClientResponse, mist::h2::ClientResponse&>
{
public:

  ClientResponse(mist::h2::ClientResponse& _self)
    : NodeWrapSingleton(_self)
  {
  }

  static const char *ClassName() { return "ClientResponse"; }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "setOnData",
      Method<&ClientResponse::setOnData>);
    Nan::SetPrototypeMethod(tpl, "stream",
      Method<&ClientResponse::stream>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void setOnData(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void headers(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void stream(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

void
ClientStream::request(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ClientRequest::object(self().request()));
}

void
ClientStream::response(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ClientResponse::object(self().response()));
}

void
ClientRequest::_write(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> chunk = info[0].As<v8::Object>();
  std::string encoding = convBack<std::string>(info[1]);
  v8::Local<v8::Function> callback = info[2].As<v8::Function>();

  assert(node::Buffer::HasInstance(chunk));

  assert(!_dataToWrite);
  assert(!_lengthToWrite);

  _dataToWrite = node::Buffer::Data(chunk);
  _lengthToWrite = node::Buffer::Length(chunk);
  _callback.Reset(callback);

  self().stream().resume();
}

ssize_t
ClientRequest::onRead(std::uint8_t* data, std::size_t length,
  std::uint32_t* flags)
{
  if (!_lengthToWrite) {
    _dataToWrite = nullptr;
    asyncCall([=]()
    {
      v8::HandleScope scope(isolate);

      Nan::Callback cb(Nan::New(_callback));
      cb();
    });
    return NGHTTP2_ERR_DEFERRED;
  }

  std::size_t actualLength = std::min(length, _lengthToWrite);
  std::copy(_dataToWrite, _dataToWrite + actualLength, data);
  _lengthToWrite -= actualLength;
  return actualLength;
}

void
ClientRequest::setOnResponse(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
  auto func = v8::Local<v8::Function>::Cast(info[0]);

  self(info.Holder()).setOnResponse(
    makeAsyncCallback<mist::h2::ClientResponse&>(func));
}

void
ClientRequest::setOnPush(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
  auto func = v8::Local<v8::Function>::Cast(info[0]);

  self(info.Holder()).setOnPush(
    makeAsyncCallback<mist::h2::ClientRequest&>(func));
}

void
ClientRequest::headers(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
}

void
ClientRequest::stream(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ClientStream::object(self().stream()));
}

void
ClientResponse::setOnData(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  auto func = info[0].As<v8::Function>();
  self().setOnData(
    makeAsyncCallback<const std::uint8_t*, std::size_t>(func,
      [](v8::Local<v8::Function> func, const std::uint8_t* data,
        std::size_t length)
  {
    v8::HandleScope scope(isolate);
    Nan::Callback cb(func);
    v8::Local<v8::Value> args[] = {
      node::Buffer::Copy(isolate, reinterpret_cast<const char*>(data),
        length).ToLocalChecked()
    };
    cb(1, args);
  }));
}

void
ClientResponse::headers(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
}

void
ClientResponse::stream(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ClientStream::object(self().stream()));
}

namespace detail
{

template<>
struct NodeValueConverter<const mist::h2::ClientStream*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ClientStream* v)
  {
    mist::h2::ClientStream& ptr = *const_cast<mist::h2::ClientStream*>(v);
    return ClientStream::object(ptr);
  }
};

template<>
struct NodeValueConverter<const mist::h2::ClientRequest*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ClientRequest* v)
  {
    mist::h2::ClientRequest& ptr = *const_cast<mist::h2::ClientRequest*>(v);
    return ClientRequest::object(ptr);
  }
};

template<>
struct NodeValueConverter<const mist::h2::ClientResponse*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ClientResponse* v)
  {
    mist::h2::ClientResponse& ptr = *const_cast<mist::h2::ClientResponse*>(v);
    return ClientResponse::object(ptr);
  }
};

} // namespace detail



/*****************************************************************************
 * ServerStream, ServerRequest, ServerResponse
 *****************************************************************************/

class ServerStream
  : public NodeWrapSingleton<ServerStream, mist::h2::ServerStream&>
{
public:

  static const char *ClassName() { return "ServerStream"; }

  ServerStream(mist::h2::ServerStream& _self) : NodeWrapSingleton(_self) {}

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "request",
      Method<&ServerStream::request>);
    Nan::SetPrototypeMethod(tpl, "response",
      Method<&ServerStream::response>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void request(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void response(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

class ServerRequest
  : public NodeWrapSingleton<ServerRequest, mist::h2::ServerRequest&>
{
public:

  static const char *ClassName() { return "ServerRequest"; }

  ServerRequest(mist::h2::ServerRequest& _self) : NodeWrapSingleton(_self) {}

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "setOnData",
      Method<&ServerRequest::setOnData>);
    Nan::SetPrototypeMethod(tpl, "headers",
      Method<&ServerRequest::headers>);
    Nan::SetPrototypeMethod(tpl, "stream",
      Method<&ServerRequest::stream>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void setOnData(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void headers(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void stream(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

class ServerResponse
  : public NodeWrapSingleton<ServerResponse, mist::h2::ServerResponse&>
{
private:

  bool _inWrite;
  const char* _dataToWrite;
  std::size_t _lengthToWrite;
  CopyablePersistent<v8::Function> _callback;

public:

  static const char* ClassName() { return "ServerResponse"; }

  ServerResponse(mist::h2::ServerResponse& _self)
    : NodeWrapSingleton(_self),
    _dataToWrite(nullptr), _lengthToWrite(0), _inWrite(false)
  {
    using namespace std::placeholders;
    self().setOnRead(std::bind(&ServerResponse::onRead, this, _1, _2, _3));
  }

  static v8::Local<v8::FunctionTemplate> Init()
  {
    v8::Local<v8::FunctionTemplate> tpl = defaultTemplate(ClassName());

    Nan::SetPrototypeMethod(tpl, "_write",
      Method<&ServerResponse::_write>);
    Nan::SetPrototypeMethod(tpl, "headers",
      Method<&ServerResponse::headers>);
    Nan::SetPrototypeMethod(tpl, "stream",
      Method<&ServerResponse::stream>);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

    return tpl;
  }

private:

  void _write(const Nan::FunctionCallbackInfo<v8::Value>& info);
  ssize_t onRead(std::uint8_t* data, std::size_t length, std::uint32_t* flags);
  void headers(const Nan::FunctionCallbackInfo<v8::Value>& info);
  void stream(const Nan::FunctionCallbackInfo<v8::Value>& info);

};

void
ServerStream::request(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ServerRequest::object(self().request()));
}

void
ServerStream::response(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ServerResponse::object(self().response()));
}

void
ServerRequest::setOnData(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  auto func = info[0].As<v8::Function>();
  self().setOnData(
    makeAsyncCallback<const std::uint8_t*, std::size_t>(func,
      [](v8::Local<v8::Function> func, const std::uint8_t* data,
        std::size_t length)
  {
    v8::HandleScope scope(isolate);
    Nan::Callback cb(func);
    v8::Local<v8::Value> args[] = {
      node::Buffer::Copy(isolate, reinterpret_cast<const char*>(data),
        length).ToLocalChecked()
    };
    cb(1, args);
  }));
}

void
ServerRequest::headers(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
}

void
ServerRequest::stream(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ServerStream::object(self().stream()));
}

void
ServerResponse::_write(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> chunk = info[0].As<v8::Object>();
  std::string encoding = convBack<std::string>(info[1]);
  v8::Local<v8::Function> callback = info[2].As<v8::Function>();

  assert(node::Buffer::HasInstance(chunk));

  assert(!_dataToWrite);
  assert(!_lengthToWrite);

  _dataToWrite = node::Buffer::Data(chunk);
  _lengthToWrite = node::Buffer::Length(chunk);

  self().stream().resume();
}

ssize_t
ServerResponse::onRead(std::uint8_t *data, std::size_t length,
  std::uint32_t *flags)
{
  if (!_lengthToWrite) {
    _dataToWrite = nullptr;
    asyncCall([=]()
    {
      v8::HandleScope scope(isolate);

      Nan::Callback cb(Nan::New(_callback));
      cb();
    });
    return NGHTTP2_ERR_DEFERRED;
  }

  std::size_t actualLength = std::min(length, _lengthToWrite);
  std::copy(_dataToWrite, _dataToWrite + actualLength, data);
  _lengthToWrite -= actualLength;
  return actualLength;
}

void
ServerResponse::headers(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);
}

void
ServerResponse::stream(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  info.GetReturnValue().Set(ServerStream::object(self().stream()));
}

namespace detail
{

template<>
struct NodeValueConverter<const mist::h2::ServerRequest*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ServerRequest* v)
  {
    mist::h2::ServerRequest& ptr = *const_cast<mist::h2::ServerRequest*>(v);
    return ServerRequest::object(ptr);
  }
};

template<>
struct NodeValueConverter<const mist::h2::ServerResponse*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ServerResponse* v)
  {
    mist::h2::ServerResponse& ptr = *const_cast<mist::h2::ServerResponse*>(v);
    return ServerResponse::object(ptr);
  }
};

template<>
struct NodeValueConverter<const mist::h2::ServerStream*>
{
  static v8::Local<v8::Value> conv(const mist::h2::ServerStream* v)
  {
    mist::h2::ServerStream& ptr = *const_cast<mist::h2::ServerStream*>(v);
    return ServerStream::object(ptr);
  }
};

} // namespace detail



void
initializeNSS(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

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

void
loadPKCS12(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  std::string data(convBack<std::string>(info[0]));
  std::string password(convBack<std::string>(info[1]));

  sslCtx->loadPKCS12(data, password);
}

void
loadPKCS12File(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  std::string filename(convBack<std::string>(info[0]));
  std::string password(convBack<std::string>(info[1]));

  sslCtx->loadPKCS12File(filename, password);
}

void
serveDirect(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  std::uint16_t incomingPort(convBack<std::uint16_t>(info[0]));

  connCtx->serveDirect(incomingPort);
}

void
startServeTor(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

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

void
connectPeerDirect(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  mist::Peer& peer = Peer::self(info[0].As<v8::Object>());

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

void
connectPeerTor(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  mist::Peer& peer = Peer::self(info[0].As<v8::Object>());

  connCtx->connectPeerTor(peer);
}

void
addPeer(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  std::string derPublicKey(convBack<std::string>(info[0]));
  std::string nickname(convBack<std::string>(info[1]));

  mist::Peer& peer = connCtx->addPeer(derPublicKey, nickname);

  v8::Local<v8::Object> nodePeer = Peer::object(peer);

  info.GetReturnValue().Set(nodePeer);
}

void
onionAddress(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  v8::HandleScope scope(isolate);

  try {
    auto func = info[0].As<v8::Function>();
    connCtx->onionAddress(makeAsyncCallback<const std::string&>(func));
  } catch (boost::exception &) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}

void
Init(v8::Local<v8::Object> target, v8::Local<v8::Object> module)
{
  isolate = target->GetIsolate();
  v8::HandleScope scope(isolate);

  Nan::Set(target, Nan::New(Service::ClassName()).ToLocalChecked(),
    Nan::GetFunction(Service::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(Peer::ClassName()).ToLocalChecked(),
    Nan::GetFunction(Peer::Init()).ToLocalChecked());

  Nan::Set(target, Nan::New(ClientStream::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ClientStream::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(ClientRequest::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ClientRequest::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(ClientResponse::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ClientResponse::Init()).ToLocalChecked());

  Nan::Set(target, Nan::New(ServerStream::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ServerStream::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(ServerRequest::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ServerRequest::Init()).ToLocalChecked());
  Nan::Set(target, Nan::New(ServerResponse::ClassName()).ToLocalChecked(),
    Nan::GetFunction(ServerResponse::Init()).ToLocalChecked());

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

NODE_MODULE(_mist_conn, Init)

} // namsepace nodemod
} // namespace mist
// #endif
