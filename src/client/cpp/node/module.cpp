#include <string>
#include <type_traits>
#include <iostream>

//#include <node.h>
//#include <v8.h>
#include <nan.h>

#include "conn.hpp"
#include "io/io_context.hpp"
#include "io/ssl_context.hpp"

namespace
{

mist::io::IOContext ioCtx;
std::unique_ptr<mist::io::SSLContext> sslCtx;
std::unique_ptr<mist::ConnectContext> connCtx;

template<typename T,
  typename std::enable_if<std::is_same<T, std::string>::value>::type* = nullptr>
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
  typename std::enable_if<std::is_same<T, std::string>::value>::type* = nullptr>
v8::Handle<v8::Value>
toV8(T v, v8::Isolate* isolate)
{
  return v8::String::NewFromUtf8(isolate, v.c_str());
}

template<typename T,
  typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
v8::Handle<v8::Value>
toV8(T v)
{
  return v8::Number::New(v);
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
asyncCall(v8::Local<v8::Function> callback)
{
  asyncCall([pCallback(CopyablePersistent<v8::Function>(callback))]() mutable
  {
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    v8::HandleScope handle_scope(isolate);
    
    auto callback = Nan::New(pCallback);
    callback->Call(isolate->GetCurrentContext()->Global(),
      0, nullptr);
  });
}

template<typename... Args,
  typename std::enable_if<sizeof...(Args) != 0>::type* = nullptr>
void
asyncCall(v8::Local<v8::Function> callback, Args&&... args)
{
  constexpr const std::size_t argCount = sizeof...(Args);
  
  /* We need to keep a vector of persistent arguments throughout the call */
  std::vector<CopyablePersistent<v8::Value>> pArgs
    {CopyablePersistent<v8::Value>(args)...};
  asyncCall([pCallback(CopyablePersistent<v8::Function>(callback)),
             pArgs(std::move(pArgs))]() mutable
  {
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    v8::HandleScope handle_scope(isolate);
    
    auto callback = Nan::New(pCallback);
    std::vector<v8::Local<v8::Value>> arguments(argCount);
    std::transform(pArgs.begin(), pArgs.end(), arguments.begin(),
      &Nan::New<v8::Local<v8::Object>>);
    callback->Call(isolate->GetCurrentContext()->Global(),
      argCount, arguments.data());
  });
}

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
    asyncCall(callback);
    //info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(GetValue)
  {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }
};


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

  auto rv = Nan::New("world").ToLocalChecked();
  info.GetReturnValue().Set(rv);
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
  Nan::Set(target, Nan::New(Quorve::ClassName()).ToLocalChecked(),
    Nan::GetFunction(Quorve::Init()).ToLocalChecked());
  
  Nan::Set(target, Nan::New("initializeNSS").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(initializeNSS)).ToLocalChecked());
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
