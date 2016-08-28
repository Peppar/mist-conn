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

} // namespace

/*
void
WeakCallback() {
  puts(data.GetParameter());
  // The persistent's storage cell is automatically disposed.  Keep a reference
  // to the original v8::Persistent<T> if you want to revive it with
  // .ClearWeak().
}*/

/*
HttpRequest* JsHttpRequestProcessor::UnwrapRequest(Local<Object> obj) {
  Local<External> field = Local<External>::Cast(obj->GetInternalField(0));
  void* ptr = field->Value();
  return static_cast<HttpRequest*>(ptr);
}
  Local<ObjectTemplate> result = ObjectTemplate::New(isolate);
  result->SetInternalFieldCount(1);
  result->SetInternalField(0, request_ptr);
template<typename T, typename... Args>
Local<ObjectTemplate>
make_object(Nan::Persistent<v8::Object> &persistent, Args&&... args)
{
  persistent.SetWeak(new T(std::forward<Args>(args)...),
    [](const Nan::WeakCallbackInfo<T> &data)
  {
    delete data.GetParameter();
  }, Nan::WeakCallbackType::kParameter);
  
//  return std::move(persistent);
}
*/
/*
template<typename T>
class node_wrapper
{
private:

  node_wrapper(node_wrapper &) = delete;
  node_wrapper &operator=(node_wrapper &) = delete;
  
  Nan::Persistent<v8::Object> _persistent;
  static v8::Global<v8::ObjectTemplate> _templ;

  void initialize_persistent(v8::Isolate *isolate)
  {
    v8::HandleScope handle_scope(isolate);
    
    v8::Local<v8::ObjectTemplate> templ;
    if (_templ.IsEmpty()) {
      templ = v8::ObjectTemplate::New(isolate);
      templ->SetInternalFieldCount(1);
      //result->SetHandler(NamedPropertyHandlerConfiguration(MapGet, MapSet));
      //v8::Local<v8::ObjectTemplate> raw_template = MakeMapTemplate(GetIsolate());
      _templ.Reset(isolate, templ);
    } else {
      templ = v8::Local<v8::ObjectTemplate>::New(isolate, _templ);
    }
    
    auto object = templ->NewInstance();
    object->SetAlignedPointerInInternalField(0, this);
    
    _persistent = Nan::Persistent<v8::Object>(object);
    _persistent.SetWeak(static_cast<T*>(this),
      [](const Nan::WeakCallbackInfo<T> &data)
    {
      delete data.GetParameter();
    }, Nan::WeakCallbackType::kParameter);
  }

  template<typename S, typename... Args>
  friend S& make_node(v8::Isolate *isolate, Args&&... args);

public:

  node_wrapper() {}

  v8::Local<v8::Object>
  to_local(v8::Isolate *isolate)
  {
    return v8::Local<v8::Object>::New(isolate, _persistent);
    //Local<Function> localMyFunc = Local<Function>::New(_persistent.GetIsolate(), perMyFunc)
    //return v8::Local<v8::Object>::Cast(_persistent);
  }
  
  static T&
  from_local(v8::Local<v8::Object> obj)
  {
    //auto field = v8::Local<v8::External>::Cast(
    //  _persistent->GetAlignedPointerFromInternalField(0));
    return *static_cast<T*>(obj->GetAlignedPointerFromInternalField(0));
    //field->Value());
  }
};

template<typename T, typename... Args>
T& make_node(v8::Isolate *isolate, Args&&... args)
{
  static_assert(std::is_base_of<node_wrapper<T>, T>::value,
    "Class must inherit from node_wrapper");
  T *obj = new T(std::forward<Args>(args)...);
  obj->initialize_persistent(isolate);
  return *obj;
}*/

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
      ::operator delete(reinterpret_cast<AsyncCall*>(
        reinterpret_cast<char*>(handle) - offsetof(AsyncCall, handle)));
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

/*
// called by libuv worker in separate thread
static void DelayAsync(uv_work_t *req)
{
    DelayBaton *baton = static_cast<DelayBaton *>(req->data);
    delay(baton->seconds);
}

// called by libuv in event loop when async function completes
static void DelayAsyncAfter(uv_work_t *request, int status)
{
  // get the reference to the baton from the request
  AsyncCall *ac = static_cast<AsyncCall*>(req->data);

  // set up return arguments
  Handle<Value> argv[] =
      {
          Handle<Value>(Int32::New(baton->seconds)),
          Handle<Value>(String::New(baton->greeting))
      };

  // execute the callback
  baton->callback->Call(Context::GetCurrent()->Global(),2,argv);

  // dispose the callback object from the baton
  baton->callback.Dispose();

  // delete the baton object
  delete ac;
}*/
/*
template<typename Args...>
void
QueueCallback(Handle<Function> cb, Args&& args...)
{
  AsyncRequest *ac = new AsyncRequest(cb, std::forward<Args>(args)...);

    // assign callback to baton
    baton->callback = Persistent<Function>::New(cb);

    // queue the async function to the event loop
    // the uv default loop is the node.js event loop
  uv_queue_work(uv_default_loop(), ac.request(), DelayAsync, DelayAsyncAfter);
}

void init(Handle<Object> exports) {

  // add the async function to the exports for this object
  exports->Set(
                String::NewSymbol("delay"),                          // javascript function name
                FunctionTemplate::New(Delay)->GetFunction()          // attach 'Delay' function to javascript name
              );
}*/

class Quorve : public Nan::ObjectWrap
{
 public:
 
  static v8::Local<v8::FunctionTemplate> Init() {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("MyObject").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    SetPrototypeMethod(tpl, "getHandle", GetHandle);
    SetPrototypeMethod(tpl, "callMe", CallMe);
    SetPrototypeMethod(tpl, "getValue", GetValue);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    return tpl;
  }

 private:
  explicit Quorve(double value = 0) : value_(value) {}
  ~Quorve() {}

  static NAN_METHOD(New) {
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

  static NAN_METHOD(GetHandle) {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(CallMe) {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    auto callback = v8::Local<v8::Function>::Cast(info[0]);
    asyncCall(callback);
    //info.GetReturnValue().Set(obj->handle());
  }

  static NAN_METHOD(GetValue) {
    Quorve* obj = Nan::ObjectWrap::Unwrap<Quorve>(info.Holder());
    info.GetReturnValue().Set(obj->value_);
  }

  static inline Nan::Persistent<v8::Function> & constructor() {
    static Nan::Persistent<v8::Function> my_constructor;
    return my_constructor;
  }

  double value_;
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

void
initializeNSS(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  if (args.Length() != 2) {
    isolate->ThrowException(v8::Exception::TypeError(
      v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
  }
  
  auto dbDir = fromV8<std::string>(args[0]);
  auto nickname = fromV8<std::string>(args[1]);
  
  v8::HandleScope scope(isolate);
  
  sslCtx = std::make_unique<mist::io::SSLContext>(ioCtx, dbDir, nickname);
  /*SSLContext(ioCtx, const std::string &dbdir,
             const std::string &nickname);*/

  auto rv = v8::String::NewFromUtf8(isolate, "world");
  args.GetReturnValue().Set(rv);
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

NAN_MODULE_INIT(Init) {
  Nan::Set(target, Nan::New("MyObject").ToLocalChecked(),
    Nan::GetFunction(Quorve::Init()).ToLocalChecked());
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
