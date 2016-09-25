#include "node/async.hpp"

#include <functional>
#include <memory>

#include <uv.h>

namespace
{

struct AsyncCall
{
  uv_async_t handle;
  std::function<void()> callback;

  AsyncCall(std::function<void()> callback);
  static void operator delete(void *p);
};

AsyncCall::AsyncCall(std::function<void()> callback)
  : callback(std::move(callback))
{
  handle.data = this;
};

void AsyncCall::operator delete(void *p)
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

} // namespace

void
asyncCall(std::function<void()> callback)
{
  AsyncCall *ac = new AsyncCall(std::move(callback));
  uv_async_init(uv_default_loop(), &ac->handle,
    [](uv_async_t *handle)
  {
    std::unique_ptr<AsyncCall>
      ac(static_cast<AsyncCall*>(handle->data));
    ac->callback();
  });
  uv_async_send(&ac->handle);
}
