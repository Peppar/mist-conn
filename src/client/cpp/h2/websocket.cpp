#include <cstddef>
#include <string>

#include <nghttp2/nghttp2.h>

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/websocket.hpp"

namespace mist
{
namespace h2
{

/*
 * WebSocket
 */
WebSocket::WebSocket()
{
  _r.state = Read::State::Off;
  _w.state = Write::State::Off;
}

generator_callback::result_type
WebSocket::generator(std::uint8_t *data, std::size_t length,
  std::uint32_t *flags)
{
  if (_w.state == Write::State::Off)
    return NGHTTP2_ERR_DEFERRED;

  // Write
  std::size_t nwrite;
  {
    nwrite = std::min(length, _w.length - _w.nwritten);
    assert(nwrite);
    std::copy(_w.data + _w.nwritten, _w.data + _w.nwritten + nwrite, data);
    _w.nwritten += nwrite;
  }

  // Check for completion
  if (_w.nwritten == _w.length) {
    _w.state = Write::State::Off;
    if (_w.cb)
      std::move(_w.cb)(_w.nwritten, boost::system::error_code());
  }

  return nwrite;
}

void
WebSocket::tryReadOnce()
{
  if (_r.buffer.size() >= _r.length) {
    _r.state = Read::State::Off;
    std::move(_r.cb)(_r.buffer.data(), _r.length, boost::system::error_code());
    _r.buffer.erase(_r.buffer.begin(), _r.buffer.begin() + _r.length);
  }
}

void
WebSocket::onData(const std::uint8_t * data, std::size_t length)
{
  if (_r.state == Read::State::Continuous) {
    _r.cb(data, length, boost::system::error_code());
  } else {
    _r.buffer.insert(_r.buffer.end(), data, data + length);

    if (_r.state == Read::State::Once)
      tryReadOnce();
  }
}

void
WebSocket::readOnce(std::size_t length, read_callback cb)
{
  assert(_r.state == Read::State::Off);
  _r.state = Read::State::Once;
  _r.length = length;
  _r.cb = std::move(cb);

  tryReadOnce();
}

void
WebSocket::read(read_callback cb)
{
  assert(_r.state == Read::State::Off);
  _r.state = Read::State::Continuous;
  _r.cb = std::move(cb);
  if (!_r.buffer.empty()) {
    _r.cb(_r.buffer.data(), _r.buffer.size(), boost::system::error_code());
    _r.buffer.clear();
  }
}

void
WebSocket::write(const std::uint8_t *data, std::size_t length,
  write_callback cb)
{
  assert(_w.state == Write::State::Off);
  _w.state = Write::State::On;
  _w.data = data;
  _w.length = length;
  _w.nwritten = 0;
  _w.cb = std::move(cb);

  _stream->resume();
}

void
WebSocket::close(boost::system::error_code ec)
{
  _stream->close(ec);
}

/*
 * ClientWebSocket
 */
ClientWebSocket::ClientWebSocket()
{
}

void
ClientWebSocket::start(ClientSession &session, std::string authority,
  std::string path)
{
  boost::optional<ClientStream&> stream;

  // Request
  {
    mist::h2::header_map headers;
    // nghttp2 does not allow custom special headers, for now we do not
    // aim to be compliant of the WebSocket proposal.
    //headers.insert({ ":version", { "WebSocket / 13", false } });
    //headers.insert({ ":origin", { origin, false } });
    //headers.insert({ ":host", { authority, false } });
    //headers.insert({ ":sec-websocket-protocol", { protocol, false } });

    using namespace std::placeholders;
    auto& request = session.submit("GET", path, "wss", authority, headers,
      std::bind(&WebSocket::generator, this, _1, _2, _3));
    stream = request.stream();
  }

  // Response
  {
    using namespace std::placeholders;
    stream->response().setOnData(std::bind(&WebSocket::onData, this, _1, _2));
  }

  _stream = *stream;
}

/*
 * ServerWebSocket
 */
ServerWebSocket::ServerWebSocket()
{
}

void
ServerWebSocket::start(ServerRequest &request)
{
  boost::optional<ServerStream&> stream = request.stream();

  // Request
  {
    using namespace std::placeholders;
    request.setOnData(std::bind(&WebSocket::onData, this, _1, _2));
  }

  // Response
  {
    mist::h2::header_map headers;
    // nghttp2 does not allow custom special headers, for now we do not
    // aim to be compliant of the WebSocket proposal.
    //headers.insert({ ":sec-websocket-protocol", { protocol, false } });

    using namespace std::placeholders;
    stream->submit(101, headers,
      std::bind(&WebSocket::generator, this, _1, _2, _3));
  }

  _stream = *stream;
}

}
}
