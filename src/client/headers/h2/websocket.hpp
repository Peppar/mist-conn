#ifndef __MIST_HEADERS_H2_WEBSOCKET_HPP__
#define __MIST_HEADERS_H2_WEBSOCKET_HPP__

#include <cstddef>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "io/socket.hpp"

#include "h2/stream.hpp"

namespace mist
{
namespace h2
{

class IOContext;

class WebSocket : public io::Socket
{
public:

  generator_callback::result_type generator(std::uint8_t *data,
    std::size_t length, std::uint32_t *flags);

  void onData(const std::uint8_t *data, std::size_t length);

  /* Read a fixed-length packet. */
  virtual void readOnce(std::size_t length, read_callback cb) override;

  /* Read indefinitely. */
  virtual void read(read_callback cb) override;

  /* Write. */
  virtual void write(const std::uint8_t *data, std::size_t length,
    write_callback cb = nullptr) override;

  /* Close the socket. */
  virtual void close(boost::system::error_code ec
    = boost::system::error_code()) override;

protected:

  WebSocket();

  boost::optional<Stream&> _stream;

private:

  /* Write state data. */
  struct Write
  {
    enum class State {
      Off,
      On,
    } state;

    const uint8_t *data;
    std::size_t length;
    std::size_t nwritten;

    write_callback cb;
  } _w;

  /* Read state data. */
  struct Read
  {
    enum class State {
      Off,
      Once,
      Continuous,
    } state;

    std::vector<uint8_t> buffer;
    std::size_t length;

    read_callback cb;
  } _r;

  void tryReadOnce();

};

class ClientWebSocket : public WebSocket
{
public:

  ClientWebSocket();

  void start(ClientSession &session, std::string authority, std::string origin,
    std::string path);

private:

  ClientWebSocket(ClientWebSocket&) = delete;
  ClientWebSocket &operator=(ClientWebSocket&) = delete;

};

class ServerWebSocket : public WebSocket
{
public:

  ServerWebSocket();

  void start(ServerRequest &request);

private:

  ServerWebSocket(ServerWebSocket&) = delete;
  ServerWebSocket &operator=(ServerWebSocket&) = delete;

};

} // namespace h2
} // namespace mist

#endif
