#ifndef __MIST_HEADERS_H2_SESSION_HPP__
#define __MIST_HEADERS_H2_SESSION_HPP__

#include <cstddef>
#include <map>
#include <memory>
#include <list>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include <nghttp2/nghttp2.h>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "io/ssl_socket.hpp"

#include "memory/nghttp2.hpp"

#include "h2/types.hpp"

namespace mist
{
namespace h2
{

class Stream;

class WebSocket
{
public:

  void setDataProvider();

};

class Session
{
private:

  friend class Stream;

  /* Disable copy constructor and copy assign */
  Session(Session &) = delete;
  Session &operator=(Session &) = delete;
  
  /* nghttp2 session struct */
  c_unique_ptr<nghttp2_session> _h2session;
  
  /* Underlying TLS socket */
  std::shared_ptr<io::SSLSocket> _socket;
  
  /* Map of all streams in the session */
  using stream_map = std::map<std::int32_t, std::unique_ptr<Stream>>;
  stream_map _streams;

  /* Boolean signifying that we are already sending data on the socket */
  bool _sending;

  /* Boolean signifying that communication has stopped for this session */
  bool _stopped;
  
  /* Boolean signifying that we are inside of a callback context and must
   * not re-trigger a write */
  bool _insideCallback;

  error_callback _onError;

  /* Called by the socket when data has been read; forwards to nghttp2 */
  void readCallback(const std::uint8_t *data, std::size_t length,
                    boost::system::error_code ec);

protected:

  Session(std::shared_ptr<io::SSLSocket> socket, bool isServer);
  
  virtual ~Session();

  /* Start reading from the socket and write the first piece of data */
  void start();
  
  /* Called when an error was detected when communicating */
  void error(boost::system::error_code ec);

  /* Write a chunk of data to the socket */
  void write();

  /* Returns true iff there are reads or writes pending */
  bool alive() const;
  
  /* Returns the raw nghttp2 struct */
  nghttp2_session *nghttp2Session();

  /* nghttp2 callbacks */
  virtual int onBeginHeaders(const nghttp2_frame *frame) = 0;

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) = 0;

  virtual int onFrameSend(const nghttp2_frame *frame) = 0;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode) = 0;

  virtual int onFrameRecv(const nghttp2_frame *frame) = 0;

  virtual int onDataChunkRecv(std::uint8_t flags, std::int32_t stream_id,
                              const std::uint8_t *data, std::size_t len) = 0;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) = 0;

protected:

  /* Lookup a stream from its stream id */
  template<typename StreamT>
  boost::optional<StreamT&> findStream(std::int32_t streamId)
  {
    auto it = _streams.find(streamId);
    if (it == _streams.end())
      return boost::none;
    assert (dynamic_cast<StreamT *>(it->second.get()));
    return *static_cast<StreamT *>(it->second.get());
  }
  
  /* Insert a new stream. The stream must have a stream id assigned. */
  template<typename StreamT>
  StreamT &insertStream(std::unique_ptr<StreamT> strm)
  {
    assert (strm->hasValidStreamId());
    auto it = _streams.insert(std::make_pair(strm->streamId(),
                                             std::move(strm)));
    assert (it.second);
    assert (dynamic_cast<StreamT *>(it.first->second.get()));
    return *static_cast<StreamT *>(it.first->second.get());
  }

public:

  void shutdown();
  
  void stop();
  
  bool isStopped() const;

  void setOnError(error_callback cb);

};

class ClientSession : public Session
{
private:

  /* Disable copy constructor and copy assign */
  ClientSession(Session &) = delete;
  ClientSession &operator=(Session &) = delete;

protected:

  virtual int onBeginHeaders(const nghttp2_frame *frame) override;

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) override;

  virtual int onFrameSend(const nghttp2_frame *frame) override;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode) override;

  virtual int onFrameRecv(const nghttp2_frame *frame) override;

  virtual int onDataChunkRecv(std::uint8_t flags, std::int32_t stream_id,
                              const std::uint8_t *data, std::size_t len) override;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) override;

public:

  ClientSession(std::shared_ptr<io::SSLSocket> socket);

  ClientRequest&
  submit(std::string method, std::string path, std::string scheme,
    std::string authority, header_map headers,
    generator_callback cb = nullptr);

};

class ServerSession : public Session
{
private:

  /* Disable copy constructor and copy assign */
  ServerSession(Session &) = delete;
  ServerSession &operator=(Session &) = delete;

  server_request_callback _onRequest;

protected:

  friend class ServerStream;

  virtual int onBeginHeaders(const nghttp2_frame *frame) override;

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) override;

  virtual int onFrameSend(const nghttp2_frame *frame) override;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode) override;

  virtual int onFrameRecv(const nghttp2_frame *frame) override;

  virtual int onDataChunkRecv(std::uint8_t flags, std::int32_t stream_id,
                              const std::uint8_t *data, std::size_t len) override;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) override;

public:

  ServerSession(std::shared_ptr<io::SSLSocket> socket);

  void setOnRequest(server_request_callback cb);

};

} // namespace h2
} // namespace mist

#endif
