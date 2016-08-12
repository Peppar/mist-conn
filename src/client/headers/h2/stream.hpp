#ifndef __MIST_HEADERS_H2_STREAM_HPP__
#define __MIST_HEADERS_H2_STREAM_HPP__

#include <cstddef>
#include <string>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include <nghttp2/nghttp2.h>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "memory/nghttp2.hpp"

#include "h2/types.hpp"
#include "h2/util.hpp"
#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

namespace mist
{
namespace h2
{

class Session;

class Stream
{
private:

  friend class Session;
  
  Session &_session;
  
  /* RFC7540 5.1.1
   * "Streams are identified with an unsigned 31-bit integer."
   * We make use of int32_t, and use negative integers to indicate
   * that the stream id is invalid.
   */
  std::int32_t _streamId;
  
  close_callback _onClose;

protected:

  Stream(Session& session);
  
  /* Returns the raw nghttp2 struct */
  nghttp2_session *nghttp2Session();

  /* Write a chunk of data to the socket */
  void write();

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) = 0;

  virtual int onFrameSend(const nghttp2_frame *frame) = 0;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode) = 0;

  virtual int onFrameRecv(const nghttp2_frame *frame) = 0;

  virtual int onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t len) = 0;

  virtual int onStreamClose(std::uint32_t errorCode) = 0;
  
public:

  virtual ~Stream();

  Session &session();

  void setStreamId(std::int32_t streamId);
  
  bool hasValidStreamId() const;
  
  std::int32_t streamId() const;

  void setOnClose(close_callback cb);
  
  void close(boost::system::error_code ec);

  void resume();

  boost::system::error_code submitTrailers(const header_map &trailers);

};

class ClientStream : public Stream
{
private:

  friend class ClientSession;

  ClientRequest _request;
  
  ClientResponse _response;
  
protected:

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) override;

  virtual int onFrameSend(const nghttp2_frame *frame) override;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode)
    override;

  virtual int onFrameRecv(const nghttp2_frame *frame) override;

  virtual int onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t len) override;

  virtual int onStreamClose(std::uint32_t errorCode) override;
  
  void onPush(ClientRequest &request);

public:

  ClientStream(Session& session);
  
  ClientRequest &request();

  ClientResponse &response();
  
  boost::system::error_code submit(std::string method,
                                   std::string path,
                                   std::string scheme,
                                   std::string authority,
                                   header_map headers,
                                   generator_callback cb);

};

class ServerStream : public Stream
{
private:

  friend class ServerSession;

  ServerRequest _request;
  
  ServerResponse _response;
  
protected:

  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) override;

  virtual int onFrameSend(const nghttp2_frame *frame) override;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode)
    override;

  virtual int onFrameRecv(const nghttp2_frame *frame) override;

  virtual int onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t len) override;

  virtual int onStreamClose(std::uint32_t errorCode) override;

public:

  ServerStream(Session& session);
  
  ServerRequest &request();

  ServerResponse &response();
  
  boost::system::error_code submit(std::uint16_t statusCode,
                                   header_map headers,
                                   generator_callback cb);
  
};

} // namespace h2
} // namespace mist

#endif
