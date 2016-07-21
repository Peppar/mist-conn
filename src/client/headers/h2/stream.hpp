#ifndef __MIST_HEADERS_H2_STREAM_HPP__
#define __MIST_HEADERS_H2_STREAM_HPP__

#include <cstddef>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "memory/nghttp2.hpp"

#include "h2/request.hpp"
#include "h2/response.hpp"
#include "h2/types.hpp"

namespace mist
{
namespace h2
{

class Session;

class Stream
{
protected:

  friend class Session;

  Session &_session;
  
  /* RFC7540 5.1.1
   * "Streams are identified with an unsigned 31-bit integer."
   * We make use of int32_t, and use negative integers to indicate
   * that the stream id is invalid.
   */
  std::int32_t _streamId;
  
  virtual int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags) = 0;

  virtual int onFrameSend(const nghttp2_frame *frame) = 0;

  virtual int onFrameNotSend(const nghttp2_frame *frame, int errorCode) = 0;

  virtual int onFrameRecv(const nghttp2_frame *frame) = 0;

  virtual int onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t len) = 0;

  virtual int onStreamClose(std::uint32_t errorCode) = 0;
  
public:

  Stream(Session& session);
  
  bool hasValidStreamId() const;

  std::int32_t streamId() const;

  void setStreamId(std::int32_t streamId);

  Session &session();

};

class ClientStream : public Stream
{
protected:

  ClientRequest _request;
  
  ClientResponse _response;
  
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

  ClientStream(Session& session);
  
  ClientRequest &request();

  ClientResponse &response();
  
};

class ServerStream : public Stream
{
protected:

  ServerRequest _request;
  
  ServerResponse _response;
  
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
  
};

}
}

#endif
