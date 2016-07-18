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

  Session &_session;
  
  /* RFC7540 5.1.1
   * "Streams are identified with an unsigned 31-bit integer."
   * We make use of int32_t, and use negative integers to indicate
   * that the stream id is invalid.
   */
  std::int32_t _streamId;
  
  Request _request;
  
  Response _response;
  
public:

  Stream(Session& session);
  
  bool hasValidStreamId() const;

  std::int32_t streamId() const;

  void setStreamId(std::int32_t streamId);

  int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
               std::size_t namelen, const std::uint8_t *value,
               std::size_t valuelen, std::uint8_t flags);

  int onFrameSend(const nghttp2_frame *frame);

  int onFrameNotSend(const nghttp2_frame *frame, int errorCode);

  int onFrameRecv(const nghttp2_frame *frame);

  int onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t len);

  int onStreamClose(std::uint32_t errorCode);
  
  void cancel(std::uint32_t errorCode);
  
  void resume();

  /* void writeTrailer(const header_map &headers, boost::system::error_code &ec); */

  Session &session();
  
  Request &request();

  Response &response();
};

}
}

#endif
