#ifndef __MIST_HEADERS_H2_SESSION_HPP__
#define __MIST_HEADERS_H2_SESSION_HPP__

#include <cstddef>
#include <map>
#include <memory>
#include <list>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "memory/nghttp2.hpp"

#include "h2/types.hpp"

namespace mist
{

class Socket;

namespace h2
{

class Stream;

class Session// : std::enable_shared_from_this<Session>
{
public:

  Session(Socket &sock);
  
  void stop();
  
  boost::optional<Stream&>
  submit(boost::system::error_code &ec,
         const std::string &method,
         const std::string &path,
         generator_callback cb,
         header_map headers);
  
  nghttp2_session *nghttp2Session();
  
  void signalWrite();
  
  /* Lookup a stream from its stream id */
  boost::optional<Stream&> stream(std::int32_t streamId);
  
protected:

  /* Create a new steam */
  std::unique_ptr<Stream> createStream();

  /* Close a stream */
  void closeStream(Stream &stream);
  
  /* Insert a new stream created with createStream. The stream
   * must have a stream id assigned. */
  Stream &insertStream(std::unique_ptr<Stream> strm);

  /* Create a new push stream with the specified promised id */  
  void createPushStream(std::int32_t streamId);

  void readCallback(const std::uint8_t *data, std::size_t length,
                    boost::system::error_code ec);

  void _error(boost::system::error_code ec);

  void _write();
  
protected:

  Socket &sock;
  
  c_unique_ptr<nghttp2_session> h2session;
  
  /* Boolean to signify that we are already sending data on the socket */
  bool _sending;

  /* Boolean to signify that we are inside of a callback context and must
   * not re-trigger a write */
  bool _insideCallback;
  
  using stream_map = std::map<std::int32_t, std::unique_ptr<Stream>>;
  stream_map _streams;

};

}
}

#endif
