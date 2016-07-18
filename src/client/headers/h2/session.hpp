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

class Session
{
protected:

  /* Underlying TLS socket */
  Socket &sock;
  
  /* nghttp2 session struct */
  c_unique_ptr<nghttp2_session> h2session;
  
  /* Boolean to signify that we are already sending data on the socket */
  bool _sending;

  /* Boolean to signify if communication has stopped for this session */
  bool _stopped;
  
  /* Boolean to signify that we are inside of a callback context and must
   * not re-trigger a write */
  bool _insideCallback;
  
  bool _isServer;
  
  /* streamId: Stream map for all the streams in the session */
  using stream_map = std::map<std::int32_t, std::unique_ptr<Stream>>;
  stream_map _streams;

  error_callback _onError;
  
  request_callback _onRequest;

public:

  Session(Socket &sock, bool isServer);
  
  void shutdown();
  
  void stop();
  
  bool isStopped() const;
  
  bool isServer() const;
  
  boost::optional<Request&>
  submit(boost::system::error_code &ec,
         const std::string &method,
         const std::string &path,
         const std::string &authority,
         header_map headers,
         generator_callback cb);
  
  /* Returns the raw nghttp2 struct */
  nghttp2_session *nghttp2Session();
  
  /* Signal possible data to be written to the socket */
  void signalWrite();
  
  void setOnError(error_callback cb);
  
  void setOnRequest(request_callback cb);
  
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

  /* Called by the socket when data has been read */
  void readCallback(const std::uint8_t *data, std::size_t length,
                    boost::system::error_code ec);

  /* Called when an error was detected when communicating */
  void error(boost::system::error_code ec);

  /* Write a chunk of data to the socket */
  void write();

  /* Returns true iff there are reads or writes pending */
  bool alive() const;
  
};

}
}

#endif
