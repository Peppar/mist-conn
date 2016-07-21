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
private:

  /* nghttp2 session struct */
  c_unique_ptr<nghttp2_session> h2session;
  
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

protected:

  Session(Socket &sock, bool isServer);
  
  /* Underlying TLS socket */
  Socket &sock;
  
  /* Called by the socket when data has been read */
  void readCallback(const std::uint8_t *data, std::size_t length,
                    boost::system::error_code ec);

  virtual int onBeginHeaders(const nghttp2_frame *frame) = 0;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) = 0;

  /* Called when an error was detected when communicating */
  void error(boost::system::error_code ec);

  /* Write a chunk of data to the socket */
  void write();

  /* Returns true iff there are reads or writes pending */
  bool alive() const;
  
  /* Signal possible data to be written to the socket */
  void signalWrite();

protected:

  /* Lookup a stream from its stream id */
  template<typename StreamT>
  boost::optional<StreamT&> stream(std::int32_t streamId);
  {
    auto it = _streams.find(streamId);
    if (it == _streams.end())
      return boost::none;
    return static_cast<StreamT &>(*it->second);
  }
  
  /* Insert a new stream. The stream must have a stream id assigned. */
  template<typename StreamT>
  StreamT &insertStream(std::unique_ptr<StreamT> strm)
  {
    auto it = _streams.insert(std::make_pair(strm.streamId(),
                                             std::move(strm)));
    assert (!it.second);
    return *it.first.second;
  }

public:

  void shutdown();
  
  void stop();
  
  bool isStopped() const;

  void setOnError(error_callback cb);

  /* Returns the raw nghttp2 struct */
  nghttp2_session *nghttp2Session();

};

class ClientSession : public Session
{
protected:

  virtual int onBeginHeaders(const nghttp2_frame *frame) override;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) override;

public:

  ClientSession(Socket &sock);
  
  boost::optional<ClientRequest&>
  submit(boost::system::error_code &ec,
         // const std::string &method,
         // const std::string &path,
         // const std::string &scheme,
         // const std::string &authority,
         header_map headers,
         generator_callback cb);

};

class ServerSession : public Session
{
private:

  server_request_callback _onRequest;

protected:

  virtual int onBeginHeaders(const nghttp2_frame *frame) override;

  virtual int onStreamClose(std::int32_t stream_id,
                            std::uint32_t error_code) override;

public:

  ServerSession(Socket &sock);

  void setOnRequest(request_callback cb);

};

}
}

#endif
