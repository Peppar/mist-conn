#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>

template<std::size_t N>
class circular_buffer
{
protected:

  using bufTy = std::array<uint8_t, N>;
  bufTy buf;
  std::size_t in, out;
  bool bufEmpty;

  inline std::pair<std::size_t, std::size_t> produceRange() const
  {
    if (in < out)
      return std::make_pair(in, out);
    else
      return std::make_pair(in, N);
  }
  
  inline std::pair<std::size_t, std::size_t> consumeRange() const
  {
    if (in < out)
      return std::make_pair(out, N);
    else
      return std::make_pair(out, in);
  }

  // 0                         N
  // *******in--------out******   wrapped
  // -------out*******in-------

public:
  
  inline constexpr bool size() const { return N; }
  inline bool empty() const { return bufEmpty; }
  inline bool full() const { return !bufEmpty && in == out; }
  inline std::size_t dataCount() const
  { 
    if (bufEmpty)
      return 0;
    else if (out < in)
      return in - out;
    else
      return out - in + N; 
  }
  inline std::size_t freeCount() const { return N - dataCount(); }

  // std::size_t write(const uint8_t *data, std::size:t length)
  // {
    // /* Corner case for empty buffer */
    // if (!length)
      // return 0;
    // bufEmpty = false;
    
    // std::size_t nwritten = 0;
    // /* For each write, we may encounter maximally two slices.
       // Specify a loop of two and hope that the compiler will
       // unroll it for us */
    // for (std::size_t n = 0; n < 2; ++n) {
      // if (!length)
        // break;
      
      // auto range = writeRange();
      
      // std::size_t available = range.second - range.first;
      // if (!available)
        // break;

      // std::size_t actual = std::min(available, length);
      // std::copy(data, data + actual, buf.data() + range.first);

      // in = (in + actual) % N;
      // length -= actual;
      // nwritten += actual;
      // data += actual;
    // };

    // return nwritten;
  // }
  
  // std::size_t read(const uint8_t *data, std::size:t length)
  // {
    // /* Corner case for empty buffer */
    // if (bufEmpty)
      // return 0;
    
    // std::size_t nread = 0;
    // /* For each write, we may encounter maximally two slices.
       // Specify a loop of two and hope that the compiler will
       // unroll it for us */
    // for (std::size_t n = 0; n < 2; ++n) {
      // if (!length)
        // break;

      // auto range = readRange();
      // std::size_t available = range.second - range.first;
      // if (!available)
        // break;

      // std::size_t actual = std::min(available, length);
      // std::copy(buf.data() + range.first, buf.data() + range.first + actual,
                // data);

      // out = (out + actual) % N;
      // length -= actual;
      // nread += actual;
      // data += actual;
    // };
    
    // /* Corner case: if the buffer is empty, in == out does not mean full */
    // if (in == out) {
      // bufEmpty = true;
      // /* Reset indexes to 0, to avoid slicing */
      // in = 0;
      // out = 0;
    // }
    // return nread;
  // }

  // std::size_t sockRecv()
  // {
  // }

  using data_producer
    = std::function<std::size_t(uint8_t *, std::size_t)>;

  using data_consumer
    = std::function<std::size_t(uint8_t *, std::size_t)>;

  data_producer prod;
  data_consumer cons;
  
  circular_buffer()
    : in(0), out(0), bufEmpty(true) {}

  void setProducer(data_producer prod)
  {
    this->prod = std::move(prod);
  }
  
  void setConsumer(data_consumer cons)
  {
    this->cons = std::move(cons);
  }
  
  /*
   * Receives data from the producer callback until the buffer is full
   * or the producer supplies no more data.
   */
  bool produce()
  {
    assert (prod);
    
    bool fatigue = false;
    
    while (true) {
      auto range = produceRange();

      std::size_t available = range.second - range.first;
      if (!available)
        break;

      std::size_t ndata = prod(buf.data() + range.first, available);
      if (!ndata) {
        fatigue = true;
        break;
      }
      
      empty = false;
      
      in = (in + ndata) % N;
    };

    return !fatigue;
  }
  
  /*
   * Sends data to the consumer callback until the buffer is empty
   * or the consumer accepts no more data.
   */
  bool consume()
  {
    assert (cons);
    
    /* Corner case for empty buffer */
    if (bufEmpty)
      return true;
    
    bool fatigue = false;
    
    while (true) {
      auto range = consumeRange();
      
      std::size_t available = range.second - range.first;
      if (!available)
        break;

      std::size_t actual = cons(buf.data() + range.first, actual);
      if (!actual) {
        fatigue = true;
        break;
      }
      
      out = (out + actual) % N;
    };

    /* Corner case: if the buffer is empty, in == out does not mean full */
    if (in == out) {
      bufEmpty = true;
      /* Reset indexes to 0 */
      in = 0;
      out = 0;
    }

    return !fatigue;
  }

  /*
   * Cycles produce and consume, and stops when no more actions are possible.
   */
  void cycle()
  {
    assert (prod);
    assert (cons);
    
    bool producerFatigue = false;
    bool consumerFatigue = false;
    while ((!producerFatigue && !full()) || (!consumerFatigue && !empty())) {
      if (!produce())
        producerFatigue = true;
      if (!consume())
        consumerFatigue = true;
    }
  }
  
  /*
   * Writes the given data directly into the buffer.
   */
  std::size_t write(const uint8_t *data, std::size_t length)
  {
    /* Corner case for empty buffer */
    if (!length)
      return 0;
    bufEmpty = false;
    
    std::size_t nwritten = 0;
    /* For each write, we may encounter maximally two slices.
       Specify a loop of two and hope that the compiler will
       unroll it for us */
    for (std::size_t n = 0; n < 2; ++n) {
      auto range = produceRange();
      
      std::size_t available = range.second - range.first;
      if (!available)
        break;

      std::size_t actual = std::min(available, length);
      std::copy(data, data + actual, buf.data() + range.first);

      in = (in + actual) % N;
      length -= actual;
      nwritten += actual;
      data += actual;
      
      if (!length)
        break;
    };

    return nwritten;
  }
  
  /*
   * Reads the given data directly from the buffer.
   */
  std::size_t read(const uint8_t *data, std::size_t length)
  {
    assert (length);
    
    /* Corner case for empty buffer */
    if (bufEmpty)
      return 0;
    
    std::size_t nread = 0;
    /* For each read, we may encounter maximally two slices.
       Specify a loop of two and hope that the compiler will
       unroll it for us */
    for (std::size_t n = 0; n < 2; ++n) {
      auto range = consumeRange();
      
      std::size_t available = range.second - range.first;
      if (!available)
        break;
      
      std::size_t actual = std::min(available, length);
      std::copy(buf.data() + range.first, buf.data() + range.first + actual,
                data);
                
      nread += actual;
      data += actual;
      length -= actual;
      
      if (!length)
        break;
    }
      
    return nread;
  }
  
  /*
   * This is a special procedure when reading a set amount
   * of data, less than or equal to N, beginning from an empty buffer.
   *
   * An empty buffer always starts filling at 0, guaranteeing no slicing.
   *
   * The data is valid until the next call to a member function.
   */
  const uint8_t *read(std::size_t length)
  {
    assert (length);
    assert (length <= N);
    assert (in == length);
    assert (out == 0);
    
    in = 0;
    bufEmpty = true;
    
    return buf.data();
  }
  
  // /*
   // * This is a special procedure when producing a set amount
   // * of data, less than or equal to N, beginning from an empty buffer.
   // */
  // void produceFixed(const uint8_t *data, std::size_t length)
  // {
    // assert (length);
    // assert (length <= N);
    // assert (in == 0);
    // assert (out == 0);
 
    // std::copy(data, data + length, buf.data());

    // in = length % N;
    // empty = false;
  // }

/*
  void produce()
  {
    bool producerFatigue = false;
    while (!producerFatigue && !full()) {
      if (!produce())
        producerFatigue = true;
    }
  }

  void consume()
  {
    bool consumerFatigue = false;
    while (!consumerFatigue && !empty()) {
      if (!consume())
        consumerFatigue = true;
    }
  }*/

  // std::size_t write(void *user, data_producer prod)
  // {
    // std::size_t nwritten = 0;

    // while (true) {
      // auto range = writeRange();

      // std::size_t available = range.second - range.first;
      // if (!available)
        // break;

      // std::size_t ndata = prod(buf.data() + range.first, available, user);
      // if (!ndata)
        // break;
      
      // empty = false;
      
      // in = (in + ndata) % N;
      // nwritten += ndata;
    // };

    // return nwritten;
  // }

  // using data_consumer = std::size_t(*)(uint8_t *, std::size_t, void *);

  // std::size_t write(const uint8_t *data, std::size:t length)
  // {
    // std::size_t nwritten = 0;
    // while (length) {
      // auto range = writeRange();
      // std::size_t available = (std::size_t)std::distance(begin, end);
      // if (!available)
        // break;

      // std::size_t actual = std::min(available, length);
      // std::copy(data, data + actual, range.first);

      // length -= actual;
      // nwritten += actual;
      // data += actual;
    // };
    // return nwritten;
  // }
  
  // std::size_t read(const uint8_t *data, std::size:t length)
  // {
    // std::size_t nread = 0;
    // while (length) {
      // auto range = readRange();
      // std::size_t available = (std::size_t)std::distance(begin, end);
      // if (!available)
        // break;

      // std::size_t actual = std::min(available, length);
      // std::copy(range.first, range.first + actual, range.first);

      // length -= actual;
      // nread += actual;
      // data += actual;
    // };
    // return nread;
  // }
};
