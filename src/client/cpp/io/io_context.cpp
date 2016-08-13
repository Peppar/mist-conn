// #include <algorithm>
#include <cassert>
#include <cstddef>
#include <list>
#include <memory>
#include <string>
#include <vector>

// For debugging
#include <iostream> 

#include <prio.h>
#include <prtpool.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "error/mist.hpp"
#include "error/nss.hpp"
#include "memory/nss.hpp"

#include "io/io_context.hpp"

namespace mist
{
namespace io
{

/*
 * Timeout
 */
Timeout::Timeout(PRIntervalTime interval, std::function<void()> callback)
  : interval(interval), callback(std::move(callback))
{
  established = PR_IntervalNow();
}

/*
 * IOContext
 */
IOContext::IOContext()
  : _signalEvent(to_unique<PRFileDesc>()),
    _threadPool(to_unique<PRThreadPool>())
{
  _signalEvent = to_unique(PR_NewPollableEvent(), [](PRFileDesc *p) {
    PR_DestroyPollableEvent(p);
  });
  if (!_signalEvent)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to create signal event"));
  
  _threadPool = to_unique(PR_CreateThreadPool(initialThreadCount,
                                              maxThreadCount, 0));
  if (!_threadPool)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to create thread pool"));
}

/* Forces the eventLoop to wake up */
void
IOContext::signal()
{
  if (PR_SetPollableEvent(_signalEvent.get()) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to signal write"));
}

void
IOContext::addDescriptor(std::shared_ptr<FileDescriptor> descriptor)
{
  _descriptors.emplace_back(std::move(descriptor));
}

/* Set a timeout (in milliseconds) */
void
IOContext::setTimeout(unsigned int interval, job_callback callback)
{
  _timeouts.emplace_back(PR_MillisecondsToInterval(interval), callback);
}

PRJob *
IOContext::queueJob(job_callback callback)
{
  /* We juggle memory here assuming that all jobs will run eventually */
  job_callback *outsideArg = new job_callback(callback);

  PRJob *job = PR_QueueJob(_threadPool.get(),
    [](void *insideArg)
  {
    std::unique_ptr<job_callback> insideCb
      (reinterpret_cast<job_callback*>(insideArg));
    
    (*insideCb)();
  }, reinterpret_cast<void*>(outsideArg), PR_TRUE);

  if (!job)
    BOOST_THROW_EXCEPTION(boost::system::system_error(
      make_mist_error(MIST_ERR_ASSERTION), "Unable to queue job"));
      
  return job;
}

/* Wait for one round of I/O events and process them.
   Timeout in milliseconds */
void
IOContext::ioStep(unsigned int maxTimeout)
{
  /* Prepare the poll descriptor structures */
  std::vector<PRPollDesc> pds;
  {
    pds.reserve(1 + _descriptors.size());

    /* Add the write event */
    pds.push_back(PRPollDesc{_signalEvent.get(), PR_POLL_READ, 0});

    /* Add the descriptors */
    for (auto i = _descriptors.begin(); i != _descriptors.end(); ) {
      boost::optional<PRInt16> inFlags = (*i)->inFlags();
      if (inFlags) {
        pds.push_back(PRPollDesc{(*i)->fileDesc(), *inFlags, 0});
        ++i;
      } else {
        i = _descriptors.erase(i);
      }
    }
  }

  /* Determine minimum timeout */
  PRIntervalTime timeoutInterval
    = PR_MillisecondsToInterval(maxTimeout);
  {
    PRIntervalTime now = PR_IntervalNow();
    for (auto &timeout : _timeouts) {
      PRIntervalTime elapsedSince
        = static_cast<PRIntervalTime>(now - timeout.established);
      if (elapsedSince > timeout.interval) {
        /* Timeout already expired */
        timeoutInterval = PR_INTERVAL_NO_WAIT;
        break;
      } else if (timeout.interval - elapsedSince < timeoutInterval) {
        /* This is the nearest timeout so far */
        timeoutInterval = timeout.interval - elapsedSince;
      }
    }
  }

  {
    auto time = PR_IntervalToMilliseconds(timeoutInterval);
    std::cerr << "Timeout interval is " << time << " ms" << std::endl;
  }

  /* Poll */
  bool pdsValid = true;
  {
    PRInt32 n = PR_Poll(pds.data(), pds.size(), timeoutInterval);
    if (n == -1) {
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION), "Poll failed"));
    } else if (!n) {
      /* Timeout */
      std::cerr << "Timeout" << std::endl;
      pdsValid = false;
    }
  }

  /* Handle the resulting flags from the poll descriptors */
  if (pdsValid) {
    auto j = pds.begin();

    /* Handle signalEvent */
    {
      if (j->out_flags & PR_POLL_READ) {
        std::cerr << "signalEvent!" << std::endl;
        if (PR_WaitForPollableEvent(_signalEvent.get()) != PR_SUCCESS)
          BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
            "Unable to wait for signalEvent"));
      }

      ++j;
    }

    /* Handle the remaining descriptors */
    for (auto i = _descriptors.begin(); j != pds.end(); ++i, ++j) {
      if (j->out_flags) {
        // PR_QueueJob
        (*i)->process(j->in_flags, j->out_flags);
      }
    }
  }

  /* Handle timeouts */
  {
    PRIntervalTime now = PR_IntervalNow();
    for (auto i = _timeouts.begin(); i != _timeouts.end(); ) {
      PRIntervalTime elapsedSince
        = static_cast<PRIntervalTime>(now - i->established);
      if (elapsedSince > i->interval) {
        // PR_QueueJob
        i->callback();
        i = _timeouts.erase(i);
      } else {
        ++i;
      }
    }
  }
}

void
IOContext::exec()
{
  unsigned int timeout = 10000;
  while(1)
    ioStep(timeout);
}

} // namespace io
} // namespace mist
