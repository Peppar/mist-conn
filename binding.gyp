{
  "targets": [
    {
      "target_name": "mist_conn",
      "cflags_cc": [ "-frtti -fexceptions -std=c++14" ],
      "libraries": [
        "-lnss3", "-lnspr4", "-lplc4", "-lssl3", "-lsmime3",
        "-lnghttp2", "-lboost_system", "-lboost_random",
        "-lboost_filesystem", "-lpthread"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "src/client/headers",
        "/usr/include/nspr",
        "/usr/include/nss"
      ],
      "sources": [
        "src/client/cpp/node/module.cpp",
        "src/client/cpp/crypto/hash.cpp",
        "src/client/cpp/crypto/pkcs12.cpp",
        "src/client/cpp/crypto/sha3.c",
        "src/client/cpp/error/mist.cpp",
        "src/client/cpp/error/nghttp2.cpp",
        "src/client/cpp/error/nss.cpp",
        "src/client/cpp/h2/client_request.cpp",
        "src/client/cpp/h2/client_response.cpp",
        "src/client/cpp/h2/lane.cpp",
        "src/client/cpp/h2/server_request.cpp",
        "src/client/cpp/h2/server_response.cpp",
        "src/client/cpp/h2/session.cpp",
        "src/client/cpp/h2/stream.cpp",
        "src/client/cpp/h2/util.cpp",
        "src/client/cpp/io/io_context.cpp",
        "src/client/cpp/io/rdv_socket.cpp",
        "src/client/cpp/io/socket.cpp",
        "src/client/cpp/io/ssl_context.cpp",
        "src/client/cpp/io/ssl_socket.cpp",
        "src/client/cpp/tor/tor.cpp",
        "src/client/cpp/conn.cpp"
      ]
    }
  ]
}

