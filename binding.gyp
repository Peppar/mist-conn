{
    "targets": [
      {
       "target_name": "_mist_conn",
       "cflags_cc": [ "-frtti -fexceptions -std=c++14" ],
       "defines": [
          "_BUILD_NODE_MODULE",
          "_SSIZE_T_",
          "_SSIZE_T_DEFINED",
          "ssize_t=unsigned long"
        ],
        "libraries": [
        "-lnss3",
        "-lnspr4",
        "-lplc4",
        "-lssl3",
        "-lsmime3",
        "-lnghttp2"
        ],
        "include_dirs": [
            "<!(node -e \"require('nan')\")",
            "src/client/headers",
            "deps/nspr",
            "deps/nss",
            ">(BOOST_ROOT)",
            ">(NGHTTP2_ROOT)/lib/includes",
            ">(NSS_ROOT)",
            ">(NSS_ROOT)/dist/public/nss",
            ">(NSS_ROOT)/dist/>(NSS_BUILDSTRING)/include"
        ],
        "sources": [
            "src/client/cpp/node/async.cpp",
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
            "src/client/cpp/h2/websocket.cpp",
            "src/client/cpp/io/io_context.cpp",
            "src/client/cpp/io/rdv_socket.cpp",
            "src/client/cpp/io/tcp_socket.cpp",
            "src/client/cpp/io/ssl_context.cpp",
            "src/client/cpp/io/ssl_socket.cpp",
            "src/client/cpp/tor/tor.cpp",
            "src/client/cpp/conn.cpp"
        ],
            'conditions': [
                [
                    'OS=="linux"', {
                        'variables': {
                            'BOOST_ROOT': "<!(echo $BOOST_ROOT)",
                            'NGHTTP2_ROOT': "<!(echo $NGHTTP2_ROOT)",
                            'NSS_ROOT': "<!(echo NSS_ROOT)",
                            "NSS_BUILDSTRING": "LINUX_64_DBG.OBJ"
                        },
                        "libraries+": [
                            "-lpthread",
                            "-lboost_exception",
                            "-lboost_filesystem",
                            "-lboost_random",
                            "-lboost_system",
                            "-L>(BOOST_ROOT)/stage/lib",
                            "-L>(NGHTTP2_ROOT)/lib/MSVC_obj",
                            "-L>(NSS_ROOT)/dist/>(NSS_BUILDSTRING)/lib"
                        ]
                    }
                ],
                [
                    'OS=="win"', {
                        'variables': {
                            "BOOST_ROOT": "<!(echo %BOOST_ROOT%)",
                            "BOOST_BUILDSTRING": "-vc140-mt-sgd-1_61",
                            "NGHTTP2_ROOT": "<!(echo %NGHTTP2_ROOT%)",
                            "NSS_ROOT": "<!(echo %NSS_ROOT%)",
                            "NSS_BUILDSTRING": "WIN954.0_64_DBG.OBJ"
                        },
                        "libraries+": [
                            "-llibboost_exception>(BOOST_BUILDSTRING)",
                            "-llibboost_filesystem>(BOOST_BUILDSTRING)",
                            "-llibboost_random>(BOOST_BUILDSTRING)",
                            "-llibboost_system>(BOOST_BUILDSTRING)"
                        ],
                        'msvs_settings': {
                            "VCCLCompilerTool": {
                                "AdditionalOptions": [
                                    "/EHsc"
                                ]
                            },
                            'VCLinkerTool': {
                                'AdditionalLibraryDirectories': [
                                    ">(BOOST_ROOT)/stage/lib",
                                    ">(NGHTTP2_ROOT)/lib/MSVC_obj",
                                    ">(NSS_ROOT)/dist/>(NSS_BUILDSTRING)/lib"
                                ]
                            }
                        }
                    }
                ]
            ]
        }
    ]
}

