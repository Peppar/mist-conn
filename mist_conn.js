var _mist_conn = require("./build/Debug/_mist_conn");
var stream = require("stream");
var util = require("util")



// Writable
function _MistWritable(mistObj) {
    stream.Writable.call(this);
    this._mistObj = mistObj;
}

util.inherits(_MistWritable, stream.Writable);

_MistWritable.prototype._write = function (chunk, encoding, callback) {
    this._mistObj._write(chunk, encoding, callback)
    console.log("_write");
};

// Readable
function _MistReadable(mistObj)
{
    var self = this;
    stream.Readable.call(this);
    this._mistObj = mistObj;
    mistObj.setOnData(function (buffer) {
        console.log("onData");
        self.push(buffer);
    });
}

util.inherits(_MistReadable, stream.Readable);

_MistReadable.prototype._read = function (length) {
};

// Duplex
function _MistDuplex(mistObj)
{
    var self = this;
    stream.Duplex.call(this);
    this._mistObj = mistObj;
    mistObj.setOnData(function (buffer) {
        console.log("onData");
        self.push(buffer);
    });
}

util.inherits(_MistDuplex, stream.Duplex);

_MistDuplex.prototype._write = function (chunk, encoding, callback) {
    this._mistObj._write(chunk, encoding, callback)
    console.log("_write");
};



_mist_conn.ClientRequest.prototype.writeStream = function () {
    return new _MistWritable(this);
}

_mist_conn.ClientResponse.prototype.readStream = function () {
    return new _MistReadable(this);
}

_mist_conn.ServerRequest.prototype.readStream = function () {
    return new _MistReadable(this);
}

_mist_conn.ServerResponse.prototype.writeStream = function () {
    return new _MistWritable(this);
}



module.exports = {

    Service: _mist_conn.Service,
    Peer: _mist_conn.Peer,

    ClientStream: _mist_conn.ClientStream,
    ClientRequest: _mist_conn.ClientRequest,
    ClientResponse: _mist_conn.ClientResponse,

    ServerStream: _mist_conn.ServerStream,
    ServerRequest: _mist_conn.ServerRequest,
    ServerResponse: _mist_conn.ServerResponse,

    initializeNSS: _mist_conn.initializeNSS,
    loadPKCS12: _mist_conn.loadPKCS12,
    loadPKCS12File: _mist_conn.loadPKCS12File,
    serveDirect: _mist_conn.serveDirect,
    startServeTor: _mist_conn.startServeTor,
    onionAddress: _mist_conn.onionAddress,
    addPeer: _mist_conn.addPeer,
    connectPeerDirect: _mist_conn.connectPeerDirect,
    connectPeerTor: _mist_conn.connectPeerTor
}
