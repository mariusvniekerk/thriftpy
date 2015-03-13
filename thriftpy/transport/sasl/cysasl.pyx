# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
""" SASL transports for Thrift. """

# Copied from the Impala repo


from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
from libc.stdint cimport int32_t, uint8_t

from thriftpy.transport.cybase cimport (
    TCyBuffer,
    CyTransportBase,
    DEFAULT_BUFFER,
    STACK_STRING_LEN
)

from .. import TTransportException
import struct

cdef extern from "../../protocol/cybin/endian_port.h":
    int32_t be32toh(int32_t n)
    int32_t htobe32(int32_t n)


cdef class TCySaslTransport(CyTransportBase):

    START = 1
    OK = 2
    BAD = 3
    ERROR = 4
    COMPLETE = 5

    cdef:
        object trans
        TCyBuffer rbuf, rframe_buf, wframe_buf
        public object sasl_client_factory, mechanism, sasl


    def __init__(self, trans, sasl_client_factory, mechanism, int buf_size=DEFAULT_BUFFER):
        self.trans = trans
        self.rbuf = TCyBuffer(buf_size)
        self.rframe_buf = TCyBuffer(buf_size)
        self.wframe_buf = TCyBuffer(buf_size)
        self.sasl_client_factory = sasl_client_factory
        self.mechanism = mechanism
        self.sasl = None


    cdef read_trans(self, int sz, char *out):
        cdef int i = self.rbuf.read_trans(self.trans, sz, out)
        if i == -1:
            raise TTransportException(TTransportException.END_OF_FILE,
                                      "End of file reading from transport")
        elif i == -2:
            raise MemoryError("grow buffer fail")

    cdef write_rframe_buffer(self, const char *data, int sz):
        cdef int r = self.rframe_buf.write(sz, data)
        if r == -1:
            raise MemoryError("Write to buffer error")

    cdef c_read(self, int sz, char *out):
        if sz == 0:
            return 0

        while self.rframe_buf.data_size < sz:
            self.read_frame()

        memcpy(out, self.rframe_buf.buf + self.rframe_buf.cur, sz)
        self.rframe_buf.cur += sz
        self.rframe_buf.data_size -= sz

        return sz

    cdef c_write(self, const char *data, int sz):
        self.wframe_buf.write(sz, data)

    cdef read_frame(self):
        cdef:
            char frame_len[4]
            char stack_frame[STACK_STRING_LEN]
            char *dy_frame
            int32_t frame_size

        self.read_trans(4, frame_len)
        frame_size = be32toh((<int32_t*>frame_len)[0])

        if frame_size <= STACK_STRING_LEN:
            self.read_trans(frame_size, stack_frame)
            # Decrypt
            success, decoded = self.sasl.decode(stack_frame[:frame_size])
            if not success:
                raise TTransportException(type=TTransportException.UNKNOWN, message=self.sasl.getError())

            self.write_rframe_buffer(decoded, len(decoded))
        else:
            dy_frame = <char*>malloc(frame_size)
            try:
                self.read_trans(frame_size, dy_frame)
                # Decrypt
                success, decoded = self.sasl.decode(dy_frame[:frame_size])
                if not success:
                    raise TTransportException(type=TTransportException.UNKNOWN, message=self.sasl.getError())

                self.write_rframe_buffer(decoded, len(decoded))
            finally:
                free(dy_frame)

    cdef c_flush(self):
        cdef:
            bytes data, encoded
            char *size_str

        if self.wframe_buf.data_size > 0:
            data = self.wframe_buf.buf[:self.wframe_buf.data_size]
            success, encoded = self.sasl.encode(data)
            if not success:
                raise TTransportException(type=TTransportException.UNKNOWN, message=self.sasl.getError())
            size = htobe32(self.wframe_buf.data_size)
            size_str = <char*>(&size)

            self.trans.write(size_str[:4] + data)
            self.trans.flush()
            self.wframe_buf.clean()

    def read(self, int sz):
        return self.get_string(sz)

    def write(self, bytes data):
        cdef int sz = len(data)
        self.c_write(data, sz)

    def flush(self):
        self.c_flush()

    def is_open(self):
        return self.trans.is_open()

    cdef _recv_sasl_message(self):
        cdef:
            bytes header, payload
            int length
            uint8_t status

        header = self.trans.read(5)
        status, length = struct.unpack(">BI", header)
        if length > 0:
            payload = self.trans.read(length)
        else:
            payload = ""
        return status, payload

    cdef _send_message(self, status, bytes body):
        cdef bytes header = struct.pack(">BI", status, len(body))
        self.trans.write(header + body)
        self.trans.flush()

    def open(self):
        if not self.trans.is_open():
            self.trans.open()

        if self.sasl is not None:
              raise TTransportException(
                type=TTransportException.NOT_OPEN,
                message="Already open!")
        self.sasl = self.sasl_client_factory()

        ret, chosen_mech, initial_response = self.sasl.start(self.mechanism)
        if not ret:
          raise TTransportException(type=TTransportException.NOT_OPEN,
            message=("Could not start SASL: %s" % self.sasl.getError()))

        # Send initial response
        self._send_message(self.START, chosen_mech)
        self._send_message(self.OK, initial_response)

        # SASL negotiation loop
        while True:
            status, payload = self._recv_sasl_message()
            if status not in (self.OK, self.COMPLETE):
                raise TTransportException(type=TTransportException.NOT_OPEN,
                    message=("Bad status: %d (%s)" % (status, payload)))
            if status == self.COMPLETE:
                break
            ret, response = self.sasl.step(payload)
            if not ret:
                raise TTransportException(type=TTransportException.NOT_OPEN,
                    message=("Bad SASL result: %s" % (self.sasl.getError())))
            self._send_message(self.OK, response)


    def close(self):
        return self.trans.close()

    def clean(self):
        self.rbuf.clean()
        self.rframe_buf.clean()
        self.wframe_buf.clean()


class TCySaslTransportFactory(object):
    def get_transport(self, trans):
        return TCySaslTransport(trans)