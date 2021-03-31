#!/usr/bin/env python

import collections
import crc32c
import ctypes as ct
import json
import os
import select
import socket
import string
import sys
import time

PDU_TYPE_IC_REQ = 0x00
PDU_TYPE_IC_RESP = 0x01
PDU_TYPE_H2C_TERM_REQ = 0x02
PDU_TYPE_C2H_TERM_REQ = 0x03
PDU_TYPE_CAPSULE_CMD = 0x04
PDU_TYPE_CAPSULE_RESP = 0x05
PDU_TYPE_H2C_DATA = 0x06
PDU_TYPE_C2H_DATA = 0x07
PDU_TYPE_R2T = 0x09

PDU_FLAGS_HDGSTF = 1 << 0
PDU_FLAGS_DDGSTF = 1 << 1


class Config:
    def __init__(self, align, hdgst, ddgst, timeout):
        self.align = (align + 1) * 4
        self.hdgst = hdgst
        self.ddgst = ddgst
        self.timeout = timeout

    def __str__(self):
        return (f'align: {self.align}, hdgst: {self.hdgst}, ' +
                f'ddgst: {self.ddgst}, timeout: {self.timeout}')


class PDU(ct.Structure):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.common.pdu_type = self._pdu_type

    def __eq__(self, other):
        for fname, ftype, *_ in self._fields_:
            v1, v2 = getattr(self, fname), getattr(other, fname)
            if issubclass(ftype, ct.Array):
                v1, v2 = list(v1), list(v2)
            if v1 != v2:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def flags(self):
        flags = 0
        if self.config.hdgst:
            flags |= (self._supported_flags & PDU_FLAGS_HDGSTF)
        if self.config.ddgst:
            flags |= (self._supported_flags & PDU_FLAGS_HDGSTF)
        return flags

    def has_hdgst(self):
        return self.flags() & PDU_FLAGS_HDGSTF

    def has_ddgst(self):
        return self.flags() & PDU_FLAGS_DDGSTF

    def headlen(self):
        # We treat everything up to the start of the data as the header
        if self.data is not None:
            return self.common.pdo
        else:
            return self._size + self.has_hdgst() * 4

    def datalen(self):
        if self.data is not None:
            return len(self.data) + self.has_ddgst() * 4
        else:
            return None

    @classmethod
    def create(cls, config, flags=0, data=None, *args, **kwargs):
        obj = cls(config, *args, **kwargs)
        if data is not None:
            remainder = (cls._size + obj.has_hdgst() * 4) % config.align
            padlen = config.align - remainder if remainder > 0 else 0
        else:
            padlen = 0

        class _PDU(cls):
            _pack_ = 1
            _fields_ = [('hdgst', ct.c_uint32)] if obj.has_hdgst() else [] + [
                        ('pad', ct.c_uint8 * padlen)]

        obj = _PDU(config, *args, **kwargs)
        return obj, obj._build(config, flags, data)

    def _build(self, config, flags, data):
        self.data = data
        self.common.flags |= self.flags() | flags
        self.common.hlen = ct.sizeof(self.common) + ct.sizeof(self.psh)
        psh_size = ct.sizeof(self.psh)
        ct.memmove(self.psh, os.urandom(psh_size), psh_size)

        if data is not None:
            self.common.pdo = ct.sizeof(self)
            self.common.plen = self.common.pdo + len(data)
        else:
            self.common.pdo = 0
            self.common.plen = self.common.hlen + self.has_hdgst() * 4

        result = bytes(self)
        if self.has_hdgst():
            self.common.hdgst = ct.c_uint32(crc32c.crc32c(result))
        if data is not None:
            result += bytes(data)
            if self.has_ddgst():
                result += bytes(ct.c_uint32(crc32c.crc32c(data)))

        return result


class CommonPDUHeader(PDU):
    _size = 8
    _pack_ = 1
    _fields_ = [('pdu_type', ct.c_uint8),
                ('flags', ct.c_uint8),
                ('hlen', ct.c_uint8),
                ('pdo', ct.c_uint8),
                ('plen', ct.c_uint32)]


def define_pdu(pdu_type, size, flags=0):
    class _PDU(PDU):
        _pdu_type = pdu_type
        _supported_flags = flags
        _size = size
        _pack_ = 1
        _fields_ = [('common', CommonPDUHeader),
                    ('psh', ct.c_uint8 * (size - ct.sizeof(CommonPDUHeader)))]
    return _PDU


TCPICReq = define_pdu(PDU_TYPE_IC_REQ, 128)
TCPICResp = define_pdu(PDU_TYPE_IC_RESP, 128)
TCPH2CTermReq = define_pdu(PDU_TYPE_H2C_TERM_REQ, 24)
TCPC2HTermReq = define_pdu(PDU_TYPE_C2H_TERM_REQ, 24)
TCPCapsuleCmd = define_pdu(PDU_TYPE_CAPSULE_CMD, 72, PDU_FLAGS_HDGSTF |
                           PDU_FLAGS_DDGSTF)
TCPCapsueResp = define_pdu(PDU_TYPE_CAPSULE_RESP, 24, PDU_FLAGS_HDGSTF)
TCPH2CData = define_pdu(PDU_TYPE_H2C_DATA, 24, PDU_FLAGS_HDGSTF |
                        PDU_FLAGS_DDGSTF)
TCPC2HData = define_pdu(PDU_TYPE_C2H_DATA, 24, PDU_FLAGS_HDGSTF |
                        PDU_FLAGS_DDGSTF)
TCPR2T = define_pdu(PDU_TYPE_R2T, 24, PDU_FLAGS_HDGSTF)


class Client:
    def __init__(self, addr):
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addr = addr

    def __enter__(self):
        self.ssock.connect(self.addr)
        self.csock.connect(self.addr)
        self.dsock.connect(self.addr)
        self.csock.settimeout(1)
        self.dsock.settimeout(1)
        return self

    def __exit__(self, *args, **kwargs):
        self.ssock.close()
        self.csock.close()
        self.dsock.close()

    def _ready(self, sock):
        return len(select.select([sock], [], [], 0)[0]) > 0

    def data_ready(self):
        return self._ready(self.dsock)

    def ctrl_ready(self):
        return self._ready(self.csock)

    def send(self, data):
        self.ssock.sendall(data)

    def _recv(self, sock, size):
        data = bytearray()
        while len(data) < size:
            curr = sock.recv(size - len(data))
            if len(curr) == 0:
                raise IOError('Connection closed')
            data += curr
        return data

    def recv_data(self, size):
        return self._recv(self.dsock, size)

    def recv_ctrl(self, size):
        return self._recv(self.csock, size)


def test_ctrl_request(client, config, PDUType):
    # Sunny path test, send whole request with no data at once
    req, payload = PDUType.create(config, 0, None)
    client.send(payload)
    resp = client.recv_ctrl(len(payload))
    assert resp == payload

    # Do it again to make sure everything is still working
    req, payload = PDUType.create(config, 0, None)
    client.send(payload)
    resp = client.recv_ctrl(len(payload))
    assert resp == payload

    # Send a request in two chunks with the first chunk not containing
    # complete  PDU header
    req, payload = PDUType.create(config, 0, None)
    client.send(payload[:4])
    # Sleep to avoid the chunks being coalesced
    time.sleep(config.timeout)
    client.send(payload[4:])
    resp = client.recv_ctrl(len(payload))
    assert resp == payload

    # Put multiple requests at once
    payload = bytes()
    for i in range(10):
        req, _payload = PDUType.create(config, 0, None)
        payload += _payload

    client.send(payload)
    resp = client.recv_ctrl(len(payload))
    assert resp == payload

    # Do the same but split the payload into several buffers
    for pkt_size in [req.headlen() // 2, req.headlen() // 3,
                     req.headlen() + req.headlen() // 2]:
        for off in range(0, len(payload), pkt_size):
            client.send(payload[off:off + pkt_size])
            # Sleep to avoid the chunks being coalesced
            time.sleep(config.timeout)

        resp = client.recv_ctrl(len(payload))
        assert resp == payload


def test_data_request(client, config, PDUType):
    # Send a single request with the data attached to it
    data = os.urandom(100)
    req, payload = PDUType.create(config, 0, data)
    client.send(payload)
    resp_ctrl = client.recv_ctrl(req.headlen())
    resp_data = client.recv_data(req.datalen())
    assert resp_ctrl == bytes(req)
    assert resp_data == data

    # Send several requests at once
    payload = bytes()
    requests = []
    num_requests, data_len = 10, 100
    for i in range(num_requests):
        data = os.urandom(data_len)
        req, _payload = PDUType.create(config, 0, data)
        requests.append((req, data))
        payload += _payload
    client.send(payload)
    resp_ctrl = client.recv_ctrl(req.headlen() * num_requests)
    resp_data = client.recv_data(data_len * num_requests)
    for i, (req, data) in enumerate(requests):
        coff, doff = i * req.headlen(), i * data_len
        assert resp_ctrl[coff:coff + req.headlen()] == bytes(req)
        assert resp_data[doff:doff + data_len] == data

    # Split the request into multiple smaller ones
    data = os.urandom(100)
    req, payload = PDUType.create(config, 0, data)
    for pkt_size in [10, 32, 68]:
        for off in range(0, len(payload), pkt_size):
            client.send(payload[off:off + pkt_size])
            # Sleep to avoid the chunks being coalesced
            time.sleep(config.timeout)

        resp_ctrl = client.recv_ctrl(req.headlen())
        resp_data = client.recv_data(req.datalen())
        assert resp_ctrl == bytes(req)
        assert resp_data == data

    # Send a larger data buffer
    data = os.urandom(128 * 1024)
    req, payload = PDUType.create(config, 0, data)
    client.send(payload)
    resp_ctrl = client.recv_ctrl(req.headlen())
    resp_data = client.recv_data(req.datalen())
    assert resp_ctrl == bytes(req)
    assert resp_data == data


def test_icreq(client, config):
    test_ctrl_request(client, config, TCPICReq)


def test_icresp(client, config):
    test_ctrl_request(client, config, TCPICResp)


def test_h2ctermreq(client, config):
    test_ctrl_request(client, config, TCPH2CTermReq)


def test_c2htermreq(client, config):
    test_ctrl_request(client, config, TCPC2HTermReq)


def test_capsulecmd(client, config):
    test_data_request(client, config, TCPCapsuleCmd)


def test_capsuleresp(client, config):
    test_ctrl_request(client, config, TCPCapsueResp)


def test_h2cdata(client, config):
    test_data_request(client, config, TCPH2CData)


def test_c2hdata(client, config):
    test_data_request(client, config, TCPC2HData)


def test_r2t(client, config):
    test_ctrl_request(client, config, TCPR2T)


def run_test(fn, client, *args, **kwargs):
    sys.stdout.write(f'Running {fn.__name__}... ')
    sys.stdout.flush()

    # Make sure that there's no data left in the sockets between the tests
    assert not client.ctrl_ready()
    assert not client.data_ready()

    fn(client, *args, **kwargs)
    sys.stdout.write('OK\n')
    sys.stdout.flush()


def main(args):
    configs = [
        Config(align=0, hdgst=False, ddgst=False, timeout=0.1),
        Config(align=0, hdgst=True, ddgst=False, timeout=0.1),
        Config(align=2, hdgst=False, ddgst=False, timeout=0.1),
        Config(align=2, hdgst=True, ddgst=False, timeout=0.1),
        Config(align=2, hdgst=True, ddgst=True, timeout=0.1),
        Config(align=0, hdgst=False, ddgst=False, timeout=0),
        Config(align=0, hdgst=True, ddgst=False, timeout=0),
        Config(align=2, hdgst=False, ddgst=False, timeout=0),
        Config(align=2, hdgst=True, ddgst=False, timeout=0),
        Config(align=2, hdgst=True, ddgst=True, timeout=0)]

    tests = [
        test_icreq, test_icresp, test_h2ctermreq, test_c2htermreq,
        test_capsulecmd, test_capsuleresp, test_h2cdata, test_c2hdata,
        test_r2t]

    with Client(('127.0.0.1', int(args[0], 10))) as client:
        # Sleep for a second here to allow the target to setup and attach the
        # BPF programs to the sockets
        time.sleep(1)
        for config in configs:
            print('=' * 80)
            print(f'{config}'.center(80))
            print('=' * 80)
            for tc in tests:
                run_test(tc, client, config)


if __name__ == '__main__':
    main(sys.argv[1:])
