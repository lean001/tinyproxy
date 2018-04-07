#!/usr/bin/python
# -*- coding:utf-8 -*-

import json
import asyncio

MSG_MAX_LEN = 1024

METHOD_INIT = "INIT"
METHOD_PING = "PING"
METHOD_OPT = "OPT"

STATE_SUCC = "true"
STATE_FAIL = "false"

INIT_MSG = {
    "Type": 0,
    "Method": "INIT", 
    "Server": "test_server",
    "ID": "SDFSFSFGHF343FSDFS",
    "Capabilitis": [
        {
            "ID" : "sdfsdfgddg",
            "Description" : "yinxiang",
            "Level" : 5
        },{
            "ID" : "sdfsdfgdfgdegdf",
            "Description" : "reshuiqi",
            "Level" : 5
        },{
            "ID" : "sdfsdfsdfsfgddg",
            "Description" : "dianfanbao",
            "Level" : 5
        }
    ]
}

PING_MSG = {
    "Type": 0,
    "Method": METHOD_PING, 
    "Server": "测试服务器"
}
PONG_MSG = {
    "Type": 1,
    "Method": METHOD_PING, 
    "Server": "测试服务器"
}

def msg_encode(data):
    return json.JSONEncoder().encode(data)

class MsgRespond(object):
    def __init__(self):
        self._state = -1
        self._method = None
        self._data = None
    
    @property
    def state(self):
        return self._state
    
    @state.setter
    def state(self, value):
        self._state = value
        
    @property
    def msg(self):
        return self._data
    
    @msg.setter
    def msg(self, data):
        if data is None or not isinstance(data, str):
            raise ValueError('msg must be string')
        try:
            json.loads(data)
        except ValueError:
            print("%s not json format"%data)
            self._data = None
        else:
            self._data = data.encode()
            
    @property
    def method(self):
        return self._method
    
    @method.setter
    def method(self, value):
        self._method = value
    
    
    def parser(self, data):
        
        try:
            input = json.loads(data)
        except ValueError:
            print('[Error] %r not json format'%data)
            self.method = METHOD_PING
            self.msg = msg_encode(PONG_MSG)
            self.state = 0
            return
            
        try:
            self.method = input['Method']
        except KeyError:
            print('[Error] %r no method found'%data)
            self.state = -1
            return
        
        # require
        try:
            if input['Type'] == 0:
                if self.method == METHOD_PING:
                    self.msg = msg_encode(PONG_MSG)
                if self.method == METHOD_OPT:
                    pass
            else: #respond
                if self.method == METHOD_INIT:
                    if input['State'] == 'true':
                        self.state = 0
                    else:
                        self.state = -1
        except KeyError:
            pass


async def msg_handler(host=None, port=None, loop=None):
    inited = 0
    id = 0
    reader,sender = await asyncio.open_connection(host, port, loop=loop)
    while True:
        id = id + 1
        print("loop %d"%id)
        str_id = '{0}-{1}'.format(id, "test_server")
        try:
            if inited == 0:
                await asyncio.sleep(5)
                msg = INIT_MSG
                msg["MsgId"] = str_id
                data = msg_encode(msg)
                sender.write(data.encode())
                await sender.drain()
                print("init")
                
            data = await reader.read(MSG_MAX_LEN)
            print("recv msg: %r"%data)
            if len(data) == 0 or data == b'recv 0 bytes\r\n':
                break
                
            res = MsgRespond()
            res.parser(data.decode('utf-8'))
            # init until success
            if res.state == 0:
                if res.method == METHOD_INIT:
                    inited = 1
                    print("init done")
                else:
                    sender.write(res.msg)
                    await sender.drain()
        except KeyboardInterrupt:
            break
        except ConnectionResetError:
            print("server shutdown, connection lost!")
            break
    sender.close()
    
    
if __name__ == '__main__':
    print('server start')
    #server('127.0.0.1', 8888)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(msg_handler('127.0.0.1', 8888, loop))
    loop.close()
    print('server end')