#! /usr/bin/env python


import collectd
import socket
import json
from datetime import timedelta

class NutcrackerServer( object ):
    def __init__(self):
        self.server = '127.0.0.1'
        self.port = '22222'


    def submit(self, type, instance, value, server=None):
        if server:
            plugin_instance = '%s-%s' % (self.port, server)
        else:
            plugin_instance = str(self.port)

        v = collectd.Values()
        v.plugin = self.plugin_name
        v.plugin_instance = plugin_instance
        v.type = type
        v.type_instance = instance
        v.values = [value, ]
        v.dispatch()

    def do_twemproxy_status( self ):

        conn = socket.create_connection( (self.server, self.port) )
        buf = True
        content = ''
        while buf:
            buf = conn.recv( 1024 )
            content += buf
        conn.close()
        #print "content : %s" % ( content )
        self.data = json.loads( content )

        for k in sorted( self.data.keys() ):
            try:
                v = self.data[k]
                # just to prove we are looking at a key for a backend server
                v['server_ejects']

                #dispatch([type][, values][, plugin_instance][, type_instance][, plugin][, host][, time][, interval]) -> None.
                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'client_connections'
                #metric.plugin_instance = 'client_connections'
                metric.type = 'tcp_connections'
                metric.values = [str(v['client_connections'])]
                metric.dispatch()


                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'client_eof'
                metric.type = 'derive'
                metric.values = [str(v['client_eof'])]
                metric.dispatch()


                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'forward_error'
                metric.type = 'derive'
                metric.values = [str(v['forward_error'])]
                metric.dispatch()


                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'client_err'
                metric.type = 'derive'
                metric.values = [str(v['client_err'])]
                metric.dispatch()

                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'fragments'
                metric.type = 'derive'
                metric.values = [str(v['fragments'])]
                metric.dispatch()

                metric = collectd.Values()
                metric.plugin = 'twemproxy-%s'%k
                metric.type_instance = 'server_ejects'
                metric.type = 'derive'
                metric.values = [str(v['server_ejects'])]
                metric.dispatch()

                #---
                for bk in v.keys():
                    if type(v[bk]) is dict:
                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-server_eof'%bk
                        metric.type = 'derive'
                        metric.values = [str(v[bk]['server_eof'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-server_err'%bk
                        metric.type = 'derive'
                        metric.values = [str(v[bk]['server_err'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-server_connections'%bk
                        metric.type = 'gauge'
                        metric.values = [str(v[bk]['server_connections'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-server_timedout'%bk
                        metric.type = 'derive'
                        metric.values = [str(v[bk]['server_timedout'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-responses'%bk
                        metric.type = 'counter'
                        metric.values = [str(v[bk]['responses'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-response_bytes'%bk
                        metric.type = 'total_bytes'
                        metric.values = [str(v[bk]['response_bytes'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-in_queue_bytes'%bk
                        metric.type = 'gauge'
                        metric.values = [str(v[bk]['in_queue_bytes'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-out_queue_bytes'%bk
                        metric.type = 'gauge'
                        metric.values = [str(v[bk]['out_queue_bytes'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-request_bytes'%bk
                        metric.type = 'derive'
                        metric.values = [str(v[bk]['request_bytes'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-requests'%bk
                        metric.type = 'derive'
                        metric.values = [str(v[bk]['requests'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-in_queue'%bk
                        metric.type = 'gauge'
                        metric.values = [str(v[bk]['in_queue'])]
                        metric.dispatch()

                        metric = collectd.Values()
                        metric.plugin = 'twemproxy-%s'%k
                        metric.type_instance = '%s-out_queue'%bk
                        metric.type = 'gauge'
                        metric.values = [str(v[bk]['out_queue'])]
                        metric.dispatch()
            except:
                pass


    def config(self, obj):
        for node in obj.children:
            if node.key == 'Port':
                self.port = int(node.values[0])
            elif node.key == 'Host':
                self.server = node.values[0]
            else:
                collectd.warning("twemproxy plugin: Unkown configuration key %s" % node.key)


twemproxy = NutcrackerServer()
collectd.register_config(twemproxy.config)
collectd.register_read(twemproxy.do_twemproxy_status)
