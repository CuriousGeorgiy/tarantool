net_box = require('net.box')
fiber = require('fiber')
env = require('test_run')
test_run = env.new()

------------------------------------------------------------
-- When receiving a shutdown signal server
-- should stop accept new connections,
-- close for read existing not graceful connections
-- and do some work before the shutdown is complete
------------------------------------------------------------

box.schema.user.grant('guest','execute,write,read','universe', nil, {if_not_exists = true})

_ = box.schema.space.create('counter')
_ = box.space.counter:create_index('primary')

test_run:cmd("create server remote with script='box/graceful_shutdown.lua'")
test_run:cmd("start server remote")
test_run:cmd("switch remote")
fiber = require('fiber')
function exit() fiber.new(function() os.exit() end) return 'exit scheduled' end
net_box = require('net.box')
test_run:cmd("set variable def_uri to 'default.listen'")
def_con = net_box.connect(def_uri)
test_run:cmd("setopt delimiter ';'")
function check(t)
    fiber.sleep(t)
    def_con:call('box.space.counter:auto_increment',
                 {{'sleep ' .. tostring(t)}})
end;
test_run:cmd("switch default");

test_run:cmd("set variable remote_uri to 'remote.listen'");
remote_con = net_box.connect(remote_uri);
remote_con:set_shutdown_handler(function()
    box.space.counter:auto_increment{'unreachable'}
end);
graceful_con = net_box.connect(remote_uri);
graceful_con.space._session_settings:update('graceful_shutdown',
                                            {{'=', 'value', true}});
graceful_con:set_shutdown_handler(function()
    box.space.counter:auto_increment{'shutdown receive'}
end);
for time = 1.5, 10, 3 do
    remote_con:call('check', {time}, {is_async=true})
end;
test_run:cmd("setopt delimiter ''");

fiber.sleep(0.1)
remote_con:call('exit')
fiber.sleep(0.1)
net_box.connect(remote_uri).state
remote_con:ping()
graceful_con:ping()
graceful_con:shutdown()
graceful_con:ping()

fiber.sleep(5)
box.space.counter:select()
box.space.counter:drop()
test_run:cmd("stop server remote")

---------------------------------------------------------------
-- Every graceful connection has only his shutdown handler.
---------------------------------------------------------------

test_run:cmd("start server remote")
test_run:cmd("switch remote")
fiber = require('fiber')
function exit() fiber.new(function() os.exit() end) return 'exit scheduled' end
test_run:cmd("switch default")
test_run:cmd("set variable remote_uri to 'remote.listen'")
graceful_cons = {}
cons = {}
counter = 0
test_run:cmd("setopt delimiter ';'")
for i=1,100 do
    graceful_cons[i] = net_box.connect(remote_uri)
    cons[i] = net_box.connect(remote_uri)
    graceful_cons[i].space._session_settings:update('graceful_shutdown',
                                                    {{'=', 'value', true}})
    graceful_cons[i]:set_shutdown_handler(function() counter = counter + i end)
    cons[i]:set_shutdown_handler(function() counter = counter + i end)
end;
test_run:cmd("setopt delimiter ''");
net_box.connect(remote_uri):call('exit')
fiber.sleep(1)
counter
test_run:cmd("delete server remote")
box.schema.user.revoke('guest','execute,write,read','universe')
