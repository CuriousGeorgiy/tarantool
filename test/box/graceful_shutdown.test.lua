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

--guest can have some of these privileges
_, _ = pcall(function() box.schema.user.grant('guest','execute,write,read','universe') end)

_ = box.schema.space.create('counter')
_ = box.space.counter:create_index('primary')

test_run:cmd("create server remote with script='box/proxy.lua'")
test_run:cmd("start server remote")
test_run:cmd("switch remote")
_, _ = pcall(function() box.schema.user.grant('guest','execute,write,read','universe') end)
fiber = require('fiber')
net_box = require('net.box')
test_run:cmd("set variable def_uri to 'default.listen'")
def_con = net_box.connect(def_uri)
test_run:cmd("setopt delimiter ';'")
function check(t)
    fiber.sleep(t)
    def_con:call('box.space.counter:auto_increment', {{'sleep ' .. tostring(t)}})
end;
function exit()
    fiber.new(function()
        os.exit()
    end)
    return 'exit scheduled'
end;
test_run:cmd("setopt delimiter ''");
test_run:cmd("switch default")

test_run:cmd("set variable remote_uri to 'remote.listen'")
remote_con = net_box.connect(remote_uri)
graceful_con = net_box.connect(remote_uri)
graceful_con.space._session_settings:update('graceful_shutdown', {{'=', 'value', true}})
graceful_con:set_shutdown_handler(function() box.space.counter:auto_increment{'shutdown receive'} end)
for time = 1.5, 10, 3 do remote_con:call('check', {time}, {is_async=true}) end

-- Default on_shutdown triggers timeout == 3, but we sets it
-- here directly to make test clear
box.ctl.set_on_shutdown_timeout(3)
fiber.sleep(0.1)
remote_con:call('exit')
fiber.sleep(0.1)
net_box.connect(remote_uri).state
remote_con:ping()
graceful_con:ping()
graceful_con:shutdown()
graceful_con:ping()

fiber.sleep(4)
box.space.counter:select()
box.space.counter:truncate()
graceful_con:set_shutdown_handler(function() end)
test_run:cmd("stop server remote")

---------------------------------------------------------------
-- Server should stop when all sessions ended and all graceful
-- connections sent shutdown
---------------------------------------------------------------

test_run:cmd("start server remote")
test_run:cmd("switch remote")
fiber = require('fiber')
net_box = require('net.box')
test_run:cmd("set variable def_uri to 'default.listen'")
def_con = net_box.connect(def_uri)
test_run:cmd("setopt delimiter ';'")
_ = fiber.new(function()
    while true do
        fiber.sleep(2)
        def_con:call('box.space.counter:auto_increment', {{'remote alive'}})
    end
end);
test_run:cmd("setopt delimiter ''");

test_run:cmd("switch default")
test_run:cmd("set variable remote_uri to 'remote.listen'")
remote_con = net_box.connect(remote_uri)
graceful_con = net_box.connect(remote_uri)
graceful_con.space._session_settings:update('graceful_shutdown', {{'=', 'value', true}})
_ = remote_con:eval('fiber.sleep(1.5)', {}, {is_async=true})
_ = graceful_con:eval('os.exit()', {}, {is_async=true})
graceful_con:shutdown()
fiber.sleep(5)

box.space.counter:select()
box.space.counter:drop()
test_run:cmd("delete server remote")
box.schema.user.revoke('guest','execute,write,read','universe')
