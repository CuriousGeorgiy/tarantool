--
-- gh-5447: Test for box.info.replication[n].downstream.lag.
-- We need to be sure that if replica start been back of
-- master node reports own lagging and cluster admin would
-- be able to detect such situation.
--

fiber = require('fiber')
test_run = require('test_run').new()
engine = test_run:get_cfg('engine')

box.schema.user.grant('guest', 'replication')

test_run:cmd('create server replica with rpl_master=default, \
             script="replication/replica.lua"')
test_run:cmd('start server replica')

s = box.schema.space.create('test', {engine = engine})
_ = s:create_index('pk')

--
-- The replica should wait some time (wal delay is 1 second
-- by default) so we would be able to detect the lag, since
-- on local instances the lag is minimal and usually transactions
-- are handled instantly.
test_run:switch('replica')
box.error.injection.set("ERRINJ_WAL_DELAY", true)

test_run:switch('default')
box.space.test:insert({1})
test_run:wait_cond(function() return box.info.replication[2].downstream.lag ~= 0 end, 10)

test_run:switch('replica')
box.error.injection.set("ERRINJ_WAL_DELAY", false)
--
-- Cleanup everything.
test_run:switch('default')

test_run:cmd('stop server replica')
test_run:cmd('cleanup server replica')
test_run:cmd('delete server replica')
