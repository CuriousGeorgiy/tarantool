test_run = require('test_run').new()

cfg_save = {                                                            \
    replication_connect_quorum  = box.cfg.replication_connect_quorum,   \
    replication_synchro_quorum  = box.cfg.replication_synchro_quorum,   \
    replication_synchro_timeout = box.cfg.replication_synchro_timeout,  \
    replication_sync_timeout    = box.cfg.replication_sync_timeout,     \
    read_only                   = box.cfg.read_only,                    \
    election_mode               = box.cfg.election_mode,                \
}

box.cfg{                                                                \
    replication_connect_quorum      = 3,                                \
    replication_synchro_quorum      = 2,                                \
    replication_synchro_timeout     = 1000,                             \
    replication_sync_timeout        = 5,                                \
    read_only                       = false,                            \
}

box.schema.user.grant('guest', 'super')

test_run:cmd('create server replica1 with rpl_master=default,\
              script="replication/gh-6035-replica-1.lua"')
test_run:cmd('start server replica1')

test_run:cmd('create server replica2 with rpl_master=default,\
              script="replication/gh-6035-replica-2.lua"')
test_run:cmd('start server replica2')

test_run:cmd('create server replica3 with rpl_master=default,\
              script="replication/gh-6035-replica-3.lua"')
test_run:cmd('start server replica3')

--
-- Prepare RAFT states.
test_run:switch('default')
box.cfg{election_mode = 'candidate'}

test_run:switch('replica1')
box.cfg{election_mode = 'voter'}

test_run:switch('replica2')
box.cfg{election_mode = 'voter'}

test_run:switch('replica2')
box.cfg{election_mode = 'voter'}

--
-- Cleanup.
test_run:switch('default')
test_run:cmd('stop server replica1')
test_run:cmd('delete server replica1')
test_run:cmd('stop server replica2')
test_run:cmd('delete server replica2')
test_run:cmd('stop server replica3')
test_run:cmd('delete server replica3')

--
-- Restore settings.
box.schema.user.revoke('guest', 'super')
box.cfg.replication_connect_quorum = cfg_save.replication_connect_quorum
box.cfg.replication_synchro_quorum = cfg_save.replication_synchro_quorum
box.cfg.replication_synchro_timeout = cfg_save.replication_synchro_timeout
box.cfg.read_only = cfg_save.read_only
box.cfg.election_mode = cfg_save.election_mode

----
---- Instance 1.
----
---- Step 1.
--box.cfg{
--    listen = 3313,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315', 'localhost:3316'},
--    replication_connect_quorum = 3,
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    read_only = false,
--    election_mode = 'candidate',
--}
--
---- Step 5.
--box.schema.user.grant('guest', 'super')
--box.schema.create_space('async')
--_ = box.space.async:create_index('pk')
--box.schema.create_space('sync', {is_sync = true})
--_ = box.space.sync:create_index('pk')
--
---- Step 11.
--box.cfg{replication_synchro_quorum = 1}
--box.ctl.wait_rw()
--
---- Step 12.
--box.cfg{replication_synchro_quorum = 2}
--require('fiber').create(function() box.space.sync:replace{1} end)
---- Wait WAL write.
--os.exit(0)
--
---- Step 16.
---- Restart.
--box.cfg{
--    listen = 3313,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315'},
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    election_mode = 'manual',
--}
--
---- Step 18.
--box.cfg{replication_synchro_quorum = 1}
--box.cfg{election_mode = 'candidate'}
--
--
--
--
----
---- Instance 2.
----
---- Step 2.
--box.cfg{
--    listen = 3314,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315', 'localhost:3316'},
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    read_only = true,
--    election_mode = 'voter',
--}
--
---- Step 7.
--os.exit(0)
--
---- Step 13.
--box.cfg{
--    listen = 3314,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315'},
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    election_mode = 'voter',
--}
--
---- Step 15.
--box.cfg{election_mode = 'manual'}
--box.ctl.promote()
--
---- Step 17.
---- Resign.
--box.cfg{election_mode = 'voter'}
--
--
--
--
--
----
---- Instance 3.
----
---- Step 3.
--box.cfg{
--    listen = 3315,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315', 'localhost:3316'},
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    read_only = true,
--    election_mode = 'voter',
--}
--
---- Step 8.
--os.exit(0)
--
---- Step 14.
--box.cfg{
--    listen = 3315,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315'},
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    election_mode = 'voter',
--}
--
--
--
--
----
---- Instance 4.
----
---- Step 4.
--box.cfg{
--    listen = 3316,
--    replication = {'localhost:3313', 'localhost:3314', 'localhost:3315', 'localhost:3316'},
--    replication_connect_quorum = 3,
--    replication_synchro_quorum = 2,
--    replication_synchro_timeout = 1000,
--    replication_sync_timeout = 5,
--    read_only = true,
--    election_mode = 'voter',
--}
--
---- Step 6.
--box.cfg{read_only = false, election_mode = 'manual'}
--box.ctl.promote()
--
---- Step 9.
--box.space.async:replace{1}
---- Wait replication to instance 1.
--
---- Step 10.
--os.exit(0)
