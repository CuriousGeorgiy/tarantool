test_run = require('test_run').new()
log = require('log')
fiber = require('fiber')

SERVERS = {                 \
    'gh6035master',         \
    'gh6035replica1',       \
    'gh6035replica2',       \
    'gh6035replica3'        \
}

test_run:create_cluster(SERVERS, "replication")
test_run:wait_fullmesh(SERVERS)

--
-- Make sure master node is a RAFT leader.
test_run:switch('gh6035master')
test_run:wait_cond(function() return box.info().election.state == 'leader' end, 10)

-- Create spaces needed.
_ = box.schema.create_space('async')
_ = box.space.async:create_index('pk')
_ = box.schema.create_space('sync', {is_sync = true})
_ = box.space.sync:create_index('pk')

--
-- Now force make replica3 being a leader.
test_run:switch('gh6035replica3')
box.cfg{read_only = false, election_mode = 'manual'}
box.ctl.promote()
test_run:wait_cond(function() return box.info().election.state == 'leader' end, 10)

--
-- Stop replica1 and replica2.
test_run:switch('default')
test_run:cmd('stop server gh6035replica1')
test_run:cmd('stop server gh6035replica2')

--
-- Insert data into async space on replica3 (which is leader now).
test_run:switch('gh6035replica3')
box.space.async:replace{1}
-- And wait its replication to complete on the master node
test_run:switch('gh6035master')
test_run:wait_cond(function() return box.space.async:select{}[1] ~= nil \
                   and box.space.async:select{}[1][1] == 1 end, 10)

--
-- And stop this leader (only the master node remains up).
test_run:switch('default')
test_run:cmd('stop server gh6035replica3')
test_run:cmd('delete server gh6035replica3')

--
-- On master node update quorum so we can write
-- to the database again, we're sole node up and
-- running.
test_run:switch('gh6035master')
box.cfg{replication_synchro_quorum = 1}
box.ctl.wait_rw()

old_lsn = box.info.lsn
box.cfg{replication_synchro_quorum = 2}
require('fiber').create(function() box.space.sync:replace{1} end)

--
-- Wait the write to reach WAL, since master node is only
-- once node alive here at this moment, it won't gather quorum
-- for this write and won't issue CONFIRM because only the
-- master node is up and running at this moment.
test_run:wait_cond(function() return box.info.lsn > old_lsn end, 10)

--
-- Stop master, it has unconfirmed (but not rolled back) record.
test_run:switch('default')
test_run:cmd('stop server gh6035master')

--
-- No active nodes at this point. Now restart replica1 and replica2
-- without replica3 in configs and master node stopped.
test_run:switch('default')
test_run:cmd('start server gh6035replica1 with args="true"')
test_run:cmd('start server gh6035replica2 with args="true"')

--
-- While master is down make sure the replicas are
-- connected between each other.
test_run:switch('gh6035replica2')
test_run:wait_upstream(test_run:get_server_id('gh6035replica1'), {status = 'follow'})
test_run:switch('gh6035replica1')
test_run:wait_upstream(test_run:get_server_id('gh6035replica2'), {status = 'follow'})

--
-- Make replica1 being a leader.
test_run:switch('gh6035replica1')
box.cfg{election_mode = 'manual'}
box.ctl.promote()
test_run:wait_cond(function() return box.info().election.state == 'leader' end, 10)

--
-- Connect master node back.
test_run:switch('default')
test_run:cmd('start server gh6035master with args="true"')

--
-- Resign replica1 and make it a plain voter back.
test_run:switch('gh6035replica1')
box.cfg{election_mode = 'voter'}

--
-- Make master node back to candidate.
test_run:switch('gh6035master')
box.cfg{replication_synchro_quorum = 1}
box.cfg{election_mode = 'candidate'}
test_run:wait_cond(function() return box.info().election.state == 'leader' end, 10)

--
-- Cleanup
test_run:switch('default')
--test_run:drop_cluster({'gh6035master', 'gh6035replica1', 'gh6035replica2'})

----
---- Instance master.
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
---- Instance replica1.
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
---- Instance replica2.
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
---- Instance replica3.
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

--
--By my idea the replica3 should generate a transaction, relay it to
--master only, then master makes a synchro transaction without
--a CONFIRM and dies.
--
--Then replica1 becomes a leader and emits PROMOTE which should rollback
--row {1} from the 'sync' space, but keep the old {1} from 'async' space.
--Then master is back and is elected a leader. Its old row sync {1} should
-- be considered outdated and turned into NOPs on the other nodes,
--while row async {1} must be applied everywhere.
--
--I thought that if the NOP filter would use applier->instance_id, it
--would nopify the async {1} too. But it didn't nopify not rolled back
--anything, and I don't know what is worse really.
--
--One of the reasons why sync {1} is not rolledback is that master
--is a leader. So when PROMOTE comes from replica1, it is simply ignored
--by !raft_is_source_allowed() in applier_apply_tx(), which should not
--happen obviously.
