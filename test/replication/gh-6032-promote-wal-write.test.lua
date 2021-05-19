test_run = require('test_run').new()
fiber = require('fiber')

replication_synchro_timeout = box.cfg.replication_synchro_timeout
box.cfg{\
    replication_synchro_timeout = 0.001,\
}

_ = box.schema.create_space('sync', {is_sync = true}):create_index('pk')

box.error.injection.set('ERRINJ_WAL_DELAY', true)
_ = fiber.create(function() box.space.sync:replace{1} end)
ok, err = nil, nil

-- Test that the fiber actually waits for a WAL write to happen.
f = fiber.create(function() ok, err = pcall(box.ctl.promote) end)
fiber.sleep(0.1)
f:status()
box.error.injection.set('ERRINJ_WAL_DELAY', false)
test_run:wait_cond(function() return f:status() == 'dead' end)
ok
err

box.error.injection.set('ERRINJ_WAL_DELAY', true)
_ = fiber.create(function() box.space.sync:replace{2} end)

-- Test that the fiber is cancellable.
f = fiber.create(function() ok, err = pcall(box.ctl.promote) end)
fiber.sleep(0.1)
f:status()
f:cancel()
test_run:wait_cond(function() return f:status() == 'dead' end)
ok
err

-- Cleanup.
box.error.injection.set('ERRINJ_WAL_DELAY', false)
box.cfg{\
    replication_synchro_timeout = replication_synchro_timeout,\
}
box.space.sync:drop()
