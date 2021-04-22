#!/usr/bin/env tarantool
local os = require('os')

box.cfg{
    listen              = os.getenv("LISTEN"),
    memtx_memory        = 107374182,
    pid_file            = "tarantool.pid",
    iproto_threads      = 10,
    wal_max_size        = 2500
}
box.schema.user.grant("guest", "read,write,execute,create,drop", "universe", nil, {if_not_exists = true})
require('console').listen(os.getenv('ADMIN'))