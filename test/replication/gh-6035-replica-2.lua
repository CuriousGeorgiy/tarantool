local SOCKET_DIR = require('fio').cwd()
local noreplica3 = arg[1] or false

local function unix_socket(name)
    return SOCKET_DIR .. "/" .. name .. '.sock';
end

if noreplica3 then
    repl_list = {
        unix_socket("gh6035master"),
        unix_socket("gh6035replica1"),
        unix_socket("gh6035replica2"),
    }
else
    repl_list = {
        unix_socket("gh6035master"),
        unix_socket("gh6035replica1"),
        unix_socket("gh6035replica2"),
        unix_socket("gh6035replica3"),
    }
end

require('console').listen(os.getenv('ADMIN'))

if noreplica3 then
box.cfg({
    listen                      = unix_socket("gh6035replica2"),
    replication                 = repl_list,
    replication_connect_quorum  = 1, -- the master is down and second replica is not up yet
    replication_synchro_quorum  = 2,
    replication_synchro_timeout = 1000,
    replication_sync_timeout    = 5,
    election_mode               = 'voter',
})
else
box.cfg({
    listen                      = unix_socket("gh6035replica2"),
    replication                 = repl_list,
    replication_synchro_quorum  = 2,
    replication_synchro_timeout = 1000,
    replication_sync_timeout    = 5,
    read_only                   = true,
    election_mode               = 'voter',
})
end
