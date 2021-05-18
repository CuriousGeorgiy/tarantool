local SOCKET_DIR = require('fio').cwd()

local function unix_socket(name)
    return SOCKET_DIR .. "/" .. name .. '.sock';
end

repl_list = {
    unix_socket("gh6035master"),
    unix_socket("gh6035replica1"),
    unix_socket("gh6035replica2"),
    unix_socket("gh6035replica3"),
}

require('console').listen(os.getenv('ADMIN'))

box.cfg({
    listen                      = unix_socket("gh6035replica3"),
    replication                 = repl_list,
    replication_connect_quorum  = 3,
    replication_synchro_quorum  = 2,
    replication_synchro_timeout = 1000,
    replication_sync_timeout    = 5,
    read_only                   = true,
    election_mode               = 'voter',
})
