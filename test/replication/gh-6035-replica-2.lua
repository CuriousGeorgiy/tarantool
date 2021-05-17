local repl_include_self = arg[1] and arg[1] == 'true' or false
local repl_list

if repl_include_self then
    repl_list = {os.getenv("MASTER"), os.getenv("LISTEN")}
else
    repl_list = os.getenv("MASTER")
end

require('console').listen(os.getenv('ADMIN'))

box.cfg{
    listen                      = os.getenv("LISTEN"),
    replication                 = repl_list,
    replication_synchro_quorum  = 2,
    replication_synchro_timeout = 1000,
    replication_sync_timeout    = 5,
    read_only                   = true,
    election_mode               = 'voter',
}
