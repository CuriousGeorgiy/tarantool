-- clock.lua -- internal file
local clock = {}
local ffi = require('ffi')

local C = ffi.C

clock.realtime = C.clock_realtime
clock.monotonic = C.clock_monotonic
clock.proc = C.clock_process
clock.thread = C.clock_thread

clock.realtime64 = C.clock_realtime64
clock.monotonic64 = C.clock_monotonic64
clock.proc64 = C.clock_process64
clock.thread64 = C.clock_thread64

clock.time = clock.realtime
clock.time64 = clock.realtime64

clock.bench = function(fun, ...)
    local overhead = clock.proc()
    overhead = clock.proc() - overhead
    local start_time = clock.proc()
    local res = {0, fun(...)}
    res[1] = clock.proc() - start_time - overhead, res
    return res
end

return clock
