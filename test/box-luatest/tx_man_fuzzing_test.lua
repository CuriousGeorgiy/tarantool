local cluster = require('test.luatest_helpers.cluster')
local fio = require('fio')
local json = require('json')
local key_def = require('key_def')
local t = require('luatest')
local yaml = require('yaml')

local g = t.group()

local repro_file
local serialization_file

local stmts
local ro_txs_mask
local committed_txs_mask
local bad_dml_txs_mask
local serialization

-- Number of test rounds.
local rounds_cnt = 8096

-- Total number of transactions and number of read-only transactions.
local tx_cnt = 16
local ro_tx_cnt = 6

-- Number of statements.
local stmt_cnt = 160

-- Probability of rollback.
local p_rollback = 0.05

-- Probability of commit.
local p_commit = 0.1

-- Max random unsigned key (min is 0).
local max_key = 8

-- Operation types.
local DML = 0
local DQL = 1
local TXL = 2

-- DQL operation subtypes.
local SELECT = 0
local GET = 1
local LEN = 2

-- Index types.
local TREE = 0
local HASH = 1
local BITSET = 2
local RTREE  = 3

local function dump_repro()
    --repro_file:write("os.execute('rm -rf *.snap *.xlog *.vylog 512')\n" ..
    --                 '\n' ..
    --                 "local ffi = require('ffi')\n" ..
    --                 "local json = require('json')\n" ..
    --                 "local log = require('log')\n" ..
    --                 "local txn_proxy = require('txn_proxy')\n" ..
    --                 '\n' ..
    --                 'box.cfg{memtx_use_mvcc_engine = true}\n' ..
    --                 '\n' ..
    --                 "box.schema.space.create('s')\n" ..
    --                 "box.space.s:create_index('pk', {parts = {{1, 'uint'}, \n" ..
    --                 "                                         {2, 'uint'}}})\n" ..
    --                 "box.space.s:create_index('sk', {unique = false,\n" ..
    --                 "                                parts = {{3, 'uint'}}})\n" ..
    --                 '\n')

    for _, stmt in ipairs(stmts) do
        if stmt.str == 'box.begin()' then
            --local tx_fmt = 'tx%d = txn_proxy:new()\n'
            --repro_file:write(tx_fmt:format(stmt.tid))
        end
        local stmt_fmt = "tx%d('%s') -- %s\n"
        repro_file:write(stmt_fmt:format(stmt.tid, stmt.str,
                                         json.encode(stmt.res)))
    end

    repro_file:write('\n')
    --repro_file:write('\n' ..
     --                'os.exit()\n')
end

local function dump_serialization()
    serialization_file:write("os.execute('rm -rf *.snap *.xlog *.vylog 512')\n" ..
                     '\n' ..
                     "local ffi = require('ffi')\n" ..
                     "local json = require('json')\n" ..
                     "local log = require('log')\n" ..
                     '\n' ..
                     'box.cfg{}\n' ..
                     '\n' ..
                     "box.schema.space.create('s')\n" ..
                    "box.space.s:create_index('pk', {parts = {{1, 'uint'}, \n" ..
                     "                                         {2, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk1', {type = 'HASH', \n" ..
                     "                                 parts = {{1, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk2', {type = 'BITSET', \n" ..
                     "                                 unique = false,\n" ..
                     "                                 parts = {{2, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk3', {type = 'RTREE', \n" ..
                     "                                 unique = false,\n" ..
                     "                                 parts = {{3, 'array'}}})\n" ..
                     '\n')

    for _, stmt in ipairs(serialization) do
        local stmt_fmt = "%s -- tx%d: %s\n"
        serialization_file:write(stmt_fmt:format(stmt.str, stmt.tid,
                                                 json.encode(stmt.res)))
    end

    serialization_file:write('\n' ..
                     'os.exit()\n')
end

local function tx_call(tx, operation)
    local ok, res = pcall(tx._strm.eval, tx._strm, 'return ' .. operation.str)
    table.insert(stmts, {
        tid  = tx.id,
        type = operation.type,
        str  = operation.str,
        ok   = ok,
        res  = res,
    })
    if ok and operation.type == DML then tx.ro = false end
    if not ok then
        if res.message == 'Transaction has been aborted by conflict' then
            tx:rollback()
            return ok, res
        end
        if operation.type == DML then tx.bad_dml = true end
    end
    if tx._strm._conn.state == 'error' then
        dump_repro()
        t.fail(('connection in error state: %s'):format(tx._strm._conn.error))
    end
    return ok, res
end

local function tx_begin(tx)
    t.fail_if(tx.running or tx.committed or tx.aborted,
              'internal test error: cannot start transaction')
    tx{
        tid  = tx.id,
        type = TXL,
        str  = 'box.begin()',
    }
    tx.running = true
end

local function tx_rollback(tx)
    t.fail_if(not tx.running or tx.committed or tx.aborted,
              'internal test error: cannot rollback transaction')
    local ok, res = tx{
        tid  = tx.id,
        type = TXL,
        str  = 'box.rollback()',
    }
    if not ok then t.fail('`stream:rollback` failed: ' .. res[1].error) end
    tx.running = false
    tx.aborted = true
end

local function tx_commit(tx)
    t.fail_if(not tx.running or tx.committed or tx.aborted,
              'internal test error: cannot commit transaction')
    local ok, err = tx{
                tid  = tx.id,
                type = TXL,
                str  = 'box.commit()',
    }
    if not ok then
        t.fail_if(err.message ~= 'Transaction has been aborted by conflict',
                  '`stream:commit` failed unexpectedly: ' .. err)
        tx.running = false
        tx.aborted = true
        tx.str = 'box.rollback()'
        return false
    end
    tx.running = false
    tx.committed = true
    return true
end

local function tx_new(conn, id)
    local mt = {
        __index = {
            begin    = tx_begin,
            rollback = tx_rollback,
            commit   = tx_commit,
        },
        __call = tx_call,
    }
    return setmetatable({
        id        = id,
        _strm     = conn:new_stream(),
        running   = false,
        committed = false,
        aborted   = false,
        ro        = true,
        bad_dml   = false,
    }, mt)
end

local ro_ops = {
    {
        type = DQL,
        subtype = SELECT,
        idx = TREE,
        key_cnt = 0,
        fmt = 'box.space.s:select({}, {iterator = "%s", fullscan = true})',
    },
    {
        type = DQL,
        subtype = SELECT,
        idx = TREE,
        key_cnt = 1,
        fmt = 'box.space.s:select({%d}, {iterator = "%s", fullscan = true})',
    },
    {
        type = DQL,
        subtype = SELECT,
        idx = TREE,
        key_cnt = 2,
        fmt = 'box.space.s:select({%d, %d}, {iterator = "%s", fullscan = true})',
    },
    {
        type = DQL,
        subtype = GET,
        idx = TREE,
        fmt = 'box.space.s:get{%d, %d}',
    },
    {
        type = DQL,
        subtype = LEN,
        idx = TREE,
        fmt = 'box.space.s:len()',
    },
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = HASH,
    --    key_cnt = 0,
    --    fmt = 'box.space.s.index[1]:select({}, {fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = HASH,
    --    key_cnt = 1,
    --    fmt = 'box.space.s.index[1]:select({%d}, {iterator = "%s", fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = BITSET,
    --    key_cnt = 0,
    --    fmt = 'box.space.s.index[2]:select({}, {fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = BITSET,
    --    key_cnt = 1,
    --    fmt = 'box.space.s.index[2]:select({%d}, {iterator = "%s", fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = RTREE,
    --    key_cnt = 0,
    --    fmt = 'box.space.s.index[3]:select({}, {fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = RTREE,
    --    key_cnt = 2,
    --    fmt = 'box.space.s.index[3]:select({%d, %d}, {iterator = "%s", fullscan = true})',
    --},
    --{
    --    type = DQL,
    --    subtype = SELECT,
    --    idx = RTREE,
    --    key_cnt = 4,
    --    fmt = 'box.space.s.index[3]:select({%d, %d, %d, %d}, {iterator = "%s", fullscan = true})',
    --},
}

local ops = {
    unpack(ro_ops),
    {
        type = DML,
        fmt = 'box.space.s:delete{%d, %d}',
    },
    {
        type = DML,
        fmt = 'box.space.s:insert{%d, %d, {%d, %d}}',
    },
    {
        type = DML,
        fmt = 'box.space.s:replace{%d, %d, {%d, %d}}',
    },
    {
        type = DML,
        fmt = 'box.space.s:update({%d, %d}, {{"=", 3, {%d, %d}}})',
    },
    {
        type = DML,
        fmt = 'box.space.s:upsert({%d, %d, {%d, %d}}, {{"=", 3, {%d, %d}}})',
    },
}

local tree_iters = {'EQ', 'REQ', 'GT', 'GE', 'LT', 'LE'}
local hash_iters = {'EQ'}
local bitset_iters = {'EQ', 'BITS_ALL_SET', 'BITS_ANY_SET', 'BITS_ALL_NOT_SET'}
local rtree_iters = {'EQ', 'GT', 'GE', 'LT', 'LE', 'OVERLAPS', 'NEIGHBOR'}
local iters_map = {[TREE] = tree_iters, [HASH] = hash_iters,
                   [BITSET] = bitset_iters, [RTREE] = rtree_iters}

local function gen_rand_operation(ro)
    local op = ro and ro_ops[math.random(#ro_ops)] or ops[math.random(#ops)]
    local key1 = math.random(max_key)
    local key2 = math.random(max_key)
    local key3 = math.random(max_key)
    local key4 = math.random(max_key)
    if (op.type == DQL) then
        if op.subtype == SELECT then
            local iters = iters_map[op.idx]
            local iter = iters[math.random(#iters)]
            assert(op.idx ~= HASH or iter == 'EQ')
            if op.key_cnt == 0 then
                if op.idx == TREE then
                    op.str = op.fmt:format(iter)
                else
                    op.str = op.fmt
                end
            else
                if op.key_cnt == 1 then
                    op.str = op.fmt:format(key1, iter)
                elseif op.key_cnt == 2 then
                    op.str = op.fmt:format(key1, key2, iter)
                else
                    op.str = op.fmt:format(key1, key2, key3, key4, iter)
                end
            end
        elseif op.subtype == GET then
            op.str = op.fmt:format(key1, key2)
        else
            op.str = op.fmt
        end
    else
        local val1 = math.random(max_key)
        local val2 = math.random(max_key)
        local upd1 = math.random(max_key)
        local upd2 = math.random(max_key)
        op.str = op.fmt:format(key1, key2, val1, val2, upd1, upd2)
    end
    return op
end

local function txs_fetch_incomplete(txs)
    local tid = math.random(tx_cnt)

    for _ = 1, #txs do
        if not txs[tid].committed and not txs[tid].aborted then break end
        tid = tid % #txs + 1
    end

    if not txs[tid].committed and not txs[tid].aborted then
        if not txs[tid].running then
            txs[tid]:begin()
        end
    else
        return
    end
    return txs[tid]
end

local function tx_gen_stmt(tx, ro)
    tx(gen_rand_operation(ro))
    if (tx.aborted) then
        return
    end

    local p = math.random()
    if p < p_rollback then
        tx:rollback()
    elseif p < (p_rollback + p_commit) then
        tx:commit()
    end
end

local function txs_stop(txs)
    for tid = 1, #txs do
        if txs[tid].running then txs[tid]:commit() end
        table.insert(ro_txs_mask, txs[tid].ro)
        table.insert(committed_txs_mask, txs[tid].committed)
        table.insert(bad_dml_txs_mask, txs[tid].bad_dml)
    end
end

local function gen_stmts()
    local txs = {}
    for tid = 1, tx_cnt do
        table.insert(txs, tx_new(g.memtx_mvcc.net_box, tid))
    end

    for _ = 1, stmt_cnt do
        local tx = txs_fetch_incomplete(txs)
        if tx == nil then break end

        tx_gen_stmt(tx, tx.id <= ro_tx_cnt)
    end
    txs_stop(txs)
end

local function is_less(lhs, rhs)
    assert(lhs ~= nil and rhs ~= nil and
           box.tuple.is(lhs) and box.tuple.is(rhs))

    if lhs[1] < rhs[1] then
        return true
    elseif lhs[1] > rhs[1] then
        return false
    end

    if lhs[2] < rhs[2] then
        return true
    elseif lhs[2] > rhs[2] then
        return false
    end

    return false
end

local function is_equal(lhs, rhs)
    if lhs == nil and rhs == nil then return true end
    if lhs == nil or rhs == nil then return false end

    local lhs_t = type(lhs)
    local rhs_t = type(rhs)
    if lhs_t ~= rhs_t then return false end
    if lhs_t ~= 'table' then return lhs == rhs end

    if type(lhs[1]) == 'table' then
        require('log').info("before sort lhs: %s", json.encode(lhs))
        require('log').info("before sort rhs: %s", json.encode(rhs))

        table.sort(lhs, is_less)
        table.sort(rhs, is_less)

        require('log').info("after sort lhs: %s", json.encode(lhs))
        require('log').info("after sort rhs: %s", json.encode(rhs))
    end

    for k, v in ipairs(lhs) do
        if not is_equal(rhs[k], v) then return false end
    end
    for k, v in ipairs(rhs) do
        if not is_equal(lhs[k], v) then return false end
    end
    return true
end

local function try_apply_tx(tx_operations, rw)
    for i, operation in ipairs(tx_operations) do
        if not operation.ok then
            goto continue
        end

        if (rw) then
            table.insert(serialization, operation)
        end

        local _, res = pcall(g.memtx.eval, g.memtx, 'return ' .. operation.str)
        if not is_equal(res, operation.res) then
            if (not rw) then
                return false
            end
            dump_repro()
            dump_serialization()
            t.fail(('failed to serialize read-write transaction %d: ' ..
                    'discrepancy found on operation #%d "%s":\n' ..
                    'expected result:\n' ..
                    '%s\n' ..
                    'got result:\n' ..
                    '%s\n'):format(operation.tid, i, operation.str,
                    yaml.encode(operation.res), yaml.encode(res)))
        end
        ::continue::
    end
    return true
end

local function try_serialize()
    local rw_txs = {}
    local ro_txs = {}

    local tx_operations = {}
    for _ = 1, tx_cnt do
        table.insert(tx_operations, {})
    end

    for i = 1, #stmts do
        local stmt = stmts[i]
        if not committed_txs_mask[stmt.tid] then
            goto continue
        end

        if stmt.str:find('begin') and committed_txs_mask[stmt.tid] and
           ro_txs_mask[stmt.tid] and not bad_dml_txs_mask[stmt.tid] then
            table.insert(ro_txs, stmt.tid)
        end

        if stmt.str:find('commit') and committed_txs_mask[stmt.tid] and
           not ro_txs_mask[stmt.tid] then
            table.insert(rw_txs, stmt.tid)
        end

        if stmt.type ~= TXL then
            table.insert(tx_operations[stmt.tid], stmt)
        end
        ::continue::
    end

-- First of all, try to serialize read-only transactions.
    for i, tid in ipairs(ro_txs) do
        if try_apply_tx(tx_operations[tid], false) then ro_txs[i] = nil end
    end

    for _, rw_tid in ipairs(rw_txs) do
-- Try to serialize read-write transactions.
        try_apply_tx(tx_operations[rw_tid], true)
-- Afterwards, try to serialize read-only transactions again.
        for i, ro_tid in pairs(ro_txs) do
            if try_apply_tx(tx_operations[ro_tid], false) then
                ro_txs[i] = nil
            end
        end
    end

    if next(ro_txs) ~= nil then
        local failed_ro_set = {}
        for _, tid in pairs(ro_txs) do
            table.insert(failed_ro_set, tid)
        end
        dump_repro()
        dump_serialization()
        t.fail('failed to serialize the following read-only ' ..
               'transactions: ' .. table.concat(failed_ro_set, ', '))
    end
end

g.before_all(function()
    math.randomseed(os.time())

    g.cluster = cluster:new{}
    g.memtx = g.cluster:build_and_add_server{
        alias   = 'memtx',
    }
    g.memtx_mvcc = g.cluster:build_and_add_server{
        alias   = 'mvcc',
        box_cfg = {
            memtx_use_mvcc_engine = true
        }
    }
    g.cluster:start()
end)

g.after_all(function()
    --g.cluster:drop()
end)

local function open_files()
    local repro_file_name = 'tx_man_fuzzing_repro.lua'
    local repro_file_path = fio.pathjoin(g.memtx_mvcc.workdir, '..',
                                         repro_file_name)
    local err
    repro_file, err = fio.open(repro_file_path,
                               {'O_WRONLY', 'O_CREAT', 'O_TRUNC'},
                               {'S_IRUSR', 'S_IWUSR'})
    t.fail_if(repro_file == nil, ("`fio.open` failed: %s"):format(err))

    local serialization_file_name = 'tx_man_fuzzing_serialization.lua'
    local serialization_file_path = fio.pathjoin(g.memtx.workdir, '..',
                                                 serialization_file_name)
    serialization_file, err = fio.open(serialization_file_path,
                               {'O_WRONLY', 'O_CREAT', 'O_TRUNC'},
                               {'S_IRUSR', 'S_IWUSR'})
    t.fail_if(serialization_file == nil, ('`fio.open` failed: %s'):format(err))
end

local function close_files()
    t.fail_if(not repro_file:close(), 'failed to close reproducer file')
    t.fail_if(not serialization_file:close(), 'failed to close reproducer file')
end

g.test_tx_man = function()
    open_files()

    repro_file:write("os.execute('rm -rf *.snap *.xlog *.vylog 512')\n" ..
                     '\n' ..
                     "local ffi = require('ffi')\n" ..
                     "local json = require('json')\n" ..
                     "local log = require('log')\n" ..
                     "local txn_proxy = require('txn_proxy')\n" ..
                     '\n' ..
                     'box.cfg{memtx_use_mvcc_engine = true}\n' ..
                     '\n' ..
                     "box.schema.space.create('s')\n" ..
                     "box.space.s:create_index('pk', {parts = {{1, 'uint'}, \n" ..
                     "                                         {2, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk1', {type = 'HASH', \n" ..
                     "                                 parts = {{1, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk2', {type = 'BITSET', \n" ..
                     "                                 unique = false,\n" ..
                     "                                 parts = {{2, 'uint'}}})\n" ..
                     "box.space.s:create_index('sk3', {type = 'RTREE', \n" ..
                     "                                 unique = false,\n" ..
                     "                                 parts = {{3, 'array'}}})\n")
    for i = 1, tx_cnt do
        repro_file:write(('local tx%d = txn_proxy:new()\n'):format(i))
    end

    while true do
        g.memtx_mvcc:exec(function()
            local s = box.schema.space.create('s')
            s:create_index('pk', {parts = {{1, 'uint'}, {2, 'uint'}}})
            s:create_index('sk1', {type = 'HASH', parts = {{1, 'uint'}}})
            s:create_index('sk2', {type = 'BITSET', unique = false,
                                   parts = {{2, 'uint'}}})
            s:create_index('sk3', {type = 'RTREE', unique = false,
                                   parts = {{3, 'array'}}})
        end)

        stmts = {}
        committed_txs_mask = {}
        ro_txs_mask = {}
        bad_dml_txs_mask = {}
        gen_stmts()

        repro_file:write('\n')
        dump_repro()
        repro_file:write('box.space.s:drop()\n' ..
                         "box.schema.space.create('s')\n" ..
                         "box.space.s:create_index('pk', {parts = {{1, 'uint'}, \n" ..
                         "                                         {2, 'uint'}}})\n" ..
                         "box.space.s:create_index('sk1', {type = 'HASH', \n" ..
                         "                                 parts = {{1, 'uint'}}})\n" ..
                         "box.space.s:create_index('sk2', {type = 'BITSET', \n" ..
                         "                                 unique = false,\n" ..
                         "                                 parts = {{2, 'uint'}}})\n" ..
                         "box.space.s:create_index('sk3', {type = 'RTREE', \n" ..
                         "                                 unique = false,\n" ..
                         "                                 parts = {{3, 'array'}}})\n")

        g.memtx_mvcc:exec(function()
            box.space.s:drop()
        end)

        g.memtx:exec(function()
            local s = box.schema.space.create('s')
            s:create_index('pk', {parts = {{1, 'uint'}, {2, 'uint'}}})
            s:create_index('sk1', {type = 'HASH', parts = {{1, 'uint'}}})
            s:create_index('sk2', {type = 'BITSET', unique = false,
                                   parts = {{2, 'uint'}}})
            s:create_index('sk3', {type = 'RTREE', unique = false,
                                   parts = {{3, 'array'}}})
        end)

        serialization = {}
        try_serialize()
        g.memtx:exec(function()
            box.space.s:drop()
        end)

        --close_files()
    end
end