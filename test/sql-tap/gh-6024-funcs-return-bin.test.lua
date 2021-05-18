#!/usr/bin/env tarantool
local build_path = os.getenv("BUILDDIR")
package.cpath = build_path..'/test/sql-tap/?.so;'..build_path..'/test/sql-tap/?.dylib;'..package.cpath

local test = require("sqltester")
test:plan(5)

box.schema.func.create("gh-6024-funcs-return-bin.ret_bin", {
    language = "C",
    param_list = {},
    returns = "varbinary",
    exports = {"SQL"},
})

test:do_execsql_test(
    "gh-6024-1",
    [[
        SELECT typeof("gh-6024-funcs-return-bin.ret_bin"());
    ]], {
        "varbinary"
    })

box.schema.func.create("gh-6024-funcs-return-bin.ret_uuid", {
    language = "C",
    param_list = {},
    returns = "varbinary",
    exports = {"SQL"},
})

test:do_execsql_test(
    "gh-6024-2",
    [[
        SELECT typeof("gh-6024-funcs-return-bin.ret_uuid"());
    ]], {
        "varbinary"
    })

box.schema.func.create("gh-6024-funcs-return-bin.ret_decimal", {
    language = "C",
    param_list = {},
    returns = "varbinary",
    exports = {"SQL"},
})

test:do_execsql_test(
    "gh-6024-3",
    [[
        SELECT typeof("gh-6024-funcs-return-bin.ret_decimal"());
    ]], {
        "varbinary"
    })

box.schema.func.create("get_uuid", {
    language = "LUA",
    param_list = {},
    returns = "varbinary",
    body = "function(x) return require('uuid').fromstr('11111111-1111-1111-1111-111111111111') end",
    exports = {"SQL"},
})

test:do_execsql_test(
    "gh-6024-4",
    [[
        SELECT typeof("get_uuid"()), "get_uuid"() == "gh-6024-funcs-return-bin.ret_uuid"();
    ]], {
        "varbinary", true
    })

box.schema.func.create("get_decimal", {
    language = "LUA",
    param_list = {},
    returns = "varbinary",
    body = "function(x) return require('decimal').new('12345') end",
    exports = {"SQL"},
})

test:do_execsql_test(
    "gh-6024-5",
    [[
        SELECT typeof("get_decimal"()), "get_decimal"() == "gh-6024-funcs-return-bin.ret_decimal"();
    ]], {
        "varbinary", true
    })

test:finish_test()
