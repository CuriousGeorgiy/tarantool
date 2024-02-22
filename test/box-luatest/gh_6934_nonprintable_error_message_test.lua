local console = require('console')
local t = require('luatest')
local yaml = require('yaml')

local g = t.group()

-- Check that an error message with invalid UTF-8 sequences is encoded to Base64

g.test_bad_utf8_in_error_msg1 = function()
    local res = console.eval("box.error.new(box.error.ILLEGAL_PARAMS, 'bad: \x80')")
    res = yaml.decode(res)
    local ref = "Illegal parameters, bad: \x80"
    t.assert_equals(res[1].message, ref)
end

g.test_bad_utf8_in_error_msg2 = function()
    local res = console.eval("require('net.box').self:call('bad: \x8a')")
    res = yaml.decode(res)
    local ref = "Procedure 'bad: \x8A' is not defined"
    t.assert_equals(res[1].error.message, ref)
end
