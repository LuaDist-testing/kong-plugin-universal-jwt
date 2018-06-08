local singletons = require "kong.singletons"
local table_insert = table.insert
local jwt = require "resty.jwt"
local constants = require "kong.constants"
local env = require '/kong/plugins/universal-jwt/env' -- relative paths don't work for some reason ???

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()

local function fetch_acls(consumer_id)
  local results, err = singletons.dao.acls:find_all {consumer_id = consumer_id}
  if err then
    return nil, err
  end
  return results
end

local function add_jwt()
  local consumer
  if ngx.ctx.authenticated_consumer then
    consumer = ngx.ctx.authenticated_consumer
  else
    return responses.send_HTTP_FORBIDDEN("Cannot identify the consumer")
  end

  local acls, err = fetch_acls(consumer.id)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end
  if not acls then acls = {} end

  -- Strip everything out apart from group
  local roles = {}
  for _, v in ipairs(acls) do
    table_insert(roles, v.group)
  end

  local jwt_token = jwt:sign(
    env.jwt_private_key,
    {
      header = {
        typ = "JWT",
        alg = "RS256"
      },
      payload = {
        iss = consumer.username,
        scopes = {
          roles = roles
        },
        exp = ngx.time() + 100 -- short lived JWT as will be created for every request
      }
    }
  )
  ngx.header["Authorization"] = "Bearer " .. jwt_token

end

-- constructor
function plugin:new()
  plugin.super.new(self, "universal-jwt")
  -- do initialization here, runs in the 'init_by_lua_block', before worker processes are forked
end

---[[ runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  plugin.super.access(self)
  print "running universal-jwt plugin"

  if ngx.ctx.plugins_for_request["key-auth"] ~= nil then
    print "key auth plugin found, adding jwt"
    add_jwt()
  end
end --]]

-- set the plugin priority, which determines plugin execution order
plugin.PRIORITY = 500

-- return our plugin object
return plugin
