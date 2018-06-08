local helpers = require "spec.helpers"
local jwt = require "resty.jwt"
local cjson = require "cjson.safe"

local function has_value(tab, val)
  for index, value in ipairs(tab) do
    if value == val then
      return true
    end
  end
  return false
end

describe("universal-jwt plugin (access)", function()
  local client
  local consumer_username = "bob"
  local consumer_groups = {"admin", "owner"}

  setup(function()
    helpers.run_migrations()

    local api1 = assert(helpers.dao.apis:insert { 
        name = "api-1", 
        hosts = { "test1.com" }, 
        upstream_url = helpers.mock_upstream_url
    })
    local api2 = assert(helpers.dao.apis:insert { 
        name = "api-2", 
        hosts = { "test2.com" }, 
        upstream_url = helpers.mock_upstream_url
    })

    assert(helpers.dao.plugins:insert {
      name   = "key-auth",
      api_id = api1.id,
    })

    local consumer1 = assert(helpers.dao.consumers:insert {
      username = consumer_username
    })
    assert(helpers.dao.keyauth_credentials:insert {
      key         = "apikey1",
      consumer_id = consumer1.id,
    })

    assert(helpers.dao.plugins:insert {
      api_id = api1.id,
      name = "universal-jwt",
    })

    assert(helpers.dao.acls:insert {
      group = consumer_groups[1],
      consumer_id = consumer1.id
    })

    assert(helpers.dao.acls:insert {
      group = consumer_groups[2],
      consumer_id = consumer1.id
    })

    assert(helpers.start_kong({
      nginx_conf = "spec/fixtures/custom_nginx.template",
      custom_plugins = "universal-jwt"
    }))
  end)

  teardown(function()
    helpers.stop_kong()
  end)

  before_each(function()
    client = helpers.proxy_client()
  end)

  after_each(function()
    if client then client:close() end
  end)

  describe("request", function()
    it("with key auth plugin adds the 'Authorization' header", function()
      local r = assert(client:send {
        method = "GET",
        path = "/request?apikey=apikey1",
        headers = {
          host = "test1.com"
        }
      })
      assert.response(r).has.status(200)
      local auth_header = assert.request(r).has.header("Authorization")
      local token = auth_header:sub(8)
      local header, claims, signature = token:match("([^.]*).([^.]*).(.*)")
      claims = cjson.decode(ngx.decode_base64(claims))
      assert.are.equals(consumer_username, claims.iss)
      assert(has_value(claims.scopes.roles, consumer_groups[1]))
      assert(has_value(claims.scopes.roles, consumer_groups[2]))
    end)
    it("without key auth plugin does nothing", function()
      local r = assert(client:send {
        method = "GET",
        path = "/request",
        headers = {
          host = "test2.com"
        }
      })
      assert.response(r).has.status(200)
      assert.request(r).has_not.header("Authorization")
    end)
  end)
end)
