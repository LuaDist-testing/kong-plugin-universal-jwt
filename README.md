# kong-plugin-universal-jwt
Kong custom plugin for generating a JWT from some other auth method. It currently only applies to key auth plugin, but can be extended for others if required.

## Setting up development environment
Easiest way to setup is to run the kong vagrant VM (https://github.com/Kong/kong-vagrant)

```
git clone https://github.com/Kong/kong-vagrant
cd kong-vagrant
git clone https://github.com/localz/kong-plugin-universal-jwt
export KONG_PLUGIN_PATH=./kong-plugin-universal-jwt
vagrant up
vagrant ssh
cd /kong
export KONG_CUSTOM_PLUGINS=universal-jwt
```

Run the tests in Kong repo first (this does some sort of setup):
`bin/busted`

Then can run tests for the plugin:
`bin/busted /kong-plugin/spec`
