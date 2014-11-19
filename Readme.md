These scripts tie in nginx user authentication with a Redmine project's
database. These are a continuation of [Redmine.pm], updated for the [nginx-lua]
infrastructure.

[Redmine.pm]: http://www.redmine.org/projects/redmine/repository/changes/trunk/extra/svn/Redmine.pm
[nginx-lua]: https://github.com/openresty/lua-nginx-module

The main entry points are `init.lua`, called by `init_by_lua_file`, and
`access.lua`, called by `access_by_lua_file`. The auth decisions actually happen
in `ion-access-handler.lua`.
