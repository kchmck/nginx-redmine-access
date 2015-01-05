These scripts tie in nginx user authentication with a Redmine project's
database. These are a continuation of [Redmine.pm], updated for the [nginx-lua]
infrastructure.

[Redmine.pm]: http://www.redmine.org/projects/redmine/repository/changes/trunk/extra/svn/Redmine.pm
[nginx-lua]: https://github.com/openresty/lua-nginx-module

The redmine interface is implemented in `redmine.lua`, and the auth decisions
happen in `access.lua` with the `AccessHandler` object. An instance of
`AccessHandler` is created by passing in a [luadbi] handle and an auth realm,
then the `handle` method handles the current nginx request.

[luadbi]: https://code.google.com/p/luadbi/wiki/DBI#dbh,_err_=_DBI.Connect%28driver_name,_dbname,_dbuser,_dbpassword,https://code.google.com/p/luadbi/wiki/DBI#dbh,_err_=_DBI.Connect%28driver_name,_dbname,_dbuser,_dbpassword,

For example,

    init_by_lua '
        local dbi = require("DBI")
        local access = require("access")

        local db, err = dbi.Connect("DRIVER", "DATABASE", "USERNAME", 'PASSWORD")
        assert(db, err)

        handler = access.AccessHandler:new(db, [["REALM"]])
    ';

    location /hg {
        access_by_lua 'handler:handle()';
    }
