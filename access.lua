local redmine = require("redmine")

local AccessHandler = {
    -- These HTTP methods are considered read-only, and everything else is
    -- considered read-write.
    READ_ONLY = {
        ["GET"] = true,
        ["HEAD"] = true,
    },
}

-- Construct a new AccessHandler with the given database handle and auth realm.
function AccessHandler:new(db, realm)
    assert(db, "no database handle")
    assert(realm, "no auth realm")

    return setmetatable({
        rm = redmine.Redmine:new(db),
        realm = "\"" .. realm .. "\"",
    }, {__index = self})
end

-- Try to parse a project name from a request URI of the form /hg/PROJECT[/...].
-- Return the project name on success and nil, err on failure.
function AccessHandler.parse_project(path)
    local match, err = ngx.re.match(path, "^/hg/([^/]+)")

    if not match then
        return nil, err
    end

    return match[1]
end

-- Try to parse an RFC1945 HTTP basic auth header into a username and password.
-- Return username, password on success and nil, nil on failure.
function AccessHandler.parse_auth(header)
    local match, err = ngx.re.match(header, "^Basic (.+)$")

    if not match then
        return nil, nil
    end

    local pair = ngx.decode_base64(match[1])

    if not pair then
        return nil, nil
    end

    -- By the spec, the username must not be empty and can't contain any
    -- colons. The password can be empty and can contain any number of colons.
    local match, err = ngx.re.match(pair, "^([^:]+):(.*)$")

    if not match then
        return nil, nil
    end

    return match[1], match[2]
end

-- Check if the given method is a read-only HTTP method.
function AccessHandler:read_only(method)
    return self.READ_ONLY[method] and true or false
end

-- Allow the current request as authorized.
function AccessHandler:allow()
    return true
end

-- Forbid the current request as unauthorized.
function AccessHandler:forbid(err)
    ngx.log(ngx.ERR, err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Force the user to authenticate and provide credentials.
function AccessHandler:authenticate()
    ngx.header.www_authenticate = "Basic realm=" .. self.realm
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Handle authentication of the current request.
function AccessHandler:handle()
    return self:decide() or self:forbid("auth not handled")
end

-- Most of this logic is from redmine's Redmine.pm script.
function AccessHandler:decide()
    -- Parse the project name from the url.
    local pname, err = self.parse_project(ngx.var.uri)
    if not pname then
        return self:forbid(err or "malformed project")
    end

    -- Get whether the request is read-only.
    local read_only = self:read_only(ngx.req.get_method())

    -- Get the project object.
    local project, err = self.rm:project(pname)
    if not project then
        return self:forbid(err)
    end

    -- If the project isn't readable, then it isn't writable either, so it can't
    -- be operated on at all.
    if not project:readable() then
        return self:forbid("project not readable")
    end

    -- If the method requires write access, but the project is read-only, then
    -- it can't be operated on in with any user.
    if not read_only and not project:writable() then
        return self:forbid("project not writable")
    end

    -- Get the auth (username/password) header.
    local header = ngx.var.http_authorization

    -- If there's no auth header, then the user gave no credentials, so handle
    -- as an anonymous user.
    if not header then
        -- Get the settings object.
        local settings, err = self.rm:settings()
        if not settings then
            return self:forbid(err)
        end

        -- If authentication is globally forced, then force it.
        if settings.login_required == "1" then
            return self:authenticate()
        end

        -- Force authentication for methods requiring write access.
        if not read_only then
            return self:authenticate()
        end

        local anon, err = self:anon_perms(pname)
        if not anon then
            return self:forbid(err)
        end

        -- Since the method is read-only at this point, allow without
        -- authentication if the project is public and Anon has read access.
        if project.is_public and anon:read_access() then
            return self:allow()
        end

        -- Otherwise, force authentication.
        return self:authenticate()
    end

    -- Try to parse credentials from the header.
    local username, password = self.parse_auth(header)

    -- Forbid if the header was malformed.
    if not username or not password then
        return self:forbid("malformed auth header")
    end

    -- Get the user object.
    local user, err = self.rm:user(username)
    if not user then
        return self:forbid(err)
    end

    -- Forbid if the username and password don't match.
    if not user:check_pass(password) then
        return self:forbid("incorrect password")
    end

    -- Get the member or non-member permissions for the current user on the
    -- current project.
    local perms, err = self:user_perms(pname, username)
    if not perms then
        return self:forbid(err)
    end

    -- Ensure read/write permissions match with method.
    if read_only then
        return perms:read_access() and self:allow() or
            self:forbid("no read access")
    else
        return perms:write_access() and self:allow() or
            self:forbid("no write access")
    end
end

-- Get the project-specific or global permissions for Anon on the given project.
-- Return a Perms object on success and nil, err on failure.
function AccessHandler:anon_perms(pname)
    -- Try to get project-specific Anon permissions.
    local anon, err = self.rm:anon_perms(pname)
    if not anon then
        return nil, err
    end

    if anon:exists() then
        return anon
    end

    -- Otherwise, try to get the global permissions and use those.
    local global, err = self.rm:global_anon_perms()
    if not global then
        return nil, err
    end

    if not global:exists() then
        return nil, "no permissions for anon"
    end

    return global
end

-- Get either the member or non-member permissions for the given user on the
-- given project. Return a Perms object on success and nil, err on failure.
function AccessHandler:user_perms(pname, username)
    -- Get the permissions for the current user.
    local perms, err = self.rm:member_perms(pname, username)
    if not perms then
        return nil, err
    end

    -- If the user is actually a member of the current project, then the
    -- permissions are valid.
    if perms:exists() then
        return perms
    end

    -- Otherwise, try to get the project-specific permissions for non-members.
    local perms, err = self.rm:non_member_perms(pname)
    if not perms then
        return nil, err
    end

    if perms:exists() then
        return perms
    end

    -- Finally, try to get the global permissions for non-members.
    local global, err = self.rm:global_non_member_perms()
    if not global then
        return nil, err
    end

    if not global:exists() then
        return nil, "no permissions for user"
    end

    return global
end

return {
    AccessHandler = AccessHandler,
}
