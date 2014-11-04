local access = require("access-handler")
local IONAccessHandler = access.AccessHandler:new()

function IONAccessHandler:new(rm)
    return setmetatable({
        rm = rm,
    }, {__index = self})
end

function IONAccessHandler:realm()
    return [["ION"]]
end

function IONAccessHandler.parse_project(path)
    local match, err = ngx.re.match(path, "/hg/([^/]+)")

    if not match then
        return nil, err
    end

    return match[1]
end

function IONAccessHandler:decide()
    -- Parse the project name from the url.
    local pname, err = self.parse_project(ngx.var.uri)
    if not pname then
        return self:forbid("malformed project")
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
        if settings:auth_forced() then
            return self:authenticate()
        end

        -- Force authentication for methods requiring write access.
        if not read_only then
            return self:authenticate()
        end

        -- Get permissions for Anon.
        local anon = self.rm:anon_perms(pname)
        if not anon then
            return self:forbid(err)
        end

        -- Since the method is read-only at this point, allow without
        -- authentication if the project is public and Anon has read access.
        if project.is_public and anon:exists() and anon:read_access() then
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
    local perms = self:user_perms(pname, username)

    -- Ensure read/write permissions match with method.
    if read_only then
        return perms:read_access() and self:allow() or
            self:forbid("no read access")
    else
        return perms:write_access() and self:allow() or
            self:forbid("no write access")
    end
end

function IONAccessHandler:user_perms(pname, username)
    -- Get the permissions for the current user.
    local perms, err = self.rm:member_perms(pname, username)
    if not perms then
        return self:forbid(err)
    end

    -- If the user is actually a member of the current project, then the
    -- permissions are valid.
    if perms:exists() then
        return perms
    end

    -- Otherwise, handle the non-member case.
    local perms, err = self.rm:non_member_perms(pname, username)
    if not perms then
        return self:forbid(err)
    end

    -- Forbid if the member has no non-member permissions on the project.
    if not perms:exists() then
        self:forbid("no non-member permissions for user")
    end

    return perms
end

return {
    IONAccessHandler = IONAccessHandler,
}
