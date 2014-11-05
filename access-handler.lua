local AccessHandler = {
    -- These HTTP methods are considered read-only, and everything else is
    -- considered read-write.
    READ_ONLY = {
        ["GET"] = true,
        ["HEAD"] = true,
    },
}

function AccessHandler:new(obj)
    return setmetatable(obj or {}, {__index = self})
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
    ngx.header.www_authenticate = "Basic realm=" .. self:realm()
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Handle authentication of the current request.
function AccessHandler:handle()
    return self:decide() or self:forbid("auth not handled")
end

-- Child class should implement to call one of allow(), forbid(), or
-- authenticate().
function AccessHandler:decide()
    error("unimplemented")
end

-- Child class should implement to return a valid authentication "realm" as a
-- string.
function AccessHandler:realm()
    error("unimplemented")
end

return {
    AccessHandler = AccessHandler,
}
