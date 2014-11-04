local AccessHandler = {
    READ_ONLY = {
        ["GET"] = true,
        ["HEAD"] = true,
    },
}

function AccessHandler:new(obj)
    return setmetatable(obj or {}, {__index = self})
end

function AccessHandler.parse_auth(header)
    local match, err = ngx.re.match(header, "^Basic (.+)$")

    if not match then
        return nil, nil
    end

    local pair = ngx.decode_base64(match[1])

    if not pair then
        return nil, nil
    end

    -- The username must be set by the check above. The password can be empty by
    -- the spec, and it can contain any number of colons.
    local match, err = ngx.re.match(pair, "^([^:]+):(.*)$")

    if not match then
        return nil, nil
    end

    return match[1], match[2]
end

function AccessHandler.read_only(method)
    return AccessHandler.READ_ONLY[method] and true or false
end

function AccessHandler:allow()
    return true
end

function AccessHandler:forbid(err)
    ngx.log(ngx.ERR, err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

function AccessHandler:authenticate()
    ngx.header.www_authenticate = "Basic realm=" .. self:realm()
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

function AccessHandler:handle()
    return self:decide() or self:forbid("auth not handled")
end

function AccessHandler:decide()
    error("unimplemented")
end

function AccessHandler:realm()
    error("unimplemented")
end

return {
    AccessHandler = AccessHandler,
}
