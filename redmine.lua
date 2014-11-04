local crypto = require("crypto")

local Settings = {}

function Settings:new(row, err)
    if not row then
        return nil, err
    end

    return setmetatable(row, {__index = self})
end

function Settings:auth_forced()
    return self.value == "1"
end

local Project = {}

function Project:new(info, err)
    if not info then
        return nil, err or "invalid project"
    end

    return setmetatable(info, {__index = self})
end

function Project:readable()
    -- Project status 9 corresponds to "archived", defined in
    -- app/models/project.rb. The project is readable as long as it isn't
    -- archived
    return self.status ~= 9
end

function Project:writable()
    -- Project status 1 corresponds to "active".
    return self.status == 1
end

local User = {}

function User:new(row, err)
    if not row then
        return nil, err or "invalid user"
    end

    return setmetatable(row, {__index = self})
end

function User:hash_pass(pass)
    return crypto.digest("sha1", self.salt .. crypto.digest("sha1", pass))
end

function User:check_pass(pass)
    return self.hashed_password == self:hash_pass(pass)
end

function User:active()
    -- User status 1 means "active", defined in app/models/principal.rb.
    return self.status == 1
end

local Perms = {}

function Perms:new(info, err)
    if not info then
        return nil, err
    end

    return setmetatable(info, {__index = self})
end

function Perms:exists()
    return self.perms ~= nil
end

function Perms:read_access()
    return self.perms:find(":browse_repository") ~= nil
end

function Perms:write_access()
    return self.perms:find(":commit_access") ~= nil
end

local Redmine = {}

function Redmine:new(db)
    return setmetatable({db = db}, {__index = self})
end

function Redmine:exec(sql, ...)
    local query, err = self.db:prepare(sql)

    if not query then
        return nil, err
    end

    local good, err = query:execute(unpack(arg))

    if not good then
        return nil, err
    end

    return query
end

function Redmine:fetch(sql, ...)
    local query, err = self:exec(sql, unpack(arg))

    if not query then
        return nil, err
    end

    if query:rowcount() ~= 1 then
        return nil, "more than one row"
    end

    return query:fetch(true)
end

function Redmine:settings()
    return Settings:new(self:fetch([[
        SELECT value
        FROM settings
        WHERE settings.name = 'login_required'
        ;
    ]]))
end

function Redmine:project(project)
    return Project:new(self:fetch([[
        SELECT is_public, status
        FROM projects
        WHERE projects.identifier = ?
        ;
    ]], project))
end

function Redmine:user(user)
    -- User status 1 is "active", defined in app/models/principal.rb
    return User:new(self:fetch([[
        SELECT hashed_password, salt, status
        FROM users
        WHERE users.login = ?
        ;
    ]], user, project))
end

function Redmine:anon_perms(project)
    -- Builtin role 2 is "anonymous", defined in app/models/role.rb
    return Perms:new(self:fetch([[
        SELECT string_agg(permissions, '') AS perms
        FROM roles
        WHERE builtin = 2 OR
              id IN (
                SELECT member_roles.role_id
                FROM members, member_roles, projects, users
                WHERE projects.identifier = ? AND
                      members.user_id = users.id AND
                      members.project_id = projects.id AND
                      members.id = member_roles.member_id AND
                      users.type = 'GroupAnonymous'
            )
        ;
    ]], project))
end

function Redmine:non_member_perms(project, user)
    -- Builtin role 1 is "non-member" defined in role.rb.
    return Perms:new(self:fetch([[
        SELECT string_agg(permissions, '') AS perms
        FROM roles
        WHERE builtin = 1 OR
              id IN (
                  SELECT member_roles.role_id
                  FROM members, member_roles, projects, users
                  WHERE projects.identifier = ? AND
                        users.login = ? AND
                        members.user_id = users.id AND
                        members.project_id = projects.id AND
                        members.id = member_roles.member_id AND
                        users.type = 'GroupNonMember'
              )
        ;
    ]], project, user))
end

function Redmine:member_perms(project, user)
    return Perms:new(self:fetch([[
        SELECT string_agg(permissions, '') AS perms
        FROM roles
        WHERE id IN (
                  SELECT member_roles.role_id
                  FROM members, member_roles, projects, users
                  WHERE projects.identifier = ? AND
                        users.login = ? AND
                        members.user_id = users.id AND
                        members.project_id = projects.id AND
                        members.id = member_roles.member_id
              )
        ;
    ]], project, user))
end

return {
    Redmine = Redmine,
}
