local crypto = require("crypto")

local Settings = {}

-- Construct a new settings object given some rows of settings from the
-- database. Return a Settings object on success and nil, err on failure. If a
-- setting is defined, the Settigns object can be indexed with its name to
-- return its value as a string.
function Settings:new(query, err)
    if not query then
        return nil, err
    end

    local s = setmetatable({}, {__index = self})

    for row in query:rows(true) do
        s[row.name] = row.value
    end

    return s
end

local Project = {}

-- Construct a new project given a row from the database.
function Project:new(info, err)
    if not info then
        return nil, err or "invalid project"
    end

    return setmetatable(info, {__index = self})
end

-- Check whether the project's repo can be read.
function Project:readable()
    -- Project status 9 corresponds to "archived", defined in
    -- app/models/project.rb. The project is readable as long as it isn't
    -- archived
    return self.status ~= 9
end

-- Check whether the project's repo can be written to.
function Project:writable()
    -- Project status 1 corresponds to "active".
    return self.status == 1
end

local User = {}

-- Construct a new user object given a row from the database.
function User:new(row, err)
    if not row then
        return nil, err or "invalid user"
    end

    return setmetatable(row, {__index = self})
end

-- Create an ASCII hash of the given password using redmine's salt and hashing
-- method.
function User:hash_pass(pass)
    return crypto.digest("sha1", self.salt .. crypto.digest("sha1", pass))
end

-- Check whether the given password matches that stored in the database.
function User:check_pass(pass)
    return self.hashed_password == self:hash_pass(pass)
end

-- Check if the user is active (not unregistered or locked).
function User:active()
    -- User status 1 means "active", defined in app/models/principal.rb.
    return self.status == 1
end

local Perms = {}

-- Construct a new permissions object given a row from the database.
function Perms:new(info, err)
    if not info then
        return nil, err
    end

    return setmetatable(info, {__index = self})
end

-- Check if any permissions exist.
function Perms:exists()
    return self.permissions ~= nil
end

-- Check if permissions allow read access.
function Perms:read_access()
    return self.permissions:find(":browse_repository") ~= nil
end

-- Check if permissions allow write access.
function Perms:write_access()
    return self.permissions:find(":commit_access") ~= nil
end

local Redmine = {}

-- Construct a new redmine object given a database connection to work from.
function Redmine:new(db)
    return setmetatable({db = db}, {__index = self})
end

-- Execute the given sql query bound with given variadic arguments. Return a
-- query object on success and nil, err on failure.
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

-- Execute the given query with exec() and return the first row. More than one
-- row is considered an error, so the query should ensure results are combined
-- to a single row. Return the row table on success and nil, err on failure.
function Redmine:fetch(sql, ...)
    local query, err = self:exec(sql, unpack(arg))

    if not query then
        return nil, err
    end

    if query:rowcount() > 1 then
        return nil, "more than one row"
    end

    -- Fetch the row using column names as table indices.
    return query:fetch(true)
end

-- Get the settings object for this redmine setup.
function Redmine:settings()
    return Settings:new(self:exec([[
        SELECT name, value
        FROM settings
        WHERE name = 'login_required'
        ;
    ]]))
end

-- Get a project object for the given project name.
function Redmine:project(project)
    return Project:new(self:fetch([[
        SELECT is_public, status
        FROM projects
        WHERE projects.identifier = ?
        ;
    ]], project))
end

-- Get a user object for the given username.
function Redmine:user(user)
    -- User status 1 is "active", defined in app/models/principal.rb.
    return User:new(self:fetch([[
        SELECT hashed_password, salt, status
        FROM users
        WHERE users.login = ?
        ;
    ]], user, project))
end

-- Get the global permissions for Anon.
function Redmine:global_anon_perms()
    return Perms:new(self:fetch([[
        SELECT permissions
        FROM roles
        -- This constant is defined in app/models/role.rb.
        WHERE builtin = 2
        ;
    ]]))
end

-- Get the permissions for Anon on the given project. If these exist, they
-- override the global permissions for Anon.
function Redmine:anon_perms(project)
    return Perms:new(self:fetch([[
        -- Take the union of all the permissions of Anon.
        SELECT string_agg(permissions, '') AS permissions
        FROM roles
        WHERE id IN (
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

-- Get the global permissions for non-member users.
function Redmine:global_non_member_perms()
    return Perms:new(self:fetch([[
        SELECT permissions
        FROM roles
        -- This constant is defined in app/models/role.rb.
        WHERE builtin = 1
        ;
    ]]))
end

-- Get the non-member permissions for the given project. If these exist, they
-- override the global non-member permissions.
function Redmine:non_member_perms(project)
    return Perms:new(self:fetch([[
        -- Take the union of all the permissions of the user.
        SELECT string_agg(permissions, '') AS permissions
        FROM roles
        WHERE id IN (
            SELECT member_roles.role_id
            FROM members, member_roles, projects, users
            WHERE projects.identifier = ? AND
                  members.user_id = users.id AND
                  members.project_id = projects.id AND
                  members.id = member_roles.member_id AND
                  users.type = 'GroupNonMember'
        )
        ;
    ]], project))
end

-- Get the permissions for the given user on the given project. If the user
-- isn't a member of the project, the permissions will be empty.
function Redmine:member_perms(project, user)
    return Perms:new(self:fetch([[
        -- Take the union of all the permissions of the user.
        SELECT string_agg(permissions, '') AS permissions
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
