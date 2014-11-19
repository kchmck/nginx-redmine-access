-- This script is ran on nginx startup to set up the global handler used by the
-- access script.

local dbi = require("DBI")
local redmine = require("redmine")
local ion = require("ion-access-handler")

-- Connect to the redmine database. Replace with the actual database, username,
-- and password.
local db, err = dbi.Connect("PostgreSQL", "redmine", "redmine", "redmine")
assert(db, err)
local rm = redmine.Redmine:new(db)

-- Export our access handler.
handler = ion.IONAccessHandler:new(rm)
