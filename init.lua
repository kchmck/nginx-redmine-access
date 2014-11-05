local dbi = require("DBI")
local redmine = require("redmine")
local ion = require("ion-access-handler")

-- Connect to the redmine database.
local db, err = dbi.Connect("PostgreSQL", "redmine", "redmine", "redmine")
assert(db, err)
local rm = redmine.Redmine:new(db)

-- Export our access handler.
handler = ion.IONAccessHandler:new(rm)
