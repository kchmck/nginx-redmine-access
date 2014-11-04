local dbi = require("DBI")
local redmine = require("redmine")

-- Connect to the redmine database.
db, err = assert(dbi.Connect("PostgreSQL", "redmine", "redmine", "redmine"))
assert(db, err)

rm = redmine.Redmine:new(db)
handler = require("ion-access-handler")
