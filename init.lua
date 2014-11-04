local dbi = require("DBI")

-- Connect to the redmine database.
db, err = assert(dbi.Connect("PostgreSQL", "redmine", "redmine", "redmine"))
assert(db, err)

handler = require("ion-access-handler")
