-- This script is ran by nginx for every request under /hg/. It uses the global
-- ION access handler to either allow or forbid each request.

handler:handle()
