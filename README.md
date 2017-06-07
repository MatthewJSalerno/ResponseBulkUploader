# ResponseBulkUploader
ex.

`perl bulkupload.pl -a bsa -u myusername -n mydomain.com -p mypassword -v qualys -d . -s 1,2,3,4,5`

**TODO**
* The script will put all incomplete tasks into a hash (%runningtasks).   The tasks in this hash should be re-checked in the loop at the end of the script.   I have the loop in place, but all it does is print the taskid and filename.   This is not vital since on the next run of the script it will detect files that have been uploaded and move them accordingly.

    * Issue with waiting for second run is that they will be moved to the "failed" directory.
    * Could move it to a Duplicate directory, although that doesn't make much sense.  Perhaps, "alreadyprocessed" dir?
    * Need to convert the hash of pending tasks into an array of hashes so that I can preserve he order in the final loop while rechecking tasks.
    * How many times should the same task be checked before giving up?
