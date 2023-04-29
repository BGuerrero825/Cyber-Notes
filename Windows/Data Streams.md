[[dir]] /r : list alternate data streams
`echo SAMPLE TEXT HERE > test.txt:alt` : write to an alternate data stream (data location in the allocated file space), called 'alt'
`more < test.txt:alt` : prints an alternate data stream named `alt`, no way to do this with `type`
[[SysInterals]] - streams