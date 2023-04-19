*finds files using an index made by updatedb*

locate **file-name**

-   -name - Search by filename or directory name (case sensitive).
-   -iname - Search by filename or directory name (case insensitive).
-   -type f/d/l/s - Search by type which can be (files, directories, links or sockets)
-   -size - Search by file or directory size.
-   -mtime - Search using the last modified date criteria.
-   -o - Allows us to combine multiple values of the same argument.
-   -user - Find files and directories based on their owner.