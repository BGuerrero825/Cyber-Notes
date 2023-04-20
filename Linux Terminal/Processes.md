Processes can be pipelined into a single job. When a job runs, it occupies the terminal.
Background process with `&` at the end
ex. `127.0.0.1 -A > results.nmap &`
Ctrl+C to interrupt, or Ctrl_Z to suspend
`bg` resume a backgrounded job with
`jobs` to list current jobs
`fg %2` or `fg` to bring a job to the foreground
[[ps 1]]
[[kill]]