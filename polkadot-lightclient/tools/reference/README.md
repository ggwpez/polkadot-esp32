Not built. Kept because it is the firmware that settled the partition table:
it dumps the table as flashed, writes a 19,200-byte authority set to NVS and
verifies it byte-for-byte across reboots. Reachable again by pointing
`src_dir` at it if the layout ever changes. Findings are in PLAN.md §6.
