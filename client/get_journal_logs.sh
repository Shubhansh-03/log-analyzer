#!/bin/bash
# client/get_journal_logs.sh

# Fetch logs from the last 5 seconds to match the batch interval
# --no-pager ensures it dumps straight to stdout
journalctl --since "5 seconds ago" --no-pager > logs/journal_temp.log
