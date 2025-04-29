#!/bin/sh
"$1" sh -c '
  for signal in 1 2 3 4 5; do
    artifacts/kill-self-signal $signal &
  done
'
