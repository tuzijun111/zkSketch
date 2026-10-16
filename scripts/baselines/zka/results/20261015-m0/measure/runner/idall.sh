#!/usr/bin/env bash
R="$(cd "$(dirname "$0")" && pwd)"
"$R/idrun.sh" gk_A gk 128 16 A; sleep 45
"$R/idrun.sh" gk_B gk 128 16 B; sleep 45
"$R/idrun.sh" bloom_A bloom 256 8 A; sleep 45
"$R/idrun.sh" bloom_B bloom 256 8 B
