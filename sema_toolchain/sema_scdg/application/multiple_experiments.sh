#!/bin/bash
set -e

usage="$(basename "$0") [-h] [-m MODE] [-c CONFIGS]
Launch one SCDG run with each specified config files using python3.10 or pypy3:
    -h  show this help text
    -m  python3.10 or pypy3
    -c  list of config files"

options=':hm:c:'
while getopts $options option; do
  case "$option" in
    h) echo "$usage"; exit;;
    m) MODE=$OPTARG;;
    c) CONFIGS=$OPTARG;;
    :) printf "missing argument for -%s\n" "$OPTARG" >&2; echo "$usage" >&2; exit 1;;
   \?) printf "illegal option: -%s\n" "$OPTARG" >&2; echo "$usage" >&2; exit 1;;
  esac
done

# mandatory arguments
if [ ! "$MODE" ] || [ ! "$CONFIGS" ]; then
  echo "arguments -m and -c must be provided"
  echo "$usage" >&2; exit 1
fi

# Mode can only be python3 or pypy3
if [ "$MODE" != "python3.10" ] && [ "$MODE" != "pypy3" ]; then
  echo "-m argument can either be python3.10 or pypy3 only"
  echo "$usage" >&2; exit 1
fi

end=$(($#-3))
for n in $(seq 1 $end); do
  echo "Running scdg with $MODE and config file : $4"
  if [ "$MODE" == "python3.10" ]; then
    source venv/bin/activate $MODE SemaSCDG.py $4
  else
    $MODE SemaSCDG.py $4
  fi
  wait
  shift
done
