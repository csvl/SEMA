#!/bin/bash


POSITIONAL=()
MEMORY=false
CPU=false
INTERVAL=10
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -f|--filename)
      FILENAME="$2"
      shift # past argument
      shift # past value
      ;;
    -m|--memory)
      MEMORY=true
      shift # past argument
      ;;
    -c|--cpu)
      CPU=true
      shift # past argument
      ;;
    -i|--interval)
      INTERVAL="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      echo "-f|--filename <name>: filename to monitor"
      echo "-m|--memory: monitor memory ? (default: false)"
      echo "-c|--cpu: monitor cpu ? (default: false)"
      echo "-i|--interval <int> : interval in second of monitoring"
      ;;
    --default) #TODO
      DEFAULT=YES
      shift # past argument
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL[@]}" # restore positional parameters

echo "FILENAME  = ${FILENAME}"
echo "MEMORY MONITORING    = ${MEMORY}"
echo "CPU MONITORING    = ${CPU}"
echo "MONITORING INTERVAL   = ${INTERVAL} sec"

NOW=$(date +"%m_%d_%Y")
OUTPUT_FILENAME="output/output-monitor/${NOW}_00b2f45c7befbced2efaeb92a725bb3d.out"
OUTPUT_FILENAMEE="output/output-monitor/${NOW}_00b2f45c7befbced2efaeb92a725bb3d_explorer.out"

cd ../src/
touch ${OUTPUT_FILENAME}
touch ${OUTPUT_FILENAMEE}
xterm -geometry 150x300 -e "source ../penv/bin/activate; python3 ToolChainWorker.py res/malware-inputs/Sample_paper/nitol/00b2f45c7befbced2efaeb92a725bb3d 2>&1 | tee ${OUTPUT_FILENAME}" &
xterm -geometry 150x300 -e "source ../penv/bin/activate; python3 ToolChainWorkerExplorer.py res/malware-inputs/Sample_paper/nitol/00b2f45c7befbced2efaeb92a725bb3d 2>&1 | tee ${OUTPUT_FILENAMEE}" &

echo "------------------------"
echo "------ Monitoring: -----"
echo "------------------------"

'''
if [ ${CPU} ] && [ ${MEMORY} ]; then
        watch -n ${INTERVAL} ps -m -o pcpu,%mem,pid,user,args,command
elif  [ ${CPU} ]; then
        watch -n ${INTERVAL} ps -m -o pcpu,pid,user,args,command 
elif  [ ${MEMORY} ]; then
        watch -n ${INTERVAL} ps -m -o %mem,pid,user,args,command 
fi
'''

top

