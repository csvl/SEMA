for i in "$@"; do
  case $i in
    --hostname=*)
      HOST="${i#*=}"
      shift # past argument
      shift # past value
      ;;
    *)
      # unknown option
      ;;
  esac
done
DATE=$(date +"%d.%m.%y-%H.%M.%S")
source ../penv/bin/activate
celery -A CeleryTasks worker -Q $HOST -n worker.scdg.classifier.$HOST -P threads -E -f logs/celery_$HOST_$DATE.logs
deactivate