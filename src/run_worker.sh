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

source ../penv/bin/activate
celery -A CeleryTasks worker -Q $HOST -n worker.scdg.classifier.$HOST -P threads -E -f celery.logs
deactivate