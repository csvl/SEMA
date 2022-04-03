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
celery -A tasks.CeleryTasksSCDG worker -Q $HOST -E
#celery -A tasks.CeleryTasksClassifier worker -Q $HOST -E
deactivate