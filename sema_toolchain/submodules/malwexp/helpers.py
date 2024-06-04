import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import click
import datetime
import getpass
import json
import re


def bazaar_to_malwexp(data):
    malware = {}

    malware["hashes"] = [ data["sha256_hash"], data["md5_hash"] ] # other available: sha1, sha3
    malware["date"] = data["first_seen"][:10] # cut from YYYY-MM-DD( HH:mm:ss)
    malware["family"] = data["signature"]
    malware["type"] = "unknown"
    malware["platform"] = file_type_to_platform(data["file_type"])
    malware["source"] = "bazaar.abuse.ch"
    malware["location"] = "malbazaar"

    malware["bazaar"] = data

    return malware


def file_type_to_platform(file_type):
    if file_type == "exe" or file_type == "dll":
        return "windows"
    elif file_type == "app":
        return "mac"
    elif file_type == "elf":
        return "linux"
    elif file_type == "apk":
        return "android"
    elif file_type == "jar":
        return "multi"
    elif file_type == "js":
        return "browser"
    else:
        return "unknown"


def json_str(obj):
    """Transform a list or dict object to string."""
    return json.dumps(obj, indent=4, ensure_ascii=False, default=datetime_to_str)


def datetime_to_str(obj):
    """Transform datetime to str YYYY-MM-DD"""
    if isinstance(obj, datetime.datetime):
        return obj.strftime("%Y-%m-%d")


def str_to_datetime(date_str):
    """Transform date in str YYYY-MM-DD to datetime, or none if conversion fail."""
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None


def parse_file(file, validation):
    """Get json file as dict and validate"""
    try:
        value = json.load(file)
    except json.JSONDecodeError:
        raise click.ClickException(f"cannot parse file as json.")

    if type(value) == list:
        return [ validation(dict) for dict in value ]
    else:
        return [ validation(value) ]


def set_generated_fields(dict):
    """Add generated fields in dict"""
    dict["user"] = getpass.getuser()
    dict["creation"] = datetime.datetime.combine(datetime.date.today(), datetime.datetime.min.time()) # get datetime instead of date, at time 0


def validate_dict(dict):
    """Validate dict"""
    if "_id" in dict:
        raise click.ClickException("cannot use _id field.")

    if "user" in dict:
        click.echo("Warning: overwriting user field", err=True)

    if "creation" in dict:
        click.echo("Warning: overwriting creation field", err=True)

    set_generated_fields(dict)


def validate_malware(malware):
    """Validate malware in dict"""
    validate_dict(malware)

    if "hashes" not in malware or type(malware["hashes"]) != list or any([type(hash) != str for hash in malware["hashes"]]):
        raise click.ClickException(f"cannot parse hashes field.")

    if "date" not in malware or str_to_datetime(malware["date"]) is None:
        raise click.ClickException(f"cannot parse date field.")
    malware["date"] = str_to_datetime(malware["date"])

    if "family" not in malware or type(malware["family"]) != str:
        raise click.ClickException(f"cannot parse family field.")

    if "type" not in malware or type(malware["type"]) != str:
        raise click.ClickException(f"cannot parse type field.")

    if "platform" not in malware or type(malware["platform"]) != str:
        raise click.ClickException(f"cannot parse platform field.")

    if "source" not in malware or type(malware["source"]) != str:
        raise click.ClickException(f"cannot parse source field.")

    if "location" not in malware or type(malware["location"]) != str:
        raise click.ClickException(f"cannot parse location field.")

    return malware


def validate_experiment(experiment):
    """Validate experiment in dict"""
    validate_dict(experiment)

    if "authors" not in experiment or type(experiment["authors"]) != list or any([type(author) != str for author in experiment["authors"]]):
        raise click.ClickException(f"cannot parse authors field.")

    if "samples" not in experiment or type(experiment["samples"]) != list or any([type(sample) != str for sample in experiment["samples"]]):
        raise click.ClickException(f"cannot parse samples field.")

    if "date" not in experiment or str_to_datetime(experiment["date"]) is None:
        raise click.ClickException(f"cannot parse date field.")
    experiment["date"] = str_to_datetime(experiment["date"])

    if "description" not in experiment or type(experiment["description"]) != str:
        raise click.ClickException(f"cannot parse description field.")

    return experiment


def prompt_list(prompt, field, dict):
    values = []
    while True:
        value = click.prompt(f"{prompt} (stop to end)")
        if value != "stop":
            values.append(value)
        else:
            if len(values) == 0:
                click.echo("Error: enter at least one value.", err=True)
            else:
                break
    dict[field] = values

def prompt_additional(dict):
    while True:
        field_name = click.prompt("Additional field name (stop to end)")
        if field_name == "stop":
            break
        if field_name in dict:
            click.echo("Error: field already exists.", err=True)
            continue
        if field_name in "_id":
            click.echo("Error: cannot use _id field.", err=True)
            continue

        dict[field_name] = click.prompt(f"Value for {field_name}")


def prompt_malware(quiet):
    """Prompt user to create a malware"""
    malware = {}

    set_generated_fields(malware)

    if not quiet:
        click.echo("Enter the required fields for a malware.")

    prompt_list("Malware hash", "hashes", malware)
    malware["date"] = click.prompt("Malware date (YYYY-MM-DD format)", type=click.DateTime(['%Y-%m-%d']))
    malware["family"] = click.prompt("Malware family")
    malware["type"] = click.prompt("Malware type")
    malware["platform"] = click.prompt("Malware platform")
    malware["source"] = click.prompt("Malware source")
    malware["location"] = click.prompt("Malware location")

    if not quiet:
        click.echo("Enter the additional fields for this malware.")

    prompt_additional(malware)

    return malware


def prompt_experiment(quiet):
    """Prompt user to create an experiment"""
    experiment = {}

    set_generated_fields(experiment)

    if not quiet:
        click.echo("Enter the required fields for an experiment.")

    prompt_list("Experiment author", "authors", experiment)
    prompt_list("Experiment malware sample hash", "samples", experiment)
    experiment["date"] = click.prompt("Experiment date (YYYY-MM-DD format)", type=click.DateTime(['%Y-%m-%d']))
    experiment["description"] = click.prompt("Experiment description")

    if not quiet:
        click.echo("Enter the additional fields for this experiment.")

    prompt_additional(experiment)

    return experiment


def get_filters(inputs, creation, date, before, after, all):
    """Get pymongo filter from user inputs"""
    filters = []

    for filter in inputs:
        search_field, query = filter
        if search_field == "creation":
            raise click.ClickException("use specific creation option to filter on creation field.")
        if search_field == "date":
            raise click.ClickException("use specific date options to filter on date field.")
        if search_field == "_id":
            raise click.ClickException("cannot filter on _id field.")
        filters.append({search_field: re.compile(query, re.IGNORECASE)})

    if creation is not None:
        filters.append({"creation": creation})

    if date is not None:
        filters.append({"date": date})

    if before is not None:
        filters.append({"date": {"$lte": date}})

    if after is not None:
        filters.append({"date": {"$gte": date}})

    if len(filters) == 0:
        return {}

    return {"$and": filters} if all else {"$or": filters}
