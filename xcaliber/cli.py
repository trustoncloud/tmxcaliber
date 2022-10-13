import json
from argparse import ArgumentParser
from argparse import Namespace


def get_params():
    parser = ArgumentParser()
    parser.add_argument("source", type=str, help="path to threat model JSON file.")

    args = parser.parse_args()
    validate(args)
    return args


def validate(args: Namespace):
    pass


if __name__ == "__main__":
    params = get_params()

    try:
        data = json.load(open(params.source))
    except FileNotFoundError:
        print("File not found:", params.source)
        exit(1)
    except json.JSONDecodeError:
        print("Invalid JSON data for the threat model:", params.source)
        exit(1)
