# pip3 install pyyaml
# cat arc-draft-validation-tests.yml | python3 yaml2json.py > arc-draft-validation-tests.json
# cat arc-draft-sign-tests.yml | python3 yaml2json.py > arc-draft-sign-tests.json

import json
import yaml
import sys

scenarios = list(yaml.safe_load_all(sys.stdin.read()))
print(json.dumps(scenarios, sort_keys=False, indent=4))
