# pip3 install pyyaml
# python3 yaml2json.py > arc-draft-validation-tests.json

import json
import yaml

VALIDATE_TEST_FILE = "arc-draft-validation-tests.yml"

scenarios = list(yaml.safe_load_all(open(VALIDATE_TEST_FILE, 'rb')))
print(json.dumps(scenarios, sort_keys=False, indent=4))
