import json


def load_config(name):
    with open("config.json", 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config.get(name)

