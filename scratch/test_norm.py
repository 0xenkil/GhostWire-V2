import re


def normalize(raw_target):
    clean_target = raw_target
    while True:
        prev = clean_target
        clean_target = re.sub(
            r'^https?://',
            '',
            clean_target,
            flags=re.IGNORECASE).strip('/')
        print(f"Loop: '{prev}' -> '{clean_target}'")
        if clean_target == prev:
            break
    return clean_target


print(f"Result 1: {normalize('https://https://novalink.lk')}")
print(f"Result 2: {normalize('novalink.lk')}")
print(f"Result 3: {normalize('http://novalink.lk/')}")
