import os


def get(path: str):
    """Return value stored with `pass` manager"""
    # return store.get_key(path=path).strip()
    with open(os.path.join(path, f'.secret'), 'r') as file:
        return file.read()


def set(value, path: str):
    """Sety new key:value stored with `pass` manager"""
    # print(path, value)
    # return store.set_key(path=path, key_data=value, force=False)
    with open(os.path.join(path, f'.secret'), 'w') as file:
        file.write(value)

    return path
