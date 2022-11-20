import os

import tomlkit


class TOMLConfig:
    def __init__(self, path: str,  *args, **kwargs):
        """
        Read and write *.toml files
        :param path: str, path to *.toml file
        """
        self.path = path
        self.settings = None

        if self._valid_file():
            self._load_from_file()

    def _valid_file(self):
        if os.path.isfile(self.path) and self.path.endswith('.toml'):
            return True

        print(f'{self.path} is not a valid path of the toml file.')
        return False

    def _load_from_file(self):
        try:
            with open(self.path, 'rt', encoding="utf-8") as file:
                self.settings = tomlkit.load(file)
        except Exception as e:
            print(str(e))

    def _save_to_file(self):
        try:
            with open(self.path, 'wt', encoding="utf-8") as file:
                tomlkit.dump(self.settings, file)
        except Exception as e:
            print(str(e))

    def get(self, category, sub_category, key):
        if self._valid_file():
            self._load_from_file()
            try:
                if sub_category:
                    return self.settings[category][sub_category][key]
                else:
                    return self.settings[category][key]
            except Exception:
                print(f'"[{category}] {sub_category} {key}" key does not exists')

    def set(self, category, sub_category, key, value):
        if self._valid_file():
            self._load_from_file()
            try:
                if sub_category:
                    self.settings[category][sub_category][key] = value
                else:
                    self.settings[category][key] = value
            except:
                self.settings[category].add(key, value)

            self._save_to_file()
            return True
