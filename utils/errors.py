class NodeError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        if 'url' in self.message.lower():
            return f'Check provided node API URL, is target server running?'
        elif 'binary' in self.message.lower():
            return f'Provide valid path to the epic server binary or add it to the PATH env variable.\n' \
                   f'Without access to binary file, node can be initialized with access="remote" and valid "api_url"'
        elif 'version' in self.message.lower():
            return f"Software version is not supported."
        elif 'NotEnoughFunds' in self.message:
            return f'Not enough funds'
