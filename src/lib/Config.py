import configparser
import os
from uuid import uuid4


class Config:
    """
    Configuration manager for the vault application.

    Handles reading, writing, and managing vault configuration settings
    including encryption salts, TTL settings, and version information.
    """

    def __init__(self, config_path: str):
        """
        Initialize Config with a path to the configuration file.

        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        # BUG FIX: Moved from class-level to instance-level to prevent
        # shared mutable state between Config instances
        self.config = configparser.ConfigParser()

    def get_config(self):
        """
            Will return a user config and set a default if necessary
        """

        # Generate a default config the first time
        if not os.path.isfile(self.config_path):
            self.set_default_config_file()

        # Load existing config
        self.config.read(self.config_path)
        return self.config['MAIN']

    def set_default_config_file(self):
        """
        Set a user default configuration file with initial settings.

        Creates a new config file with default values for version, salt,
        and TTL settings.
        """
        # Set each config value individually to avoid type issues
        self.config['MAIN'] = {}
        self.config['MAIN']['version'] = '2.00'
        self.config['MAIN']['keyVersion'] = '1'
        self.config['MAIN']['salt'] = self.generate_random_salt()
        self.config['MAIN']['clipboardTTL'] = '15'
        self.config['MAIN']['hideSecretTTL'] = '5'
        self.config['MAIN']['autoLockTTL'] = '900'
        self.config['MAIN']['encryptedDb'] = 'True'

        # Save
        self.save_config()

    def update(self, name, value):
        """
            Update a config value
        """

        # Ensure config is initialized (MAIN section exists)
        if 'MAIN' not in self.config:
            self.get_config()

        # Set new value
        self.config['MAIN'][name] = str(value)

        print()
        print('The setting `%s` is now set to `%s`.' % (name, value))
        print()

        # Save
        return self.save_config()

    def save_config(self):
        """
            Save user config to a file
        """

        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)
        os.chmod(self.config_path, 0o600)

        return True

    def generate_random_salt(self):
        """
            Generate a random salt
            Will be used to generate the vault hash with the user master key
        """

        return str(uuid4())

    def __getattr__(self, name):
        """
            Allows calls to configuration values:
            config = Config()
            print(config.salt) # Will print the salt
        """

        try:
            return self.get_config()[name]
        except KeyError:  # For values that don't exist in the config file
            return None
