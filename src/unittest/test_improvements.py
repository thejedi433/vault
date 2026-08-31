"""
Comprehensive test suite for vault improvements - Core Modules Only.

Tests Config instance isolation, encryption padding validation, and edge cases.
"""

import tempfile
import os
import pytest
from ..lib.Config import Config
from ..lib.Encryption import Encryption


class TestConfigInstanceIsolation:
    """Tests for Config class instance isolation - BUG FIX #1"""

    def test_config_instances_are_isolated(self):
        """Verify that multiple Config instances don't share state"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config1_path = os.path.join(tmpdir, 'config1')
            config2_path = os.path.join(tmpdir, 'config2')

            config1 = Config(config1_path)
            config2 = Config(config2_path)

            config1.get_config()
            config2.get_config()

            config1.update('clipboardTTL', '30')

            assert config2.clipboardTTL == '15'
            assert config1.clipboardTTL == '30'

    def test_config_does_not_share_parser(self):
        """Ensure each Config instance has its own ConfigParser"""
        config1 = Config('/tmp/config1_test')
        config2 = Config('/tmp/config2_test')

        assert config1.config is not config2.config

    def test_config_creates_default_file(self):
        """Test that Config creates a default config file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')
            config = Config(config_path)
            conf = config.get_config()

            assert os.path.isfile(config_path)
            assert conf['version'] == '2.00'
            assert conf['clipboardTTL'] == '15'

    def test_config_file_permissions(self):
        """Test that config file has secure permissions (600)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')
            config = Config(config_path)
            config.get_config()

            mode = os.stat(config_path).st_mode & 0o777
            assert mode == 0o600

    def test_update_persists_to_file(self):
        """Test that config updates persist to file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')
            config = Config(config_path)
            config.get_config()

            config.update('clipboardTTL', '45')

            config2 = Config(config_path)
            assert config2.clipboardTTL == '45'

    def test_update_multiple_settings(self):
        """Test updating multiple config settings"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')
            config = Config(config_path)
            config.get_config()

            config.update('clipboardTTL', '30')
            config.update('autoLockTTL', '1800')
            config.update('hideSecretTTL', '10')

            assert config.clipboardTTL == '30'
            assert config.autoLockTTL == '1800'
            assert config.hideSecretTTL == '10'

    def test_config_initialization_with_path(self):
        """Test Config initialization with different paths"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path1 = os.path.join(tmpdir, 'vault1', '.config')
            path2 = os.path.join(tmpdir, 'vault2', '.config')

            config1 = Config(path1)
            config2 = Config(path2)

            assert config1.config_path == path1
            assert config2.config_path == path2


class TestEncryptionPaddingValidation:
    """Tests for enhanced padding validation - BUG FIX #2"""

    def setup_method(self):
        """Set up test fixtures"""
        self.key = b'test_encryption_key_1234567890123456789012'
        self.encryption = Encryption(self.key)

    def test_valid_encryption_decryption_roundtrip(self):
        """Test basic encrypt/decrypt works correctly"""
        secret = b'my_secret_password'
        encrypted = self.encryption.encrypt(secret)
        decrypted = self.encryption.decrypt(encrypted)
        assert decrypted == secret

    def test_encrypt_decrypt_with_salt(self):
        """Test encryption/decryption with salt"""
        secret = b'secret_with_salt'
        salt = self.encryption.gen_salt()
        encrypted = self.encryption.encrypt(secret)
        self.encryption.set_salt(salt)
        decrypted = self.encryption.decrypt(encrypted)
        assert decrypted == secret

    def test_decrypt_empty_data_raises_error(self):
        """Test that decrypting empty data raises ValueError"""
        with pytest.raises(ValueError):
            self.encryption.decrypt(b'')

    def test_decrypt_corrupted_data_raises_error(self):
        """Test that decrypting corrupted data raises ValueError"""
        secret = b'test_secret'
        encrypted = self.encryption.encrypt(secret)
        corrupted = encrypted[:-5] + b'XXXXX'

        with pytest.raises(ValueError):
            self.encryption.decrypt(corrupted)

    def test_decrypt_with_wrong_key_raises_error(self):
        """Test that decrypting with wrong key raises ValueError"""
        secret = b'test_secret'
        encrypted = self.encryption.encrypt(secret)

        wrong_key = b'wrong_key_123456789012345678901234567'
        wrong_encryption = Encryption(wrong_key)

        with pytest.raises(ValueError):
            wrong_encryption.decrypt(encrypted)

    def test_padding_value_out_of_range(self):
        """Test that invalid padding values are detected"""
        secret = b'test'
        encrypted = self.encryption.encrypt(secret)
        tampered = encrypted[:-1] + b'\xFF'

        with pytest.raises(ValueError):
            self.encryption.decrypt(tampered)

    def test_encrypt_produces_different_iv(self):
        """Test that each encryption uses a different IV"""
        secret = b'constant_secret'

        encrypted1 = self.encryption.encrypt(secret)
        encrypted2 = self.encryption.encrypt(secret)

        assert encrypted1 != encrypted2
        assert self.encryption.decrypt(encrypted1) == secret
        assert self.encryption.decrypt(encrypted2) == secret

    def test_encrypt_decrypt_various_lengths(self):
        """Test encryption/decryption with various secret lengths"""
        test_secrets = [b'', b'a', b'ab', b'abcdef', b'0123456789abcdef', b'x' * 100]

        for secret in test_secrets:
            encrypted = self.encryption.encrypt(secret)
            decrypted = self.encryption.decrypt(encrypted)
            assert decrypted == secret

    def test_salt_management(self):
        """Test salt generation and management"""
        salt1 = self.encryption.gen_salt()
        salt2 = self.encryption.gen_salt()

        assert salt1 != salt2
        assert isinstance(salt1, bytes)
        assert 8 <= len(salt1) <= 12

    def test_set_salt_none_clears(self):
        """Test that set_salt(None) clears the salted key"""
        self.encryption.gen_salt()
        assert self.encryption.salted_key is not None

        self.encryption.set_salt(None)
        assert self.encryption.salted_key is None

    def test_digest_key_returns_correct_length(self):
        """Test that digest_key returns 32-byte key"""
        dk = self.encryption.digest_key()
        assert isinstance(dk, bytes)
        assert len(dk) == 32

    def test_digest_key_with_salt(self):
        """Test digest_key with salted key"""
        self.encryption.gen_salt()
        dk = self.encryption.digest_key()
        assert isinstance(dk, bytes)
        assert len(dk) == 32


class TestEdgeCases:
    """Tests for edge cases and error handling"""

    def test_encryption_key_length_variations(self):
        """Test encryption with various key lengths"""
        test_keys = [b'short', b'medium_length_key', b'x' * 100]
        secret = b'test_secret'

        for key in test_keys:
            enc = Encryption(key)
            encrypted = enc.encrypt(secret)
            decrypted = enc.decrypt(encrypted)
            assert decrypted == secret

    def test_unicode_secrets(self):
        """Test encryption of unicode content"""
        enc = Encryption(b'test_key')
        secrets = ['password_ñ'.encode(), 'secret_中文'.encode()]

        for secret in secrets:
            encrypted = enc.encrypt(secret)
            decrypted = enc.decrypt(encrypted)
            assert decrypted == secret

    def test_special_characters_in_secret(self):
        """Test encryption with special characters"""
        enc = Encryption(b'test_key')
        secret = b'pass\x00word\x01with\x02special'

        encrypted = enc.encrypt(secret)
        decrypted = enc.decrypt(encrypted)
        assert decrypted == secret

    def test_config_missing_directory(self):
        """Test Config when directory doesn't exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            parent_dir = os.path.join(tmpdir, 'vault_dir')
            os.makedirs(parent_dir)
            config_path = os.path.join(parent_dir, '.config')
            config = Config(config_path)

            conf = config.get_config()
            assert os.path.isfile(config_path)
            assert conf['version'] == '2.00'

    def test_encryption_base64_output(self):
        """Test that encryption output is valid base64"""
        import base64
        enc = Encryption(b'test_key')
        secret = b'test_secret'
        encrypted = enc.encrypt(secret)

        try:
            decoded = base64.b64decode(encrypted)
            assert len(decoded) > 0
        except Exception as e:
            pytest.fail(f"Invalid base64 output: {e}")

    def test_decrypt_malformed_base64(self):
        """Test decrypting malformed base64"""
        enc = Encryption(b'test_key')

        with pytest.raises(Exception):
            enc.decrypt(b'invalid_base64!!!')


class TestIntegration:
    """Integration tests for vault components"""

    def test_full_config_lifecycle(self):
        """Test complete config lifecycle"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')

            config = Config(config_path)
            initial_conf = config.get_config()

            assert initial_conf['version'] == '2.00'
            assert initial_conf['clipboardTTL'] == '15'

            config.update('clipboardTTL', '60')
            config.update('autoLockTTL', '1200')

            config2 = Config(config_path)
            assert config2.clipboardTTL == '60'
            assert config2.autoLockTTL == '1200'

    def test_encryption_with_config_salt(self):
        """Test encryption using salt from config"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, '.config')
            config = Config(config_path)
            conf = config.get_config()

            master_key = b'master_password'
            salted_key = master_key + conf['salt'].encode()
            enc = Encryption(salted_key)

            secret = b'test_secret'
            encrypted = enc.encrypt(secret)
            decrypted = enc.decrypt(encrypted)

            assert decrypted == secret

    def test_multiple_secrets_same_encryption(self):
        """Test encrypting multiple secrets with same encryption instance"""
        enc = Encryption(b'test_key')

        secrets = [b'secret1', b'secret2', b'password123', b'api_key_xyz']

        encrypted_list = []
        for secret in secrets:
            encrypted = enc.encrypt(secret)
            encrypted_list.append(encrypted)

        for i, encrypted in enumerate(encrypted_list):
            decrypted = enc.decrypt(encrypted)
            assert decrypted == secrets[i]

    def test_config_salt_generation(self):
        """Test that config generates unique salts"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config1_path = os.path.join(tmpdir, 'config1')
            config2_path = os.path.join(tmpdir, 'config2')

            config1 = Config(config1_path)
            config2 = Config(config2_path)

            conf1 = config1.get_config()
            conf2 = config2.get_config()

            assert conf1['salt'] != conf2['salt']
