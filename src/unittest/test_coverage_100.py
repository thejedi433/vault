"""Tests to fill remaining coverage gaps and reach 100%."""
import time
import base64
from unittest.mock import patch, MagicMock

import pyperclip

from .base import BaseTest
from ..lib.Encryption import Encryption
from ..modules import autocomplete, misc
from ..views import clipboard, menu, secrets
from ..modules.carry import global_scope
from .. import vault


class TestEncryption(BaseTest):
    """Test empty-data path in Encryption.decrypt (line 116)."""

    def test_decrypt_empty_data_after_unpad(self):
        # AES.decrypt always returns block-aligned data (at least one block).
        # Line 116 (empty data) is defensive dead code - cover with pragma
        # Instead test that the path works via direct patching of AES decrypt
        enc = Encryption(b'testkey123456789')
        enc.gen_salt()
        IV = b'\x00' * 16
        aes = enc.get_aes(IV)
        # Create a valid encrypted blob, then patch aes.decrypt to return b''
        with patch.object(aes, 'decrypt', return_value=b''):
            with patch.object(enc, 'get_aes', return_value=aes):
                # We need a valid base64 blob for b64decode to work
                fake_enc = base64.b64encode(IV + b'\x00' * 16)
                self.assertRaises(ValueError, enc.decrypt, fake_enc)

    def test_decrypt_invalid_padding(self):
        # Line 126: Invalid padding when padding bytes don't match
        enc = Encryption(b'testkey123456789')
        enc.gen_salt()
        IV = b'\x00' * 16
        # Create data with invalid padding: 16 bytes where last byte is 0x05 but padding should be 0x01
        invalid_data = b'\x00' * 15 + b'\x05'
        aes = enc.get_aes(IV)
        encrypted = aes.encrypt(invalid_data)
        # Try to decrypt - should raise ValueError for invalid padding
        with self.assertRaises(ValueError):
            enc.decrypt(base64.b64encode(IV + encrypted))


class TestAutocomplete(BaseTest):
    """Test breaking-string handling and readline bindings."""

    def test_completer_with_breaking_chars(self):
        # Trigger strip_pos > 0 branch (line 38)
        # find_breaking_strings checks for ' ', '@', '?', '#', '$', '%', '&', '*'
        # Set completion list and use buffer with '@'
        autocomplete.set_parameters(list_=['user@gmail.com', 'user2@gmail.com'], case_sensitive=True)
        with patch('readline.get_line_buffer', return_value='user@gmail.com'):
            # state=0 should give us the part after the '@'
            result = autocomplete.autocomplete('user@gmail.com', 0)
            self.assertIsNotNone(result)
            # Result should be truncated starting after strip_pos
            self.assertIsInstance(result, str)

    def test_prompt_libedit(self):
        # Line 63-64: libedit path
        with patch('readline.__doc__', 'using libedit'):
            with patch('readline.parse_and_bind') as mock_bind:
                with patch('readline.set_completer'):
                    with patch('builtins.input', return_value='  hello  '):
                        result = autocomplete.get_input_autocomplete('prompt: ')
                        self.assertEqual(result, 'hello')
                        mock_bind.assert_called_with("bind ^I rl_complete")

    def test_prompt_gnu_readline(self):
        # Line 66: GNU readline path
        with patch('readline.__doc__', 'GNU readline'):
            with patch('readline.parse_and_bind') as mock_bind:
                with patch('readline.set_completer'):
                    with patch('builtins.input', return_value='test'):
                        result = autocomplete.get_input_autocomplete('prompt: ')
                        self.assertEqual(result, 'test')
                        mock_bind.assert_called_with("tab: complete")

    def test_prompt_keyboard_interrupt(self):
        # Lines 71-72
        with patch('readline.__doc__', 'GNU readline'):
            with patch('readline.parse_and_bind'):
                with patch('readline.set_completer'):
                    with patch('builtins.input', side_effect=KeyboardInterrupt):
                        result = autocomplete.get_input_autocomplete('prompt: ')
                        self.assertFalse(result)


class TestMisc(BaseTest):
    """Test erase_vault file removal and misc edge cases."""

    def test_erase_vault_files_removed(self):
        import tempfile
        import os
        fa = tempfile.NamedTemporaryFile(delete=False)
        fb = tempfile.NamedTemporaryFile(delete=False)
        fa.write(b'x')
        fa.close()
        fb.write(b'y')
        fb.close()
        with patch('src.modules.misc.confirm', return_value=True):
            self.assertRaises(SystemExit, misc.erase_vault, fa.name, fb.name)
        self.assertFalse(os.path.isfile(fa.name))
        self.assertFalse(os.path.isfile(fb.name))

    def test_confirm_invalid_input(self):
        # Lines 127-128: invalid then valid
        with patch('builtins.input', side_effect=['x', 'y']):
            self.assertTrue(misc.confirm())

    def test_is_unicode_not_supported(self):
        # Line 143: sys.stdout.encoding doesn't start with 'utf'
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.encoding = 'ascii'
            with patch('sys.platform', 'linux'):
                self.assertFalse(misc.is_unicode_supported())

    def test_is_unicode_stdout_encoding_none(self):
        # Line 143: sys.stdout.encoding is None (defensive code)
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.encoding = None
            self.assertFalse(misc.is_unicode_supported())

    def test_lock_prefix_not_supported(self):
        # Line 155
        with patch('src.modules.misc.is_unicode_supported', return_value=False):
            self.assertEqual(misc.lock_prefix(), '')


class TestClipboard(BaseTest):
    """Test clipboard exception paths."""

    @patch.object(pyperclip, 'copy', side_effect=pyperclip.PyperclipException('no clipboard'))
    def test_copy_exception(self, *_):
        # Lines 25-27
        self.assertFalse(clipboard.copy('text'))

    @patch.object(pyperclip, 'copy')
    @patch.object(pyperclip, 'paste')
    def test_wait_keyboard_interrupt(self, mock_paste, mock_copy):
        # Lines 74-76
        mock_paste.return_value = 'some string'
        clipboard.clipboard_signature = clipboard.get_signature('some string')
        original_sleep = time.sleep
        def fake_sleep(_):
            raise KeyboardInterrupt
        with patch('time.sleep', side_effect=fake_sleep):
            self.assertIsNone(clipboard.wait())


class TestMenu(BaseTest):
    """Test menu KeyboardInterrupt and command paths."""

    def test_get_input_keyboard_interrupt(self):
        # Lines 33-34
        with patch('builtins.input', side_effect=KeyboardInterrupt):
            self.assertFalse(menu.get_input(message='prompt: '))

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_all(self, *_):
        # Lines 116, 118-120
        with patch.object(secrets, 'to_table', return_value='table'):
            with patch.object(secrets, 'all', return_value=[]):
                with patch.object(secrets, 'count', return_value=0):
                    with patch.object(secrets, 'search_input', return_value='q'):
                        call_count = [0]
                        def fake_get_input(*args, **kwargs):
                            call_count[0] += 1
                            if call_count[0] == 1:
                                return 'all'
                            return 'q'
                        with patch.object(menu, 'get_input', side_effect=fake_get_input):
                            with self.assertRaises(SystemExit):
                                menu.menu()

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_add(self, *_):
        # Line 122
        with patch.object(secrets, 'add_input', return_value=None):
            with patch.object(secrets, 'count', return_value=0):
                call_count = [0]
                def fake_get_input(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return 'a'
                    return 'q'
                with patch.object(menu, 'get_input', side_effect=fake_get_input):
                    with self.assertRaises(SystemExit):
                        menu.menu()

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_lock(self, *_):
        # Line 126
        with patch.object(secrets, 'count', return_value=0):
            call_count = [0]
            def fake_get_input(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return 'l'
                return 'q'
            with patch.object(menu, 'get_input', side_effect=fake_get_input):
                with patch.object(menu, 'lock') as mock_lock:
                    with self.assertRaises(SystemExit):
                        menu.menu()
                    mock_lock.assert_called()

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_print_empty_command(self, *_):
        # Line 112: command is False (KeyboardInterrupt returns False)
        with patch.object(secrets, 'count', return_value=0):
            call_count = [0]
            def fake_get_input(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return False  # KeyboardInterrupt path
                return 'q'
            with patch.object(menu, 'get_input', side_effect=fake_get_input):
                with self.assertRaises(SystemExit):
                    menu.menu()

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_autolock_expires(self, *_):
        # Lines 176-178
        with patch.object(secrets, 'count', return_value=0):
            menu.timer = int(time.time()) - 10000
            global_scope['conf'].update('autoLockTTL', '1')
            with patch.object(menu, 'get_input', return_value='q'):
                with patch.object(menu, 'lock') as mock_lock:
                    with self.assertRaises(SystemExit):
                        menu.menu()
                    mock_lock.assert_called()
            # Reset
            menu.timer = None


class TestSecrets(BaseTest):
    """Test secrets edge cases."""

    def test_get_names_empty(self):
        # Line 69
        from ..models.Secret import SecretModel
        self.session.query(SecretModel).delete()
        self.session.commit()
        self.assertEqual(secrets.get_names(), [])

    def test_get_top_logins_empty(self):
        # Line 87
        from ..models.Secret import SecretModel
        self.session.query(SecretModel).delete()
        self.session.commit()
        self.assertEqual(secrets.get_top_logins(), [])

    def test_add_input_name_cancelled(self):
        # Line 125
        with patch.object(menu, 'get_input', return_value=False):
            with patch.object(secrets, 'all_categories', return_value=[]):
                with patch('src.views.secrets.clear_screen'):
                    self.assertFalse(secrets.add_input())

    def test_add_input_url_cancelled(self):
        # Line 129
        call_count = [0]
        def fake_get_input(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return 'some name'
            return False
        with patch.object(menu, 'get_input', side_effect=fake_get_input):
            with patch.object(secrets, 'all_categories', return_value=[]):
                with patch('src.views.secrets.clear_screen'):
                    self.assertFalse(secrets.add_input())

    def test_add_input_login_cancelled(self):
        # Line 136
        call_count = [0]
        def fake_get_input(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                return 'value'
            return False
        with patch.object(menu, 'get_input', side_effect=fake_get_input):
            with patch.object(autocomplete, 'get_input_autocomplete', return_value=False):
                with patch.object(secrets, 'all_categories', return_value=[]):
                    with patch('src.views.secrets.clear_screen'):
                        self.assertFalse(secrets.add_input())

    def test_add_input_password_cancelled(self):
        # Line 143: password input returns False (user pressed Ctrl-C)
        def fake_get_input(message='', secure=False, **kwargs):
            if secure:
                return False  # Simulate Ctrl-C for password
            return 'val'
        with patch.object(menu, 'get_input', side_effect=fake_get_input):
            with patch.object(autocomplete, 'get_input_autocomplete', return_value='login'):
                with patch('passwordgenerator.pwgenerator.generate', return_value='suggestion'):
                    with patch.object(secrets, 'all_categories', return_value=[]):
                        with patch('src.views.secrets.clear_screen'):
                            self.assertFalse(secrets.add_input())

    def test_add_input_notes_cancelled(self):
        # Line 147
        with patch.object(menu, 'get_input', return_value='val'):
            with patch.object(autocomplete, 'get_input_autocomplete', return_value='login'):
                with patch('getpass.getpass', return_value='pw'):
                    with patch.object(secrets, 'notes_input', return_value=False):
                        with patch.object(secrets, 'all_categories', return_value=[]):
                            with patch('src.views.secrets.clear_screen'):
                                self.assertFalse(secrets.add_input())

    def test_item_menu_l_command(self):
        # Lines 362-364
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        with patch.object(clipboard, 'copy') as mock_copy:
            with patch.object(clipboard, 'wait') as mock_wait:
                call_count = [0]
                def fake_get_input(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return 'l'
                    return 'q'
                with patch.object(menu, 'get_input', side_effect=fake_get_input):
                    result = secrets.item_menu(secret)
                    mock_copy.assert_called()
                    self.assertEqual(result, 'q')

    def test_item_menu_p_command(self):
        # Lines 365-367
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        with patch.object(clipboard, 'copy') as mock_copy:
            with patch.object(clipboard, 'wait') as mock_wait:
                call_count = [0]
                def fake_get_input(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return 'p'
                    return 'q'
                with patch.object(menu, 'get_input', side_effect=fake_get_input):
                    result = secrets.item_menu(secret)
                    self.assertEqual(result, 'q')

    def test_item_menu_u_command(self):
        # Lines 368-370
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        with patch.object(clipboard, 'copy') as mock_copy:
            with patch.object(clipboard, 'wait') as mock_wait:
                call_count = [0]
                def fake_get_input(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return 'u'
                    return 'q'
                with patch.object(menu, 'get_input', side_effect=fake_get_input):
                    result = secrets.item_menu(secret)
                    self.assertEqual(result, 'q')

    def test_item_menu_o_command(self):
        # Line 371-372
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        with patch.object(secrets, 'show_secret', return_value='q') as mock_show:
            call_count = [0]
            def fake_get_input(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return 'o'
                return 'q'
            with patch.object(menu, 'get_input', side_effect=fake_get_input):
                result = secrets.item_menu(secret)
                mock_show.assert_called()
                self.assertEqual(result, 'q')

    def test_item_menu_e_command(self):
        # Lines 373-374
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        with patch.object(secrets, 'item_menu_edit') as mock_edit:
            call_count = [0]
            def fake_get_input(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return 'e'
                return 'q'
            with patch.object(menu, 'get_input', side_effect=fake_get_input):
                result = secrets.item_menu(secret)
                mock_edit.assert_called()
                self.assertEqual(result, 'q')

    def test_item_menu_false_command(self):
        # Lines 358-359
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        call_count = [0]
        def fake_get_input(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return False
            return 'q'
        with patch.object(menu, 'get_input', side_effect=fake_get_input):
            result = secrets.item_menu(secret)
            self.assertEqual(result, 'q')

    def test_search_input_exception_path(self):
        # Lines 284-287: KeyboardInterrupt/Exception in search_input's try
        # This path is when no results and time.sleep raises
        with patch.object(secrets, 'search_dispatch', return_value=[]):
            with patch('time.sleep', side_effect=KeyboardInterrupt):
                with patch('builtins.input', return_value='nonexistent'):
                    self.assertFalse(secrets.search_input())

    def test_search_input_other_exception(self):
        # Lines 286-287: Other exception
        with patch.object(secrets, 'search_dispatch', return_value=[]):
            with patch('time.sleep', side_effect=Exception('other')):
                with patch('builtins.input', return_value='nonexistent'):
                    self.assertFalse(secrets.search_input())

    def test_show_secret_keyboard_interrupt(self):
        # Lines 508-510
        from ..models.Secret import SecretModel
        secret = self.session.query(SecretModel).first()
        if secret is None:
            secret = SecretModel(name='X', url='http://x.com', login='u', password='p', notes='')
            self.session.add(secret)
            self.session.commit()
            secret = self.session.query(SecretModel).first()
        global_scope['conf'].update('hideSecretTTL', '1')
        def fake_sleep(_):
            raise KeyboardInterrupt
        with patch('time.sleep', side_effect=fake_sleep):
            with patch.object(secrets, 'item_view', return_value=None):
                self.assertIsNone(secrets.show_secret(secret))


class TestVaultInit(BaseTest):
    """Test vault.initialize edge cases."""

    def test_initialize_setup_returns_false(self):
        # Lines 126-127
        with patch.object(vault.setup, 'initialize', return_value=False):
            with patch('os.path.isfile', return_value=False):
                with patch('src.vault.check_directory'):
                    with patch('src.vault.assess_integrity'):
                        with patch.object(vault, 'config_update'):
                            result = vault.initialize(
                                '/tmp/nonexistent_vault.db',
                                self.conf_path.name + '/config')
                            self.assertFalse(result)

    def test_vault_migration_path(self):
        # Lines 95-96: migration from Vault 1.x
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, 'vault.db')
            config_path = os.path.join(tmpdir, 'config')
            # Create config with version 1.x - must use [MAIN] section
            with open(config_path, 'w') as f:
                f.write('[MAIN]\n')
                f.write('version = 1.00\n')
                f.write('encrypteddb = True\n')
                f.write('salt = test-salt\n')
            with patch('src.vault.migrate') as mock_migrate:
                with patch.object(vault.sys, 'exit', side_effect=SystemExit(0)) as mock_exit:
                    with patch('src.vault.check_directory'):
                        with patch('src.vault.assess_integrity', return_value=True):
                            with patch.object(vault, 'config_update'):
                                with self.assertRaises(SystemExit):
                                    vault.initialize(vault_path, config_path)
                                mock_migrate.assert_called_once()
                                mock_exit.assert_called_once()


class TestMenuCommandSearch(BaseTest):
    """Test menu command 's' for search."""

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_search(self, *_):
        # Line 116: command == 's'
        with patch.object(secrets, 'count', return_value=0):
            with patch.object(secrets, 'search_input', return_value='q') as mock_search:
                call_count = [0]
                def fake_get_input(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return 's'
                    return 'q'
                with patch.object(menu, 'get_input', side_effect=fake_get_input):
                    with self.assertRaises(SystemExit):
                        menu.menu()
                    mock_search.assert_called_once()
