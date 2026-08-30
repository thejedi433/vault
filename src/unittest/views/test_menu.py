from unittest.mock import patch

from ..base import BaseTest
from ...models.Secret import SecretModel
from ...views import menu
from ...modules.carry import global_scope


class Test(BaseTest):

    def setUp(self):
        # Preserve enc to restore it on tear down
        self.enc_save = global_scope['enc']

    def tearDown(self):
        # restore enc in global scope
        global_scope['enc'] = self.enc_save

    def test_get_input(self):
        with patch('builtins.input', return_value='some input'):
            self.assertEqual(menu.get_input(), 'some input')

    def test_get_input_2(self):
        with patch('getpass.getpass', return_value='some secure input'):
            self.assertEqual(menu.get_input(secure=True), 'some secure input')

    def test_get_input_3(self):
        with patch('builtins.input', return_value='SOME INPUT'):
            self.assertEqual(menu.get_input(lowercase=True), 'some input')

    def test_get_input_4(self):
        with patch('builtins.input', return_value='some input'):
            self.assertEqual(menu.get_input(
                non_locking_values=['a', 'b', 'c']), 'some input')

    def test_unlock(self):
        with patch('getpass.getpass', return_value=self.secret_key):
            self.assertTrue(menu.unlock(redirect_to_menu=False))

    @patch.object(menu, 'menu')
    def test_unlock_2(self, patched):
        patched.return_value = None
        with patch('getpass.getpass', return_value=self.secret_key):
            self.assertIsNone(menu.unlock(redirect_to_menu=True))

    def test_unlock_3(self):
        with patch('getpass.getpass', return_value='wrong password'):
            self.assertRaises(SystemExit, menu.unlock)

    def test_unlock_4(self):
        # Simulate user pressing Ctrl-C
        with patch('getpass.getpass', return_value=False):
            self.assertRaises(SystemExit, menu.unlock)

    def test_validate_key(self):
        self.assertTrue(menu.validate_key(
            self.secret_key))

    def test_validate_key_2(self):
        self.assertFalse(menu.validate_key(
            'some invalid key'))

    def test_menu(self):
        with patch('builtins.input', return_value='q'):
            self.assertRaises(SystemExit, menu.menu)

    def test_menu_2(self):
        self.assertRaises(SystemExit, menu.menu, next_command='q')

    @patch.object(menu, 'unlock')
    def test_lock(self, patched):
        patched.return_value = None
        self.assertIsNone(menu.lock())
        self.assertIsNone(global_scope['enc'])

    def test_quit(self):
        self.assertRaises(SystemExit, menu.quit)

    def test_set_autolock_timer(self):
        menu.set_autolock_timer()
        self.assertIsInstance(menu.timer, int)

    def test_check_autolock_timer(self):
        menu.check_autolock_timer()
        self.assertIsNone(menu.check_autolock_timer())

    # @patch.object(menu, 'menu')
    # def test_check_autolock_timer_2(self, patched):
    #     patched.return_value = None
    #     with patch('getpass.getpass', return_value=self.secret_key):
    #         menu.timer = 100
    #         self.assertIsNone(menu.check_autolock_timer())

    def test_check_then_set_autolock_timer(self):
        menu.check_then_set_autolock_timer()
        self.assertIsNone(menu.check_then_set_autolock_timer())

    def test_get_input_keyboard_interrupt(self):
        """Test get_input when KeyboardInterrupt is raised."""
        with patch('builtins.input', side_effect=KeyboardInterrupt):
            self.assertFalse(menu.get_input(message='prompt: '))

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_all(self, *_):
        """Test menu with 'all' command."""
        from ...views import secrets
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
        """Test menu with 'add' command."""
        from ...views import secrets
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
        """Test menu with 'lock' command."""
        from ...views import secrets
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
        """Test menu when command is False (KeyboardInterrupt)."""
        from ...views import secrets
        with patch.object(secrets, 'count', return_value=0):
            call_count = [0]

            def fake_get_input(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return False
                return 'q'

            with patch.object(menu, 'get_input', side_effect=fake_get_input):
                with self.assertRaises(SystemExit):
                    menu.menu()

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_autolock_expires(self, *_):
        """Test autolock expiration path."""
        import time
        from ...views import secrets
        with patch.object(secrets, 'count', return_value=0):
            menu.timer = int(time.time()) - 10000
            global_scope['conf'].update('autoLockTTL', '1')
            with patch.object(menu, 'get_input', return_value='q'):
                with patch.object(menu, 'lock') as mock_lock:
                    with self.assertRaises(SystemExit):
                        menu.menu()
                    mock_lock.assert_called()
            menu.timer = None

    @patch.object(menu, 'clear_screen')
    @patch.object(menu, 'logo_small')
    def test_menu_command_search(self, *_):
        """Test menu with 'search' command."""
        from ...views import secrets
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
