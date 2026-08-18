# Import/export view

import sys

from sqlalchemy.orm import Session

from . import menu, secrets
from .setup import get_key_input
from ..modules.carry import global_scope
from ..lib.Encryption import Encryption
from .users import validation_key_rekey
from ..models.base import Base, get_session, get_engine
from ..models.Category import CategoryModel  # Imported for schema creation
from ..models.Secret import SecretModel  # Imported for schema creation
from ..models.User import UserModel  # Imported for schema creation

enc_current = enc_new = None


def rekey():
    """
        Change the master key. This involves 3 steps:
         - Looping thru all secrets and encrypting them with the new key
         - Updating the validation key
         - Re-keying the database
    """

    global enc_current, enc_new

    # Ask user to unlock the vault
    print('\n* Please enter your CURRENT master key:')
    unlock()

    # Set instance of current Encryption class
    enc_current = global_scope['enc']

    # Ask the user to enter the new master key
    print('\n* Please enter your NEW master key:\n')
    newkey = get_key_input()

    if newkey:
        # Set instance of new Encryption class
        enc_new = Encryption(newkey.encode())

        # Loop thru all secrets and encrypt them with the new key
        rekey_secrets()

        # Re-key the validation key with the new master key
        rekey_validation_key()

        # Change the db encryption key
        rekey_db()

        print('\nYour master key has been updated.')
        print('You can now re-start the application.')

        return True

    return False


def rekey_secrets():
    """
        Loop thru all secrets and encrypt them with the new key
    """

    for secret in secrets.all():
        # Get current values
        password = secret.password
        notes = secret.notes

        # Set Encryption to new class
        global_scope['enc'] = enc_new

        # Update password, notes
        secret.password = password
        secret.notes = notes

        # Revert Encryption to current class
        global_scope['enc'] = enc_current

        get_session().add(secret)

    get_session().commit()

    return True


def rekey_validation_key():
    """
        Re-key the validation key with the new master key
    """

    return validation_key_rekey(enc_new)


def rekey_db():
    """
    Change the database encryption key.

    This function re-encrypts the entire database with the new master key
    by using SQLCipher's PRAGMA rekey command.
    """
    import sqlcipher3
    from hashlib import sha256

    # Get the current and new database keys
    current_key = sha256(enc_current.key + global_scope['conf'].salt.encode()).hexdigest()
    new_key = sha256(enc_new.key + global_scope['conf'].salt.encode()).hexdigest()

    # Open connection to the database with the current key
    conn = sqlcipher3.connect(global_scope['db_file'])
    conn.execute(f"PRAGMA key = '{current_key}'")

    # Rekey the database with the new key
    conn.execute(f"PRAGMA rekey = '{new_key}'")
    conn.commit()
    conn.close()

    # Update global scope to use the new encryption
    global_scope['enc'] = enc_new

    # Drop existing sessions to force reconnection with new key
    from ..models.base import drop_sessions
    drop_sessions()

    print('Database encryption key has been successfully updated.')
    return True


# def new_db_get_engine():
#     """
#         Will return a SQLite engine with the new key and a temporary location
#     """

#     # Save db file
#     db_file = global_scope['db_file']

#     # Update global scope
#     global_scope['enc'] = enc_new
#     global_scope['db_file'] = db_file + '.new'

#     # Create engine
#     engine = get_engine()

#     # Restore db file
#     global_scope['db_file'] = db_file

#     return engine


def unlock():
    """
        Ask user to unlock the vault
    """

    # `False` = don't load menu after unlocking
    return menu.unlock(redirect_to_menu=False)
