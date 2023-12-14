#  Класс с перечислением режимов блочной шифрации
import enum


class encrypt_mode(enum.Enum):
    ECB = "ECB"
    CBC = "CBC"
    CFB = "CFB"
    OFB = "OFB"
