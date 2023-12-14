# Кольцевой сдвиг влево числа number, представленного в двоичном виде как слово длиной width бит
def bit_rotation_left(number, world_width, shift_range):
    result = ((number << shift_range) % (1 << world_width)) | (number >> (world_width - shift_range))
    return result


# Кольцевой сдвиг вправо числа number, представленного в двоичном виде как слово длиной width бит
def bit_rotation_right(number, world_width, shift_range):
    shift_range = world_width - shift_range
    result = ((number << shift_range) % (1 << world_width)) | (number >> (world_width - shift_range))
    return result
