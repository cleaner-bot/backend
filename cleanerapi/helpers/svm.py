from binascii import crc32


def svm(data: bytes) -> bytes:
    key1 = data[0]
    key2 = [x ^ key1 for x in data[1:9]]

    instruction_lookup = bytearray(256)
    instruction_iv = crc32(bytes(x ^ key2[i & 4] for i, x in enumerate(data[9:25])))
    for _ in range(1024):
        instruction_bytes = bytes(
            [
                instruction_iv >> 24,
                instruction_iv >> 16 & 0xFF,
                instruction_iv >> 8 & 0xFF,
                instruction_iv & 0xFF,
            ]
        )
        instruction_lookup[instruction_bytes[0]] = instruction_bytes[1]
        instruction_lookup[instruction_bytes[2]] = instruction_bytes[3]
        instruction_iv = crc32(instruction_bytes)

    memory = bytearray(256)
    for i in range(256):
        if i & 3 == 0:
            memory[i] = (data[25 + i] + data[281 + i]) & 0xFF
        elif i & 3 == 1:
            memory[i] = (data[25 + i] - data[281 + i]) & 0xFF
        elif i & 3 == 2:
            memory[i] = data[25 + i] ^ data[281 + i]
        else:
            memory[i] = data[25 + i] ^ data[281 + i] ^ key1

    for i in range(0, len(data) - 2, 3):
        instr = instruction_lookup[data[i]] % 11
        is_addr = instr & 1 == 0
        byte1 = data[i + 1]
        byte2 = data[i + 2]
        value = memory[byte2] if is_addr else byte2
        if instr >> 1 == 0:
            memory[byte1] = (memory[byte1] + value) & 0xFF
        elif instr >> 1 == 1:
            memory[byte1] = (memory[byte1] - value) & 0xFF
        elif instr >> 1 == 2:
            memory[byte1] = memory[byte1] | value
        elif instr >> 1 == 3:
            memory[byte1] = memory[byte1] & value
        elif instr >> 1 == 4:
            memory[byte1] = memory[byte1] ^ value

    return memory
