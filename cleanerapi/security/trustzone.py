from __future__ import annotations

import base64
import math
import random
import shlex
import typing
from itertools import chain

BOOLEAN_VALUES = ("true", "false", "null", "undefined")
INSTRUCTIONS = (
    "set",
    "index",
    "index_store",
    "call_0",
    "call_1",
    "call_2",
    "call_3",
    "call_4",
    "call_5",
    "call_6",
    "call_7",
    "call_8",
    "call_9",
    "new_0",
    "new_1",
    "new_2",
    "new_3",
    "new_4",
    "new_5",
    "new_6",
    "new_7",
    "new_8",
    "new_9",
    "syscall_0",
    "syscall_1",
    "syscall_2",
    "syscall_3",
    "syscall_4",
    "syscall_5",
    "syscall_6",
    "syscall_7",
    "syscall_8",
    "syscall_9",
    "sysget",
    "await",
    "jump",
    "jumpif",
    "jumpunless",
    "add",
    "sub",
    "mul",
    "div",
    "mod",
    "xor",
    "and",
    "or",
    "lshift",
    "rshift",
    "inv",
    "not",
    "plus",
    "minus",
    "eq",
    "ne",
    "seq",
    "sne",
    "lt",
    "le",
    "gt",
    "ge",
    "stop",
)


class Variable(typing.NamedTuple):
    is_encrypted: bool
    is_dynamic: bool
    value: str

    def is_number(self) -> bool:
        return (
            self.value.isdigit()
            or (self.value.startswith("-") and self.value[1:].isdigit())
            or self.value.startswith("0x")
        )

    def is_string(self) -> bool:
        return self.value[0] == self.value[-1] and self.value[0] in ("'", '"')

    def is_bool(self) -> bool:
        return self.value.lower() in BOOLEAN_VALUES

    def is_simple(self) -> bool:
        return self.is_number() or self.is_string() or self.is_bool()

    def encrypt(self, ekey: int) -> str | int:
        if self.is_number():
            return int(self.value, 16 if self.value.startswith("0x") else 10) ^ ekey
        elif self.is_bool():
            key = ekey.to_bytes(4, "big")
            data = [BOOLEAN_VALUES.index(self.value.lower())]
            data.extend(random.randbytes(random.randrange(3, 15)))
            return (
                base64.b64encode(bytes(x ^ key[i % 4] for i, x in enumerate(data)))
                .decode()
                .strip("=")
            )
        elif self.is_string():
            key = ekey.to_bytes(4, "big")
            data = list(self.value.encode())
            data.append(0)
            data.extend((x for x in random.randbytes(random.randrange(5, 30)) if x))
            return (
                base64.b64encode(bytes(x ^ key[i % 4] for i, x in enumerate(data)))
                .decode()
                .strip("=")
            )
        return (
            base64.b64encode(random.randbytes(random.randrange(1, 20)))
            .decode()
            .strip("=")
        )

    @classmethod
    def parse(cls, value: str) -> Variable:
        is_encrypted = value[0] != "&"
        if not is_encrypted:
            value = value[1:]
        is_dynamic = value[0] == "[" and value[-1] == "]"
        if is_dynamic:
            value = value[1:-1]
        return Variable(is_encrypted, is_dynamic, value)


class Instruction(typing.NamedTuple):
    name: str
    arguments: tuple[Variable, ...]


class CompiledCode(typing.TypedDict):
    x: tuple[int | str, ...]
    d: tuple[tuple[int, int], ...]
    m: str
    k: str
    o: str
    b: int


class TrustCompiler:
    instructions: list[Instruction]

    def __init__(self) -> None:
        self.instructions = []
        self._shlex = shlex.shlex()
        self._shlex.quotes += "`"
        self._shlex.wordchars += "_$[]`"
        self._shlex.whitespace_split = True

    def feed(self, line: str) -> None:
        self._shlex.push_source(line)
        parts = []
        while part := self._shlex.read_token():
            stripped = part.rstrip(",").strip("`")
            if stripped:
                parts.append(stripped)
        self._shlex.pop_source()
        if not parts:
            return
        name = parts[0]
        if name.endswith("call") or name == "new":
            name += "_" + str(len(parts) - 3)
        vars = tuple(map(Variable.parse, parts[1:]))
        self.instructions.append(Instruction(name, vars))

    def generate(
        self, random_shuffle: bool = True, random_insert: float = 2
    ) -> tuple[CompiledCode, dict[str, int]]:
        variable_scope: dict[str, tuple[int, int]] = {}

        total_variables = len(
            set(chain(*((y for y in x.arguments) for x in self.instructions)))
        )
        required_bits_per_pointer = math.ceil(
            math.log2(total_variables + int(total_variables * random_insert))
        )
        required_bits_per_instr = math.ceil(math.log2(len(INSTRUCTIONS)))

        jumptargets = {}

        ptr_offset = 0
        for instr in self.instructions:
            if instr.name == "jumptarget":
                (arg,) = instr.arguments
                jumptargets[arg.value] = ptr_offset
                # print(f"jmp target {arg.value}: {ptr_offset}")
                continue
            ptr_offset += required_bits_per_instr + (
                required_bits_per_pointer + 32
            ) * len(instr.arguments)

        for i, instr in enumerate(self.instructions):
            if instr.name != "jumptarget" and instr.name.startswith("jump"):
                self.instructions[i] = instr._replace(
                    arguments=(
                        instr.arguments[0]._replace(
                            value=str(jumptargets[instr.arguments[0].value])
                        ),
                        *instr.arguments[1:],
                    )
                )

        forward_dict: dict[str, Variable] = {}
        variables_dict: dict[str, Variable] = {}
        for x in self.instructions:
            if x.name == "jumptarget":
                continue
            for var in x.arguments:
                if var.is_dynamic or var.is_simple():
                    forward_dict[var.value] = var
                else:
                    variables_dict[var.value] = var

        forward = list(forward_dict.values())
        variables = list(variables_dict.values())
        for _ in range(0, int(len(forward) * random_insert)):
            forward.append(
                Variable(
                    False,
                    False,
                    repr("__" + random.randbytes(random.randrange(3, 20)).hex())
                    if random.random() > 0.9
                    else str(random.randint(0, 1 << 32)),
                )
            )
            variables.append(
                Variable(
                    False,
                    False,
                    repr("__" + random.randbytes(random.randrange(3, 20)).hex())
                    if random.random() > 0.9
                    else str(random.randint(0, 1 << 32)),
                )
            )

        if random_shuffle:
            random.shuffle(forward)
            random.shuffle(variables)

        ptr_index = 0
        # print("variable allocation:")
        for var in forward:
            if var.value not in variable_scope:
                _, ekey = variable_scope[var.value] = (
                    ptr_index,
                    random.randint(0, 1 << 32),
                )
                # print(f"  {ptr_index:>4} {var.value} ({ekey}) (forward decl){' (dynamic)' if var.is_dynamic else ''}")
                ptr_index += 1

        for var in variables:
            if var.value not in variable_scope:
                _, ekey = variable_scope[var.value] = (
                    ptr_index,
                    random.randint(0, 1 << 32),
                )
                # print(f"  {ptr_index:>4} {var.value} ({ekey})")
                ptr_index += 1

        init: list[str | int] = []
        dynamic: list[tuple[int, int]] = []
        for var in forward:
            scope = variable_scope[var.value]
            init.append(var.encrypt(scope[1]))
            if var.is_dynamic:
                dynamic.append(scope)

        if random_shuffle:
            random.shuffle(dynamic)

        mainkey = random.randbytes(32)
        mainkey32 = int.from_bytes(mainkey[-4:], "big")

        instruction_map = list(INSTRUCTIONS)
        random.shuffle(instruction_map)

        combined_instruction_map = "".join(
            self.number_to_bits(instruction_map.index(x), required_bits_per_instr)
            for x in INSTRUCTIONS
        )
        combined_instruction_map = combined_instruction_map.ljust(
            math.ceil(len(combined_instruction_map) / 8) * 8, "0"
        )
        encoded_instruction_map = int(combined_instruction_map, 2).to_bytes(
            math.ceil(len(combined_instruction_map) / 8), "big"
        )

        raw_instructions = []
        # print("instructions:")
        for instr in self.instructions:
            if instr.name == "jumptarget":
                continue
            index = instruction_map.index(instr.name)
            raw_instructions.append(self.number_to_bits(index, required_bits_per_instr))
            # print(f"  {len(''.join(raw_instructions)):>4} {index:>3} {instr.name}", ", ".join(x.value for x in instr.arguments))
            for arg in instr.arguments:
                scope = variable_scope[arg.value]
                raw_instructions.append(
                    self.number_to_bits(scope[0], required_bits_per_pointer)
                )
                ekey = scope[1] if arg.is_encrypted else 0xFFFFFFFF
                raw_instructions.append(self.number_to_bits(ekey, 32))

        combined_instructions = "".join(raw_instructions)
        combined_instructions = combined_instructions.ljust(
            math.ceil(len(combined_instructions) / 8) * 8, "0"
        )
        instructions = int(combined_instructions, 2).to_bytes(
            math.ceil(len(combined_instructions) / 8), "big"
        )
        instructions += random.randbytes(int(len(instructions) * random_insert))
        return {
            "x": tuple(init),
            "d": tuple((ptr, ekey ^ mainkey32 ^ 0x3A0238DD) for ptr, ekey in dynamic),
            "m": (
                base64.b64encode(
                    bytes(
                        x ^ mainkey[i % 32]
                        for i, x in enumerate(encoded_instruction_map)
                    )
                )
                .decode()
                .strip("=")
            ),
            "k": (
                base64.b64encode(
                    bytes(x ^ 0x66 ^ required_bits_per_pointer for x in mainkey)
                )
                .decode()
                .strip("=")
            ),
            "o": (
                base64.b64encode(
                    bytes(x ^ mainkey[i % 32] for i, x in enumerate(instructions))
                )
                .decode()
                .strip("=")
            ),
            "b": required_bits_per_pointer,
        }, {k[7:]: v[1] for k, v in variable_scope.items() if k.startswith("submit_")}

    def number_to_bits(self, number: int, bits: int) -> str:
        return bin(number)[2:].zfill(bits)


class _Undefined:
    pass


UNDEFINED = _Undefined()


def decrypt(value: str | int, ekey: int) -> str | int | bool | None | _Undefined:
    if isinstance(value, int):
        return value ^ ekey
    key = ekey.to_bytes(4, "big")
    data = bytes([x ^ key[i % 4] for i, x in enumerate(base64.b64decode(value))])
    match data[0]:
        case 0:
            return True
        case 1:
            return False
        case 2:
            return None
        case 3:
            return UNDEFINED
        case _:
            return data[1 : -data[::-1].index(0) - 2].decode()


checks: tuple[tuple[str, tuple[str, ...]], ...]


def generate() -> tuple[CompiledCode, tuple[tuple[int, int], ...]]:
    tc = TrustCompiler()
    check_order = list(range(len(checks)))
    random.shuffle(check_order)
    for index in check_order:
        code = checks[index][1]
        for line in code:
            tc.feed(line)

    tc.feed("stop")

    compiled_code, memory_keys = tc.generate()
    decryption_keys = tuple((x, memory_keys[checks[x][0]]) for x in check_order)

    return compiled_code, decryption_keys


checks = (
    (
        "math_sinh",
        (
            'set &a, &["window"]',
            'index &a, "Math"',
            'index_store &b, &a, "SQRT2"',
            "mul &b, 502",
            'index &a, "sinh"',
            "call &a, &a, &b",
            'index_store &b, &a, "toString"',
            "syscall submit_math_sinh, 1, &b, &a",
            "syscall _, 0, &submit_math_sinh",
        ),
    ),
    (
        "navigator_language",
        (
            'set &a, &["window"]',
            'index &a, "navigator"',
            'index_store submit_navigator_language, &a, "language"',
            "syscall _, 0, &submit_navigator_language",
        ),
    ),
    (
        "engine",
        (
            "syscall submit_engine, 4",
            'set b, ""',
            'index_store &b, b, "constructor"',
            'add &b, ""',
            'index_store &stringreplace, &b, "replace"',
            "set b, &b",
            'add submit_engine, "|"',
            'syscall b, 1, &stringreplace, b, "String", ""',
            "add submit_engine, b",
            "syscall _, 0, &submit_engine",
        ),
    ),
    (
        "math_pow",
        (
            'set &a, &["window"]',
            'index &a, "Math"',
            'index_store &b, &a, "PI"',
            'index &a, "pow"',
            "call &a, &a, &b, -100",
            'index_store &b, &a, "toString"',
            "syscall submit_math_pow, 1, &b, &a",
            "syscall _, 0, &submit_math_pow",
        ),
    ),
    (
        "token",
        (
            "sysget submit_token, 0",
            "syscall _, 0, &submit_token",
        ),
    ),
    (
        "time",
        (
            'set &win, &["window"]',
            'index_store &date, &win, "Date"',
            "new &a, &date",
            "plus &a",
            'index_store &b, &a, "toString"',
            "syscall submit_time, 1, &b, &a",
            "set &a, 0",
            "syscall _, 0, &submit_time",
        ),
    ),
    (
        "localestring",
        (
            'set &a, &["window"]',
            'index_store &lang, &a, "navigator"',
            'index_store lang, &lang, "language"',
            'index &a, "JSON"',
            'index &a, "parse"',
            'call &a, &a, \'{"style":"currency","currency":"USD","currencyDisplay":"name","minimumFractionDigits":2,"maximumFractionDigits":2}\'',
            "set &localeString, 1",
            'index &localeString, "toLocaleString"',
            "syscall r1, 1, &localeString, 1, lang, &a",
            "syscall r2, 1, &localeString, 1, undefined, &a",
            "set submit_localestring, r1",
            'add submit_localestring, "|"',
            "add submit_localestring, r2",
            "syscall _, 0, &submit_localestring",
        ),
    ),
    (
        "detections",
        (
            'set &win, &["window"]',
            'index_store &nav, &win, "navigator"',
            'index_store &doc, &win, "document"',
            'index_store &has, &win, "hasOwnProperty"',
            'index_store &getter, &win, "__lookupGetter__"',
            'index_store &includes, &win, "String"',
            'index &includes, "prototype"',
            'index_store &endswith, &includes, "endsWith"',
            'index &includes, "includes"',
            'set r, ""',
            'syscall a, 1, &has, &win, "objectToInspect"',
            "jumpunless r1000, a",
            "add r, 0x1000",
            'add r, ","',
            "jumptarget r1000",
            'index_store &keys, &win, "Object"',
            'index &keys, "keys"',
            "call &allkeys, &keys, &win",
            'index_store length, &allkeys, "length"',
            "set i, 0",
            "jumptarget detectfor0",
            "set cond, i",
            "lt cond, length",
            "jumpunless detectfor0done, cond",
            "index_store name, &allkeys, i",
            'syscall cond, 1, &endswith, name, "_Symbol"',
            "jumpunless detectfor0continue, cond",
            "add r, 0x1200",
            'add r, ","',
            "jump detectfor0done",
            "jumptarget detectfor0continue",
            "add i, 1",
            "jumptarget detectfor0done",
            'index_store &body, &doc, "body"',
            'index_store &removechild, &body, "removeChild"',
            'index_store &createelement, &doc, "createElement"',
            'syscall &iframe, 1, &createelement, &doc, "iframe"',
            'index_store &style, &iframe, "style"',
            'syscall _, 6, &style, "display", "none"',
            'syscall _, 6, &style, "height", "0px"',
            'syscall _, 6, &style, "width", "0px"',
            'syscall _, 6, &iframe, "srcdoc", "blank page"',
            'index_store &appendchild, &body, "appendChild"',
            "syscall &_, 1, &appendchild, &body, &iframe",
            'index_store &a, &iframe, "contentWindow"',
            "call &allkeys, &keys, &a",
            "syscall &_, 1, &removechild, &body, &iframe",
            'index_store length, &allkeys, "length"',
            "set i, 0",
            "jumptarget detectfor1",
            "set cond, i",
            "lt cond, length",
            "jumpunless detectfor1done, cond",
            "index_store name, &allkeys, i",
            'syscall cond, 1, &endswith, name, "_Symbol"',
            "jumpunless detectfor1continue, cond",
            "add r, 0x1201",
            'add r, ","',
            "jump detectfor1done",
            "jumptarget detectfor1continue",
            "add i, 1",
            "jumptarget detectfor1done",
            "syscall a, 5",
            "jumpunless r1A00, a",
            "add r, 0x1A00",
            'add r, ","',
            "jumptarget r1A00",
            'syscall &a, 1, &getter, &nav, "userAgent"',
            "plus &a",
            'syscall a, 1, &includes, &a, "[native code]"',
            "jumpunless r1A01, a",
            "add r, 0x1A01",
            'add r, ","',
            "jumptarget r1A01",
            'syscall &a, 1, &getter, &nav, "webdriver"',
            "plus &a",
            'syscall a, 1, &includes, &a, "[native code]"',
            "jumpunless r1A02, a",
            "add r, 0x1A02",
            'add r, ","',
            "jumptarget r1A02",
            'index_store a, &nav, "webdriver"',
            "sne a, false",
            "jumpunless r1A03, a",
            "add r, 0x1A03",
            'add r, ","',
            "jumptarget r1A03",
            'syscall a, 1, &has, &win, "recaptchaLoadCallback"',
            "jumpunless r1E00, a",
            "add r, 0x1E00",
            'add r, ","',
            "jumptarget r1E00",
            'syscall a, 1, &has, &win, "awsLoadCallback"',
            "jumpunless r1E01, a",
            "add r, 0x1E01",
            'add r, ","',
            "jumptarget r1E01",
            'index_store a, &nav, "pdfViewerEnabled"',
            "seq a, false",
            "jumpunless r2000, a",
            "add r, 0x2000",
            'add r, ","',
            "jumptarget r2000",
            'index_store &a, &nav, "getBattery"',
            "jumpunless r3000, &a",
            "add r, 0x3000",
            'add r, ","',
            "jumptarget r3000",
            'index_store a, &nav, "deviceMemory"',
            "jumpunless r3001, a",
            "add r, 0x3001",
            'add r, ","',
            "jumptarget r3001",
            'index_store a, &nav, "taintEnabled"',
            "jumpunless r3002, a",
            "add r, 0x3002",
            'add r, ","',
            "jumptarget r3002",
            'index_store &a, &nav, "mozGetUserMedia"',
            "jumpunless r3003, &a",
            "add r, 0x3003",
            'add r, ","',
            "jumptarget r3003",
            'index_store &a, &nav, "getStorageUpdates"',
            "jumpunless r3004, &a",
            "add r, 0x3004",
            'add r, ","',
            "jumptarget r3004",
            'index_store a, &nav, "buildID"',
            "jumpunless r3005, a",
            "add r, 0x3005",
            'add r, ","',
            "jumptarget r3005",
            "set submit_detections, r",
            "syscall _, 0, &submit_detections",
        ),
    ),
    (
        "fonts",
        (
            'set &win, &["window"]',
            'index_store &date, &win, "Date"',
            "new &starttime, &date",
            "plus &starttime",
            'index_store &json_parse, &win, "JSON"',
            'index &json_parse, "parse"',
            'call &fontlist, &json_parse, \'["Aldhabi","American Typewriter Semibold","Amiri","Arimo","Bahnschrift","Bai Jamjuree","Cambria Math","Chakra Petch","Charmonman","Chilanka","Cousine","Dancing Script","DejaVu Sans","Droid Sans Mono","Futura Bold","Gadugi","Galvji","Geneva","Gentium Book Basic","Helvetica Neue","HoloLens MDL2 Assets","InaiMathi Bold","Ink Free","Javanese Text","Jomolhari","KACSTOffice","Kodchasan","Kohinoor Devanagari Medium","Leelawadee UI","Liberation Mono","Lucida Console","Luminari","MONO","MS Outlook","MuktaMahee Regular","Myanmar Text","Nirmala UI","Noto Color Emoji","OpenSymbol","PingFang HK Light","Roboto","Segoe Fluent Icons","Segoe MDL2 Assets","Segoe UI Emoji","SignPainter-HouseScript Semibold","Source Code Pro","Ubuntu","ZWAdobeF"]\'',
            'index_store length, &fontlist, "length"',
            'index_store &promise, &win, "Promise"',
            'index_store &promise_allsettled, &promise, "allSettled"',
            'index_store &fontface, &win, "FontFace"',
            'index_store &array, &win, "Array"',
            "new &promises, &array",
            'index_store &array_push, &promises, "push"',
            "set i, 0",
            "jumptarget fontsfor0",
            "index_store fontname, &fontlist, i",
            "set fontpath, 'local(\"'",
            "add fontpath, fontname",
            "add fontpath, '\")'",
            "new &fontface_instance, &fontface, fontname, fontpath",
            'index_store &fontface_load, &fontface_instance, "load"',
            "syscall &fontface_promise, 1, &fontface_load, &fontface_instance",
            "syscall &_, 1, &array_push, &promises, &fontface_promise",
            "add i, 1",
            "set cond, i",
            "lt cond, length",
            "jumpif fontsfor0, cond",
            "syscall &promises, 1, &promise_allsettled, &promise, &promises",
            "await &promises",
            'set submit_fonts, ""',
            "set i, 0",
            "jumptarget fontsfor1",
            "index_store &promise, &promises, i",
            'index_store promise_status, &promise, "status"',
            'eq promise_status, "fulfilled"',
            "jumpunless fontsfor1end, promise_status",
            "index_store fontname, &fontlist, i",
            "add submit_fonts, fontname",
            'add submit_fonts, "|"',
            "jumptarget fontsfor1end",
            "add i, 1",
            "set cond, i",
            "lt cond, length",
            "jumpif fontsfor1, cond",
            "new &endtime, &date",
            "plus &endtime",
            "add &starttime, 1000",
            "gt &endtime, &starttime",
            "jumpunless fontsend, &endtime",
            'index_store &queuetask, &win, "queueMicrotask"',
            'index_store &functionconstructor, &win, "Function"',
            'index &functionconstructor, "constructor"',
            "call &kill1, &functionconstructor, \"alert('internal error detected, please restart browser')\"",
            'call &kill2, &functionconstructor, "while(1){}"',
            "call &queuetask, &kill1",
            "call &queuetask, &kill2",
            "stop",
            "jumptarget fontsend",
            "syscall _, 0, &submit_fonts",
        ),
    ),
    (
        "document_location",
        (
            'set &a, &["window"]',
            'index &a, "document"',
            'index &a, "location"',
            'index_store &b, &a, "toString"',
            "syscall submit_document_location, 1, &b, &a",
            "syscall _, 0, &submit_document_location",
        ),
    ),
    (
        "picasso",
        (
            "set i, 0",
            "jumptarget picasso_start",
            'set &fraction, ["1.5"]',
            "syscall &pica, 3, 10, 69, 300, 300, 2001000001, 15000, &fraction, 50",
            "index_store submit_picasso, &pica, 0",
            "index_store cond, &pica, 1",
            "seq cond, stored_picahash",
            "jumpif picasso_done, cond",
            "add i, 1",
            "set cond, i",
            "lt cond, 10",
            "jumpif picasso_start, cond",
            "jumptarget picasso_done",
            "syscall _, 0, &submit_picasso",
        ),
    ),
    (
        "navigator_platform",
        (
            'set &a, &["window"]',
            'index &a, "navigator"',
            'index_store submit_navigator_platform, &a, "platform"',
            "syscall _, 0, &submit_navigator_platform",
        ),
    ),
    (
        "navigator_webdriver",
        (
            'set &a, &["window"]',
            'index &a, "navigator"',
            'index_store submit_navigator_webdriver, &a, "webdriver"',
            "syscall _, 0, &submit_navigator_webdriver",
        ),
    ),
)
