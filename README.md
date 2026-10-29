# rage-dumper

Dump a C++ SDK of Grand Theft Auto V (RAGE) from the running game: parser structures with their members and offsets, enums, and every script native with its handler, body and command function offsets.

Final builds of the game ship without RTTI, but RAGE keeps its own reflection system: the parser (`parManager`) registers every data structure the game loads from metadata, with each member's name hash, offset and type. rage-dumper is a DLL that reads that database and the script native table from inside the game and writes headers that compile, with every size and offset checked.

```
[+] rage-dumper loaded
[*] Grand Theft Auto V 1.0.3889.0
[+] module dumped, 0x3E5BC00 bytes
[+] hashes loaded: 323388
[+] pattern hit at image+0x1391F15
[+] parManager::sm_Instance at image+0x2C76148
[+] structures: 2146
[+] enums after walking members: 269
[+] Grand Theft Auto V 1.0.3889.0: 2146 structs, 269 enums
[+] native table at image+0x2E9A750
[+] natives: 6701
[+] crossmap: build column 27 of 28 matches 6482 of 6701 natives
[+] command functions: 1951, inlined into the body: 4750
[+] Natives.hpp written
[+] all done
```

## Features

- Single DLL, no dependencies; it unloads itself after the dump
- No hardcoded addresses: the parser manager and the native table are found by byte pattern
- Live console with a colored log, mirrored to `dump.log`
- Parser structures at their registered offsets, with inheritance, explicit padding and real C++ types for every member whose size is confirmed
- Enums recovered from the members that use them, since final builds never fill the parser's enum map
- `Asserts.hpp` with a size and offset check for every structure and member
- Every script native with its namespace, name, current and original hash, handler, the first real instruction of its body and its separate command function when one exists
- Writes the decrypted game image to disk, ready to load in IDA

## Usage

1. Start the game and load into story mode. Structures register as the game first uses them, so inject once the world has loaded.
2. Put `hashes.txt` and `natives.txt` next to `rage-dumper.dll`.
3. Inject `rage-dumper.dll` with any LoadLibrary injector.

A console opens with the log. The output goes to `<dll folder>\<build>\`, and the log to `<dll folder>\dump.log`.

| File | Contents |
| --- | --- |
| `Basic.hpp` | RAGE core types (`atArray`, `atFixedArray`, `atString`, `atHashString`, `atMap`, `atBinaryMap`, `Vec3V`, `Mat34V`, ...) with their x64 sizes. |
| `Enums.hpp` | Every enum used by a parser structure, as `enum class` with the underlying type the game stores it in. |
| `Classes.hpp` | Every parser structure, parents and by-value members first. Field comments are offset (size). |
| `Asserts.hpp` | Size and member offset checks for `Classes.hpp`. Include it in one translation unit. |
| `Natives.hpp` | Every script native grouped by namespace, as `{ hash, handler, body, command }`. |
| `Unresolved.txt` | Name hashes `hashes.txt` could not resolve. |
| `game_dump.exe` | The decrypted game image with its section headers fixed, so IDA loads it as is. |

### Example

```cpp
// Struct CHandlingData | Hash 0x0E9464D1
// 0x0168 (0x0170 - 0x0008)
struct CHandlingData : public CHandlingObject
{
	atHashValue handlingName; // 0x0008 (0x0004)
	float fMass; // 0x000C (0x0004)
	float fInitialDragCoeff; // 0x0010 (0x0004)
	...
};
```

```cpp
// Namespace ENTITY
inline constexpr native_entry GET_ENTITY_COORDS{ 0xD1A6A821F5AC81DB, 0x00A78FFC, 0x039879E8, 0x00A8B54C }; // 0x3FEF770D40960D5A

// Namespace PLAYER
inline constexpr native_entry PLAYER_PED_ID{ 0x4A8C381C258A124D, 0x00CE6BE8, 0x037EFDCB, 0x00000000 }; // 0xD80958FC74E988A6
```

All offsets are from the game module base.

| Field | Meaning |
| --- | --- |
| `hash` | The hash this build uses. It changes with every game update. |
| `handler` | The registered entry, the address to call or hook. Arxan turns its first bytes into a jump. |
| `body` | The first real instruction once the Arxan jumps are folded. The code is still split into chunks joined by hidden jumps. |
| `command` | The separate command function the body calls, `0` when the compiler inlined it into the body. |
| comment | The original hash, the one native databases are keyed by. |

## Data files

Both files are generated once and only change when the game or the crossmap changes. The tools need Python 3 with `pefile` and `capstone`.

**`hashes.txt`** is the joaat dictionary used to turn name hashes back into names. It holds every string of the given executables, hashed both case-sensitive (the parser's `atLiteralHashString`) and lowercase.

```
python -I tools/gen_hashes.py bin/hashes.txt <game exe> [more exes...]
```

**`natives.txt`** links each native across builds and gives it a name. It combines FiveM's [`CrossMapping_Universal.h`](https://github.com/citizenfx/fivem/blob/master/code/components/rage-scripting-five/include/CrossMapping_Universal.h), which holds one row per native with its hash in every build, with a bank (non-final) build of the game and its PDB, which registers every native by name and names its command functions. The dumper picks the crossmap column that matches the running game on its own.

```
python -I tools/gen_natives.py bin/natives.txt CrossMapping_Universal.h <bank exe, pdb next to it>
```

## Building

Requirements: Visual Studio 2026 with the **Desktop development with C++** workload (v145 toolset, Windows 10 SDK).

Open `rage-dumper.sln`, select **Production | x64** and build, or from a developer command prompt:

```
msbuild rage-dumper.sln /p:Configuration=Production /p:Platform=x64
```

The DLL is written to `bin\rage-dumper.dll`.

The two configurations are **Development** and **Production**. Both keep runtime checks enabled.

## How it works

1. **Module dump.** The game's code is encrypted on disk and decrypted in memory. The dumper copies the loaded image and rewrites the section headers so the file layout matches memory.
2. **Parser manager.** A pattern on the start of `parStructure::BuildStructureFromStaticData` resolves `parManager::sm_Instance`. If the pattern ever stops matching, a scan of `.data` looks for a pointer whose structure map validates.
3. **Structures.** `m_Structures` maps a name hash to each `parStructure`: base, size and members. Every member descriptor carries its name hash, offset, type and subtype, plus the element prototype for arrays and maps.
4. **Enums.** Final builds leave `m_Enums` empty, but every enum and bitset member keeps its `parEnumData` at `+0x28`, which gives the enum's values.
5. **Layout.** Each structure is emitted under `#pragma pack(push, 0x1)` with explicit padding. A member gets its C++ type only when that type's size fits before the next member and its offset is aligned for it, otherwise it is a byte array with the parser type in its comment.
6. **Native table.** A pattern on the script program's native resolve loop finds the table: 256 buckets keyed by the low byte of the hash. Each block holds seven handlers, and its count, hashes and next pointer are XOR encoded with their own address. Every decoded hash is checked against its bucket.
7. **Command functions.** Each handler is traced through the Arxan hidden jumps (`push; lea; xchg [rsp]; ret`) and fake returns (`lea rsp, [rsp+8]; jmp [rsp-8]`) with a small instruction length decoder, collecting every direct call up to its return. A call is reported as the command only when the bank build calls its `Command*` function at the same position and the target is not a helper shared by many natives.

### Patterns

| Pattern | Resolves |
| --- | --- |
| `48 8B 05 ?? ?? ?? ?? 48 83 7A 28 00 48 8B FA 44 8A 60 5C` | `parManager::sm_Instance`, RIP relative at `+3` |
| `76 32 48 8B 53 40 48 8D 0D ?? ?? ?? ?? 48 8B 14 FA E8` | The native table, RIP relative `lea` at `+6` |

## Compatibility

Built and tested against Grand Theft Auto V Legacy **1.0.3889.0**. Other builds most likely work as long as both patterns still match; the log shows each hit. Grand Theft Auto V Enhanced has not been tested.

GTA V Legacy ships with BattlEye. Run story mode with BattlEye disabled from the launcher.

## License

[MIT](LICENSE)
