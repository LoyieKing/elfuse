# Filenames

A Linux guest names files by exact bytes. The macOS volume underneath usually
does not. This document describes how a guest filename becomes a name on disk
and back again, and why the mechanism is shaped the way it is.

It is about *representation* only: which bytes end up in a directory entry, and
how they are read back. Which tree a path is resolved against (the sysroot or
the host filesystem) is a separate question, decided on existence by
`proc_resolve_sysroot_path_flags` (`src/syscall/proc-state.c`).

## The problem

A filesystem has to answer one question about two names: are they the same name?

```
Linux ext4          compares bytes         "Foo" != "foo" != "FOO"   three files
macOS APFS          case- and              "Foo" == "foo" == "FOO"   one file
(default volume)    normalization-blind
```

APFS is case-*preserving*: it stores exactly the bytes it is given, so `ls`
shows `Foo`. It only *matches* loosely. A guest running against a sysroot on
such a volume therefore needs two things that do not come for free:

1. `open("foo")` must fail when the directory holds `Foo`. The volume would
   happily open it.
2. `Foo` and `foo` must be able to coexist. The volume cannot hold both.

The first is answered by asking the volume for a name's stored spelling and
comparing bytes. The second needs one of the two names to be stored on disk
under a different spelling, and that is what the rest of this document is about.

A volume that probes case-sensitive (one made by `--create-sysroot`) needs
neither for case, and the escape is inactive there. It is not byte-exact,
though: no APFS variant is. Case-sensitive APFS still matches names
canonical-normalization-blind and refuses names that are not well-formed
UTF-8, and with the escape off those two divergences reach the guest. Thirty
seconds on any Mac reproduce both:

```sh
dmg=$(mktemp -u).dmg
hdiutil create -size 8m -fs "Case-sensitive APFS" -volname probe -quiet "$dmg"
mnt=$(hdiutil attach "$dmg" -nobrowse | awk '/\/Volumes\//{print $NF}')
cd "$mnt"
printf 'nfc\n' > "caf$(printf '\303\251')"    # U+00E9, composed
printf 'nfd\n' > "cafe$(printf '\314\201')"   # e + U+0301, decomposed
ls | cat                          # one entry: the second create hit the
cat "caf$(printf '\303\251')"     # first file: prints "nfd", data clobbered
printf 'x\n' > "bad$(printf '\377')"          # refused: illegal byte sequence
```

So on a `--create-sysroot` sysroot, two guest names that differ only in
canonical normalization alias each other (a write to one lands in the other),
and a create whose name is not valid UTF-8 fails with `EILSEQ` where Linux
succeeds. These are accepted divergences of that configuration, pinned exactly
by `tests/test-sysroot-name-i18n.c` in its `csapfs` mode so a change in either
direction is deliberate. A folding volume has neither divergence: the escape
below handles normalization and ill-formed names along with case. Everything
else in this document concerns that folding case.

## What the folding table actually does

Choosing which names are safe to store as themselves requires knowing what the
volume considers equal. It is considerably more than upper versus lower case.
Measured on macOS 15, APFS:

```
ascii Foo / foo                COLLIDE
french cafe NFC / NFD          COLLIDE   composed vs combining accent
german strasse / straße        COLLIDE   the sharp s folds onto "ss", so a
                                         fold can change a name's length
greek σoς / σoσ                COLLIDE   final sigma folds onto medial, so a
                                         fold can depend on position
ligature ﬁb / fib              COLLIDE   compatibility mapping, not just NFD
ohm Ωa / Ωa (U+2126 / U+03A9)  COLLIDE   singleton normalization
korean 한 NFC / jamo NFD        COLLIDE
deseret 𐐀y / 𐐨y                COLLIDE   case folding reaches beyond the BMP
chinese U+6587 U+6863 / U+6587 U+4EF6  distinct  CJK has no case
turkish ıd / id                distinct
cherokee Ꭰx / ᏸx               distinct  cased in Unicode 8, but not folded here
```

No rule short of full Unicode tables predicts that list, and elfuse carries no
Unicode tables and should not acquire any.

## Which names are stored as themselves

A name is stored under its own spelling when it is **fold-stable**: no uppercase
ASCII letter, no byte above `0x7F`, and not already shaped like an escape.
Everything else is escaped.

This is deliberately conservative: a Chinese filename has no case and would
usually be safe as itself. The rule still has to be correct for reasons
stronger than the table above. What it leaves stored literally is
lowercase ASCII, and lowercase ASCII is a **fixed point of every transformation
the volume applies**: case folding does nothing to it, canonical decomposition
does nothing to it, and compatibility decomposition maps *into* ASCII but never
between two distinct ASCII strings. Two literally stored names therefore cannot
collide, whatever is in the folding table and however it changes in a future
macOS release. That is a proof rather than an enumeration, which is what makes
it safe to rely on.

Escaping keys on the name alone and never on what the directory already holds.
That is what makes the on-disk name a pure function of the guest name, which in
turn is what lets two processes create colliding names in the same directory
without coordinating: they are writing different names.

Looking a name up still tries its literal spelling first, because a sysroot
staged from a tarball is full of names like `Makefile`, `README` and
`Documentation/` that were written by something other than elfuse and keep their
real spelling.

## The escape

```
.ef=524541444d45          is the guest name  README
.ef=e69687e6a1a32e747874                     U+6587 U+6863 followed by .txt
```

An escaped name is the four-byte prefix `.ef=` followed by a payload encoding
the guest name's bytes. Decoding is a pure function of the name: no file, no
side table, nothing to keep in step.

Every character of the prefix earns its place. The leading `.` keeps escaped
names out of a casual host-side listing. `ef` identifies what produced them.
Four characters is as short as that can be while staying recognizable, and
length matters because the prefix is charged against the same per-name budget as
the payload. `=` is the separator rather than `^` because host tooling matches
this prefix constantly and `^` is a regular-expression anchor, so
`grep -E '.ef\^'` silently matches nothing.

A guest name that is itself escape-shaped is escaped too, so it can never be
confused with the encoding of another name:

```
guest name  .ef=464f4f   is stored as  .ef=2e65663d343634663466
                         and reads back as  .ef=464f4f,  not  FOO
```

A name that is not a well-formed escape means itself. `.ef=464F4F` (uppercase
hex), `.ef=464f4` (odd length), `.ef=2f` (decodes to `/`) and `.ef=` (empty) are
all ordinary files.

## Resolving a path

A guest path is resolved one component at a time, and each component is decided
by asking the volume for the name as stored and comparing bytes. A plain `stat`
cannot answer the question: it reports success for a spelling that is not what
is stored, while Linux resolution is byte-exact and owes `ENOENT` for that.

For each component, given the parent already spelled:

| The volume says | The component is |
|---|---|
| an entry exists, spelled as asked | the literal name |
| an entry exists, spelled differently | the escape, whose slot is therefore free |
| it will not hold this name at all | the escape |
| nothing is there | the escape if that exists, otherwise the name's own rule |

A component whose literal slot is taken by a different spelling resolves to its
escape *even though nothing is there yet*. That name provably does not exist and
cannot fold onto the sibling occupying the slot, so the caller's own syscall
returns Linux's `ENOENT` for a wrong-case lookup with no separate rejection path
back into the resolver. Once a component is absent nothing below it can be
probed, and nothing needs to be, because escaping depends only on the name.

The probe takes a path rather than a directory descriptor, so the walk builds
the host spelling as a string and opens nothing at all. It cannot probe the
whole path at once: the volume validates only the last component, so a
wrong-case parent folds away silently and every prefix has to be asked about
separately.

A path is resolved this way only when the sysroot volume folds case. On a
byte-exact volume the guest spelling is the host spelling, and one concatenation
and one existence probe answer both questions.

## Which volume, and which side of the sysroot

Everything above describes what happens when the sysroot volume folds case. Two
independent facts decide whether any of it runs for a given name: what the
sysroot volume does with case, and whether the path lands inside the sysroot at
all.

### The volume decides whether escaping happens at all

At startup elfuse asks the sysroot's volume how it treats case
(`sysroot_probe_case_sensitivity`, `src/core/sysroot.c:320`), preferring
`pathconf(_PC_CASE_SENSITIVE)` and falling back to `getattrlist` with
`ATTR_VOL_CAPABILITIES`. Escaping is enabled only for a volume that preserves
case but does not distinguish it (`src/main.c:627`): only, that is, when the
volume would otherwise merge two names Linux keeps apart.

| Sysroot volume | Escaping | On-disk names |
|---|---|---|
| default APFS, which folds | on | escaped wherever the name is not fold-stable |
| case-sensitive APFS, such as a sparsebundle | off | the guest's own bytes |
| the probe fails | off | the guest's own bytes |

A **sparsebundle** is a disk image that grows on demand, and macOS can format
one case-sensitive even when the boot volume is not. Pointing the sysroot at one
turns the codec off completely: `casefold_active`
(`src/syscall/casefold-walk.c:30`) is false, no walk runs, and resolution is one
`snprintf` plus one existence probe. The volume already behaves the way Linux
does, so there is nothing to work around, and `ls` inside the sysroot shows the
guest's names exactly as the guest wrote them.

```sh
hdiutil create -size 20g -fs "Case-sensitive APFS" -type SPARSEBUNDLE \
    -volname elfuse-root elfuse-root.sparsebundle
hdiutil attach elfuse-root.sparsebundle
elfuse --sysroot /Volumes/elfuse-root ./program
```

### The sysroot boundary decides whose rules apply

Inside the sysroot elfuse owns the tree and can promise Linux naming. Outside it
the guest is looking at the real macOS filesystem, whose files elfuse did not
create and must not rename. A path that misses inside the sysroot falls through
to the host under its own spelling, which is what lets a guest read the user's
own files.

```
guest says  /usr/lib/libc.so                 /Users/henry/project/README
                |                                       |
      inside the sysroot?  yes                          no
                |                                       |
      /Volumes/elfuse-root/usr/lib/libc.so    /Users/henry/project/README
      case-sensitive sparsebundle             boot volume, folds case
      elfuse guarantees Linux naming          macOS rules apply unchanged
```

Two exceptions keep that fall-through from doing damage. Guest system
directories (`/usr`, `/bin`, `/etc`, `/lib`, ...) never fall through, because
resolving them against macOS would read the host's own system files or fail on
SIP (`is_guest_system_path`, `src/syscall/proc-state.c:578`). And `/tmp`,
`/var/tmp` and ccache
directories are forced back into the sysroot even when absent, so a build that
creates case-colliding temporaries gets Linux semantics rather than the host's.

### A worked example

Sysroot on a case-sensitive sparsebundle at `/Volumes/elfuse-root`. The user's
own files are at `/Users/henry/project` on the ordinary boot volume, which folds
case. Note that the uppercase in `/Users` never matters to the sysroot: it is
part of a host path, and the sysroot spells names the guest's way.

| The guest does | Where it lands | What happens |
|---|---|---|
| `open("/usr/lib/libc.so")` | `/Volumes/elfuse-root/usr/lib/libc.so` | byte-exact match on the sparsebundle |
| `open("/data/Foo", O_CREAT)` then `open("/data/foo", O_CREAT)` | two entries in the sysroot | two distinct files, spelled literally, as on Linux |
| `open("/usr/lib/LIBC.so")` | `/Volumes/elfuse-root/usr/lib/LIBC.so` | `ENOENT`; the volume distinguishes case, and a guest system path never falls through |
| `open("/Users/henry/project/README")` | `/Users/henry/project/README` | the real host file, read through macOS |
| `open("/Users/henry/project/Out.txt", O_CREAT)` | `/Users/henry/project/Out.txt` | created on the boot volume, spelled as asked |

The last two rows carry a limitation worth stating plainly. On the host side the
boot volume still folds, so `Out.txt` and `out.txt` are one file there, and a
guest that creates both sees the second overwrite the first. Elfuse does not fix
the host filesystem, only the sysroot; a program that depends on case-distinct
names must keep them inside the sysroot, which is why the temporary directories
are redirected there.

On a default, folding sysroot the same five rows behave the same way from the
guest's side. The difference is only on disk. Running one workload that creates
four case-colliding names against each kind of sysroot shows it directly:

```
case-sensitive sparsebundle          default folding APFS
  Contended                            .ef=436f6e74656e646564  = Contended
  race                                 race
  rAcE                                 .ef=72416345            = rAcE
  Race                                 .ef=52616365            = Race
  RACE                                 .ef=52414345            = RACE
```

The guest sees the same five files either way. On the left the volume keeps them
apart on its own, so every name is stored as itself. On the right only `race` is
fold-stable and the rest are escaped, and the listing the guest reads is decoded
back on the way out. Escaped names begin with a dot, so `ls` hides them unless
asked with `-A`.

## One representation per name

A guest name is reachable through exactly one on-disk entry. The rule that gets
there is the last row of the table above: an absent component prefers an
existing escape before falling back to its own spelling, so a lookup and a
create can never settle on different entries for the same name.

If both spellings are present (which only something outside elfuse can
arrange, since elfuse writes one or the other), a lookup takes the literal one.
The escaped entry is then unreachable under any guest name, though a listing
still reports the name twice.

## The escape never reaches the guest

Everything the kernel reports back to the guest decodes stored spellings to
guest bytes first. Directory listings (`getdents64`) and inotify event names
decode each entry as it is read, but only for directories the sysroot holds:
a host directory reached through the fallback reports its entries as stored,
because those names are the host's and an escape-shaped literal there means
itself. `getcwd`, `/proc/self/cwd`,
`/proc/self/exe`, `/proc/self/fd/N`, and the addresses returned for pathname
AF_UNIX sockets (`getsockname`, `getpeername`, `accept`, `recvfrom`) map a
whole host path back through the sysroot strip and the same per-component
decode. The forward direction is symmetric: watches, exec targets,
`PT_INTERP` interpreters, and socket addresses resolve through the ordinary
path translation, so a name spelled by the guest and a name reported to the
guest always mean the same file.

## Why nothing is locked

Which spelling a guest name takes is decided by the name, so a create is one
`openat`, a rename is one `renameat`, and an unlink is one `unlinkat`. Each is a
single kernel operation, which makes it atomic with no help from elfuse: there
is no second object recording what a name means, so there is no window in which
a file exists under neither its old name nor its new one, nothing to roll back
when one of two writes fails, and nothing for two processes sharing a sysroot to
coordinate over.

Resolution is not quite a pure function of the name, and the exception is worth
being exact about. Two rows of the table above consult the directory: a name is
stored literally when the volume already holds it under that exact spelling, and
an absent name prefers an existing escape over its own rule. Both matter only
for a fold-stable name whose escape something outside elfuse staged, because for
every name elfuse itself writes the two branches name the same entry. The
concurrency argument is unaffected either way: two *different* colliding names
resolve to two different entries whatever the directory holds, and two processes
creating the *same* name race for one entry exactly as they would on Linux.

Two processes creating names that collide are writing *different* names, because
which spelling a name takes is decided by the name and not by what the directory
already holds. Which of two colliding names ends up in the literal slot follows
arrival order and is not part of the contract.

## Symlink targets

A relative target stores the bytes the guest gave it, and nothing rewrites
them: `readlink` returns what was written. An absolute target cannot be stored
verbatim, because anything following the link natively resolves it from the
host root rather than the sysroot. Creation therefore rewrites it to a target
relative to the link's own directory, which names the same object inside the
sysroot and survives the tree being moved; `readlink` reports that rewritten
spelling, the one visible divergence, since nothing on disk tells a rewritten
target from a relative one the guest wrote.

That leaves the stored bytes naming a *guest* path while the disk holds host
spellings, so following a link is done in the guest's namespace rather than by
handing the target to the host kernel. When the walk reaches a link it has to
pass through, it stops and says so; the resolver reads the target, joins a
relative one to the directory holding the link or lets an absolute one replace
the path outright, appends whatever was left, and resolves the result as an
ordinary guest path. Chains are followed the same way, bounded at
`MAXSYMLINKS` hops, `ELOOP` past that.

Knowing a component is a link is free: the probe already asks the volume for
each component's stored name, and `ATTR_CMN_OBJTYPE` rides along on that same
request.

Following is not atomic, and nothing here claims otherwise. The walk resolves by
path rather than by holding descriptors, so a component can be replaced between
being resolved and being used; adding link following lengthens that window
without changing its nature. The guarantee is over the operation, not the
resolution: the create, rename or unlink a caller finally issues is one kernel
call, so a name is never left half-moved.

Which components are followed is POSIX's rule, not a choice: every intermediate
component is, and only the last one honors a caller's request not to. So
`lstat("/a/link/b")` follows `link` and reports on `b`.

### A link may not leave the sysroot

An absolute target resolves against the sysroot, exactly as the same path typed
by the guest would, which is what a chroot-like tree owes. It does not,
however, inherit the host fallback that a typed path gets. A path the guest
names itself may fall through to the host when the sysroot does not have it; a
path arrived at by following a link may not, because anything able to write a
symlink into the tree could otherwise hand the guest a file from outside it.

A link whose target the sysroot does not hold therefore ends one of two ways:

- the host has nothing there either, so the link simply dangles and the guest
  gets `ENOENT`
- the host does have something there, which is the escape the rule exists to
  stop, and the guest gets `ELOOP`

Operations that do not follow are untouched throughout: `lstat`, `readlink`,
`unlink`, `rename`, and `linkat` without `AT_SYMLINK_FOLLOW` all keep seeing the
link itself, including when its target does not resolve.

## Name length

Both platforms limit a name, but they do not count the same thing, and that
mismatch is what makes the encoding possible.

**Linux** limits a path component to 255 **bytes**, and bakes the limit into
`struct dirent`'s `d_name[256]`. No guest can hand over or receive a longer
name, so 255 bytes is a hard ceiling on the input.

**APFS** limits a component to 255 **UTF-16 code units**. `pathconf` reports 255
for both, which looks like a match and is not:

```
ascii U+0061           max 255 chars =  255 bytes = 255 utf16 units
latin-1 U+00E9         max 255 chars =  510 bytes = 255 utf16 units
BMP/CJK U+6587         max 255 chars =  765 bytes = 255 utf16 units
non-BMP U+1F680        max 127 chars =  508 bytes = 254 utf16 units
```

Every alphabet fails at 256 units regardless of byte count. So the host budget
in bytes swings by a factor of three with the alphabet, and an encoding that
spends units frugally can carry far more than an ASCII one.

That gives the payload two tiers:

| Guest name | Payload | Cost |
|---|---|---|
| up to 125 bytes | lowercase hex, 2 characters per byte | `4 + 2n` units |
| longer | 4096 CJK Unified Ideographs from U+4E00, 12 bits per character | `4 + 1 + ceil(2n/3)` units |

Hex caps out at 125 bytes because `4 + 2 * 126` is 256, one unit over. The short
tier exists anyway because an escaped name is then readable by eye (`xxd -r -p`
decodes it), and almost every escaped name a person ever sees is a short one.

The long tier carries the rest. Its first symbol holds the guest name's length,
so decoding knows exactly how many bytes the payload stands for; the remainder
packs three input bytes into two symbols. The largest name Linux can express
costs 175 of the 255 available units:

```
255-byte guest name -> .ef= + 171 symbols = 175 units, 517 bytes
```

There are 80 units to spare, and that margin is not an estimate: 255 bytes is
the largest input that can exist, so no name gets closer. Both tiers are held
to the limit by a `_Static_assert` in `src/syscall/casefold.h`, so widening the
prefix or raising the guest-name ceiling fails the build rather than producing
names the volume quietly refuses.

The payload block matters. CJK Unified Ideographs have no case mappings and no
decompositions, so no two payloads can fold together. Neighboring blocks are
not interchangeable: CJK **Compatibility** Ideographs normalize (U+F900
collides with U+8C48), Hangul syllables and dakuten kana decompose under NFD,
and Cherokee gained case in Unicode 8.

### Whole paths

Component length is solved; total path length is a separate budget, and here
macOS is the stricter of the two:

```
macOS PATH_MAX     1024
Linux PATH_MAX     4096
```

A guest may legitimately build a path more than three times longer than the host
can accept, and an escaped component is roughly twice the bytes of the name it
stands for, so a deep tree of escaped names reaches the host limit sooner. An
over-long host path reports `ENAMETOOLONG`; it is never truncated, because a
truncated path names a different file.

## Reproducing the measurements

Every table above is a measurement, not a specification, and can be re-run:

```sh
make probe-volume-naming                        # against a temp directory
build/probe-volume-naming /Volumes/cs-image     # against any other volume
```

`make test-sysroot-name-race` exercises the claim in "Why nothing is locked"
directly: several processes sharing one sysroot, each creating a different
member of a case-colliding set. It is a scheduling test and is repeated, so a
pass does not prove there is no race; only a failure proves there is one.

The probe reports what a volume does, including behavior elfuse is immune to.
The facts the design actually depends on are asserted separately by
`make test-casefold-host`, which fails the build if a future macOS release
changes them: that the payload alphabet cannot fold, that everything the encoder
emits can be created, and that the per-name budget is counted in UTF-16 units.
That test also takes a directory, so it can be pointed at another volume.

The escape itself is frozen in `tests/casefold-vectors.h`: a table pairing
guest names with the exact bytes stored for them, asserted in both directions
by the same test and staged host-side for `make test-sysroot-corpus` to read
back through a live sysroot. Those literals are the on-disk format. Every
sysroot ever written holds names spelled that way, so a row may change only
as part of a deliberate format migration, never to make a test pass. The
codec's other tests read their expectations back through the codec and stay
green across any self-consistent format change; the frozen table is the one
place such a change fails.
