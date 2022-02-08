---
title: "Taking a Walk with sober-bishop"
tags:
  - programming
  - ctf
  - visualization
---

Over the weekend I spent a bit of time playing in [DiceCTF 2022](https://ctf.dicega.ng/)
and really enjoyed myself. I was a fan of one problem in particular that I worked
on, and after reading the [author's solution](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#miscsober-bishop)
I felt like I wanted to share my thoughts since I thought it was a cool problem
and it wasn't clear if I did it differently than they did (other than my
solution was Python and still fast enough, while they said they wrote theirs in
Rust).

Side note: I think it's awesome when challenge authors share their reference
solutions, because I think it helps the community when there are more resources.

## Walking Sober

So this problem was called sober bishop, and we are given only four things:

1. The regex that the flag must fit (`dice{[a-z0-9_-]+}`)
1. A [code reference](https://github.com/openssh/openssh-portable/blob/d9dbb5d9a0326e252d3c7bc13beb9c2434f59409/sshkey.c#L1180) to fingerprint art generation
1. An ascii fingerprint with the label "THIS IS THE FLAG"
1. An ascii fingerprint with the label "THIS IS md5(FLAG)"

I'd seen these fingerprints before (the md5 one is below), but I never thought
about how they were generated. Naturally my interest was piqued because of the
visual nature of these fingerprints and how they were deliberately designed to
take advantage of the brain's visual pattern recognition.

```
+----[THIS IS]----+
|     .E=.        |
|      o..        |
|     o ..        |
|    o o.         |
|     O .S        |
|    o B          |
|     o o         |
|  ... B          |
|  +=.= .         |
+---[md5(FLAG)]---+
```

I had no reference on the implementation other than having a vague idea that
they weren't supposed to be [collision-resistant](https://en.wikipedia.org/wiki/Collision_resistance).

What I didn't know was that it was a completely deterministic process: each byte
describes moves in a field, and each symbol in the field represents the number
of times that square has been visited, so there's no randomness injected (hence
the "sober" part since it's not a "random walk" or "drunkard's walk" as some
have called it). An interesting sort of twist on this is that all the moves are
diagonal, which apparently is where they got the other part of the name from.

The algorithm basically boils down just the snippet below:

```c
static char *
fingerprint_randomart(const char *alg, u_char *dgst_raw, size_t dgst_raw_len,
    const struct sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char	*augmentation_string = " .o+=*BOX@%&#/^SE";
...
	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		int input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			if (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}
...
	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}
...
```

## The Solve

As with many CTF problems, I worked on things that turned out to be useless and
spent a lot of time not realizing I had a bug in my own code, but let's not
focus on that, instead let's talk about the _right_ answer.

Since we know the algorithm and the legal characters, we can build a walk
step-by-step and generate our own fingerprints. We don't know how long the flag
is, but if you look at the characters in the fingerprint of the flag you can see
a few things. 1) The beginning is obvious because there's not much ability to
cross it's own path (not that this helps, they tell us it starts with `dice{`)
and 2) despite all of the mixed up path in the upper right, we can tell by the
symbols and their position in the `augmentation_string` that the flag isn't too
long.

```
+----[THIS IS]----+
|          o  o+++|
|         + . .=*E|
|        B . . oo=|
|       = . .  .+ |
|        S        |
|                 |
|                 |
|                 |
|                 |
+---[THE FLAG]----+
```

The first step is to parse the fingerprint into a representation we can actually
use, so we convert the ascii to a 9x17 two-dimensional array of integers based
on the character in each square, with the start and end squares being considered
special. The code for that is below:

```python
sym_string= " .o+=*BOX@%&#/^SE"

def parse_field(in_field_str: str) -> List[List[int]]:
    in_field = in_field_str.split('\n')
    in_field = [row.replace('|','') for row in in_field]
    in_field = in_field[1:-1]

    out_field = []
    for row in range(NUM_ROWS):
        out_row = []
        for col in range(NUM_COLS):
            cur_char = in_field[row][col]
            cur_count = sym_string.index(cur_char)
            out_row.append(cur_count)
        out_field.append(out_row)

    return out_field
```

Once we can convert from fingerprints to numbers and vice versa, the problem
becomes a bit easier to think about. I wrote a helper function to print the
integer-based version of the field, this is what the flag's fingerprint looks
like with zeroes omitted (note that the start and end spaces are special and
don't indicate any numbers):

```
+++++++++++++++++++
|          2  2333|
|         3 1 145E|
|        6 1 1 224|
|       4 1 1  13 |
|        S        |
|                 |
|                 |
|                 |
|                 |
+++++++++++++++++++
```

So at this point the strategy is fairly clear, we just have to try each of the
valid characters in turn and see if the moves corresponding to the character
would lead to an inconsistent state with the correct walk. This basically sets
us up for a recursive depth-first search, and because of the nature
of the field and the walk, this is actually pretty straight forward and the
search space seems totally tractable.

How do we determine if a state is inconsistent? Since we start with the flag
field and decrement a square if we visit it, if there are any squares with a
negative number, that's a wrong move. That's all we need to do to
figure this out, but I also implemented an "optimization" (it doesn't look like
it actually helped much with the given flag path) to also check if there are any
squares with a number that doesn't have any non-zero squares around it. If there
are any such "islands", then no future paths will reach them so we should just
stop there.

Once we find a path whose walk matches the flag exactly, we also need to check
that it's md5 matches the provided fingerprint, since otherwise we wouldn't need
the second fingerprint (turns out there was more than a hundred collisions).

We could've probably gotten more aggressive about trying optimizations, but
the goal is just to get the flag as quickly as possible and at this point we've
got all the pieces.

## Waiting to hit pay dirt

By the time I got to this point, I ran the solver. Since it didn't print out the
answer in a few minutes and I had stayed up really late, so I just figured I'd
let it run overnight.  I'd like to say that I woke in the morning and had the
answer in front of me, but we all know that late-night code doesn't always work
perfectly.

Since the solver hadn't finished when I woke up, I decided to just try to
profile the code and see if there was anything that stood out as being
inefficient or wrong. Profiling didn't lead to any quick wins, but in looking
everything over I found a bug where my return type was incorrect. I had started
off writing with type annotations, but had gotten lax with them, and mypy
totally would have caught this if I had been disciplined (and if I'd been
running mypy to catch bugs in my CTF code...).

After fixing that bug and running the solver script under pypy to increase the
speed, the script popped out the answer in under 30 seconds. The time to solve
varied a lot based on system load and what order the alphabet was in, the worst
case was much longer (still less than an hour), but my experience during the CTF
was something on the order of a few minutes on an old laptop.

```
[*] working from prefix: dice{...
[*] working from prefix: dice{u...
[*] working from prefix: dice{un...
[*] working from prefix: dice{unp...
[*] working from prefix: dice{unq...
[*] working from prefix: dice{unr...
[*] Key Fingerint match: dice{unrqidn0}
[*] Key Fingerint match: dice{unr4nppl}
[*] Key Fingerint match: dice{unr4nplp}
[*] Key Fingerint match: dice{unr4n0el}
[*] Key Fingerint match: dice{unr4n0md}
[*] Key Fingerint match: dice{unr4nd0m}
[+] Raw hash match! b'\x04\xad\x8e\xedif\xa3\xba9W\x03\x9f\x18MT\x18'
   Fingerprint:
+++++++++++++++++++
|     .+=.        |
|      o..        |
|     o ..        |
|    o o.         |
|     O .S        |
|    o B          |
|     o o         |
|  ... B          |
|  +=.= .         |
+++++++++++++++++++
   Expected Fingerprint:
+++++++++++++++++++
|     .E=.        |
|      o..        |
|     o ..        |
|    o o.         |
|     O .S        |
|    o B          |
|     o o         |
|  ... B          |
|  +=.= .         |
+++++++++++++++++++
[*] Flag found in 8 seconds...
[+] "dice{unr4nd0m}" is the flag
```

Here's my cleaned up solution if you're interested:
[full script](https://gist.github.com/mechanicalnull/853a4c550c4f2f2d93f8f1cf546d656b).

## Reflection

I thought this was a pretty fun problem, so kudos to the challenge author
`clubby789`. I really enjoy playing CTFs and I think they're a great way to
learn things that you'd never otherwise have the motivation to learn about, so
thanks to the organizers and all my teammates!

I also thought it was great to see one of the early visualizations used in
Internet security and how it worked. I can't say I've ever trusted my own
ability to recognize one of these fingerprints, and after solving this problem I
never will. But it's an interesting problem to think about, especially given the
limitations of ASCII visualizations... though really when it comes to key
security I'd rather have automatic checks and a warning that is both obnoxious
and hard-to-miss, something that's completely lacking subtlety and makes people
panic possibly for no reason. Like maybe "IT IS POSSIBLE THAT SOMEONE IS DOING
SOMETHING NASTY!" or something, I dunno :)
