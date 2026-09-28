# Git hooks

Two hooks, for the two moments a secret can still be stopped.

## `pre-commit` — on your machine

```bash
cp hooks/git/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

It scans **the index, not the working tree**. A secret you edited but did not
stage is not part of this commit, and blocking on it would be wrong. It also
means the staged content is what gets checked even if you have since cleaned up
the file — which is the case the hook exists for.

```console
$ git commit -m "add config"
SEVERITY  TYPE  VALUE           WHERE
error     cpf   ***.***.***-25  bad.txt:1

nadzor: the commit was blocked because the staged changes hold the values above.
```

Defaults to `--min-confidence medium`, because a pre-commit hook that cries wolf
gets removed. Override with `NADZOR_MIN_CONFIDENCE=low`.

`git commit --no-verify` skips it. That is a feature: a hook you cannot get past
is a hook people uninstall.

## `pre-receive` — on the server

```bash
cp hooks/git/pre-receive /path/to/repo.git/hooks/pre-receive
chmod +x /path/to/repo.git/hooks/pre-receive
```

The last place a secret can be stopped before it is in history other people have
fetched. After that, rotation is the only remedy — rewriting history does not
un-share what was already cloned.

It scans the range being pushed, not the whole history: a server hook runs while
the client waits, so walking every branch on every push would make push time grow
with the age of the repository.

## Both hooks tell you which failure happened

Exit 3 is findings; exit 1 is the scan itself failing. Both block, and the
message differs, because "you are committing a key" and "the scanner is broken"
need different responses. A hook that treats a crashed scan as a pass is worse
than no hook: it reports safety it did not check.

## What they do not cover

- A secret already in history. Use `nadzor git` for that, deliberately.
- A secret in a commit made with `--no-verify`, or pushed before the hook existed.
- A `pre-commit` hook is per clone and not versioned, so it protects whoever
  installed it and nobody else. The `pre-receive` hook is the one that covers
  everyone, and CI is the one that covers pull requests.
