# Contributing

When contributing to this repository, please first discuss the change you wish
to make by opening an issue. Discussing the design before implementing a big
feature can result in a much better and cleaner implementation.

## Pull Request Checklist

Please ensure your PR meets the following requirements:
- Commits MUST be signed-off by the committer. For example:

   ```
   This is my commit message

   Signed-off-by: Random J Developer <random@developer.example.org>
   ```

  Git has a -s command line option to append this automatically to your commit
  message:

   ```console
   $ git commit -s -m 'This is my commit message'
   ```
- CI tests MUST pass. No PR will be accepted with a broken CI.
- Documentation MUST be updated, if you added a new user-facing option.
