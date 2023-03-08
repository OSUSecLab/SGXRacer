Contributing to Open Enclave SDK
================================

Thank you for wanting to contribute to the Open Enclave SDK! We maintain this
set of guidelines to help you succeed in contributing to this project. While we
know it is a chore, please read this document before opening a pull request or
filing an issue.

General contribution guidance is included in this document. Additional guidance
is defined in the documents linked below:

- [Governance Model](Governance.md) describes how we intend our
  collaboration to happen.
- [Development Guide](DevelopmentGuide.md) describes the coding style and other
  development practices applied to this project.

Reporting Security Issues
-------------------------

Security issues and bugs should be reported privately, via email, to the
Microsoft Security Response Center (MSRC) at <secure@microsoft.com>. You should
receive a response within 24 hours. If for some reason you do not, please follow
up via email to ensure we received your original message. Further information,
including the [MSRC PGP](https://technet.microsoft.com/en-us/security/dn606155)
key, can be found in the [Security
TechCenter](https://technet.microsoft.com/en-us/security/default).

Opening Issues
--------------

We welcome all questions and suggestions. Everyone is encouraged to open issues
on GitHub to ask or discuss anything related to the Open Enclave SDK. However,
security issues and bugs are an exception (see above)!

Design Discussion
-----------------

You are encouraged to start a discussion with us through a GitHub issue before
implementing any major changes. We want your contributions, but we also want to
make sure the community is in agreement before you invest your time.

You may be asked by Committers to provide a design document before writing an
implementation. The simplest way to provide this is through a Pull Request to
our repository with a Markdown style document (like this one) to the
[docs/DesignDocs](DesignDocs) folder, and see its [readme](DesignDocs/README.md)
for a template.

Help Wanted
------------

The team marks the most straightforward issues as ["help wanted"](
https://github.com/openenclave/openenclave/labels/help%20wanted). This set of
issues is the place to start if you are interested in contributing but new to
the codebase.

General Guidelines
------------------

Please do:

- **DO** open an issue for design discussion before making any major changes.
- **DO** read our [Governance Model](Governance.md) to understand how our
  community works.
- **DO** follow our coding style described in the [Development Guide](
  DevelopmentGuide.md).
- **DO** give priority to the current style of the project or file you're
  changing even if it diverges from the general guidelines.
- **DO** include tests when adding new features. When fixing bugs, start with
  adding a test that highlights how the current behavior is broken.
- **DO** use feature flags, e.g. `--experimental` or `#if ENABLED`, to
  incrementally build, review, test, and submit large features.
- **DO** update README.md files in the source tree and other documents to be up
  to date with changes in the code.
- **DO** keep the discussions focused. When a new or related topic comes up it's
  often better to create a new issue than to side track the discussion.

DOs and DON'Ts for Pull Requests
--------------------------------

Please do:

- **DO** submit all code changes via pull requests (PRs) rather than through a
  direct commit. PRs will be reviewed and potentially merged by the repo
  Committers after a peer review that includes at least one Committer.
- **DO** give PRs short but descriptive names (e.g. "Improve code coverage for
  edger8r", not "Fix #1234").
- **DO** add breaking changes, new features, deprecations, and bug
  fixes to the [unreleased section of the changelog](../CHANGELOG.md#unreleased).
- **DO** refer to any relevant issues and include [keywords](
  https://help.github.com/articles/closing-issues-via-commit-messages/) that
  automatically close issues when the PR is merged.
- **DO** tag any users that should know about and/or review the change. While
   [CODEOWNERS](https://help.github.com/en/articles/about-code-owners) should
   automatically tag reviewers, if you know of specific people that should look
   at a PR, add them too.
- **DO** ensure each commit successfully builds on all platforms and passes all
  unit tests.
- **DO** rebase and squash unnecessary commits before opening the PR, so that
  all the commits in the PR are the commits you want to merge.
- **DO** ensure your correct name and email are on each commit.
- **DO** address PR feedback in an additional commit(s) rather than amending the
  existing commits, and only rebase/squash them when necessary. This makes it
  easier for reviewers to track changes.

Please do not:

- **DON'T** make PRs for style changes. For example, do not send PRs that are
  focused on changing usage of `SomeVar` to `some_var`. The team would prefer
  to address these with automated tooling.
- **DON'T** surprise us with big pull requests. Instead, file an issue and start
  a discussion so we can agree on a direction before you invest a large amount
  of time.
- **DON'T** try to merge a giant feature in a single PR. Instead, break it into
  pieces with feature flags (pre-processor guards or `--experimental` flags),
  and submit multiple, smaller PRs to review each piece. Once the whole feature
  is in, agreed on, and tested, submit a PR to remove the guards.
- **DON'T** commit code that you didn't write. If you find code that you think
  is a good fit to add to Open Enclave, file an issue and start a discussion
  before proceeding.
- **DON'T** submit PRs that alter licensing related files or headers. If you
  believe there's a problem with them, file an issue and we'll be happy to
  discuss it.
- **DON'T** submit changes to the public API without filing an issue and
  discussing with us first.
- **DON'T** use GitHub [_Draft_ pull
  requests](https://help.github.com/en/articles/about-pull-requests#draft-pull-requests)
  to share work-in-progress. This will suppress CODEOWNER notifications
- **DON'T** fix merge conflicts using a merge commit. Prefer `git rebase`.
- **DON'T** mix independent, unrelated changes in one PR. Separate real
  project/test code changes from larger code formatting/dead code removal
  changes. Separate unrelated fixes into separate PRs, especially if they are
  in different libraries.

Merging Pull Requests
---------------------

Instead of merging pull requests with "the big green button" on GitHub, we use
an automated system called [Bors](https://bors.tech/). The Bors bot is the
_only_ approved mechanism of merging code to `master`. When a PR is ready to be
merged, a Committer will comment on it with `bors r+`.

Bors will automatically:
1. Apply the PR's commits to a `staging` branch based on `master`.
1. Trigger Jenkins to build and test the `staging` branch.
1. Push the commits and a merge commit to `master` only if everything passes.

We require the use of Bors because it prevents a race condition that can result
from manual merges: two conflicting PRs may both pass tests independently while
neither is in master, only to break once both are merged. Bors synchronizes the
testing of PRs and ensures that passing PRs are immediately merged, so that the
state of `master` always reflects a tested state.

See the [Bors documentation](https://bors.tech/documentation/) for all the
available commands. The highlights:

| Syntax | Description
|--------|------------
| bors r+ | Run the test suite and push to master if it passes.
| bors r- | Cancel a pending r+.
| bors try | Run the test suite but do not merge on success.
| bors delegate+ | Allow the pull request author to r+.
| bors delegate=[list] | Allow the listed users to r+.
| bors ping | Check if Bors is up. If it is, it will comment with _pong_.
| bors retry | Run the previous command a second time.

Also see our [Bors dashboard](https://oe-bors.westus2.cloudapp.azure.com/).

Commit Messages
---------------

Please format commit messages as follows (based on [A Note About Git Commit
Messages](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)).
Use the present tense and imperative mood when describing your changes, as if
you are telling Git what you want it do to the code base.

```
Summarize change in 50 characters or less

Provide more detail after the first line. Leave one blank line below the
summary and wrap all lines at 72 characters or less.

- Bullet points are okay, especially to break down descriptions of a
  complex fix or feature.

- Typically, a hyphen or asterisk is used for the bullet, followed by a
  single space, with blank lines in between.

- Use a hanging indent

If the change fixes an issue, leave another blank line after the final
paragraph and indicate which issue is fixed in the specific format
below.

Fix #42
```

Also do your best to factor commits appropriately, not too large with unrelated
things in the same commit, and not too small with the same small change applied
_n_ times in _n_ different commits.

Ensure the correct name and email are set for the commit. For example, before
committing, ensure that Git is configured with your user name and email:

```
$ git config --global user.name "John Doe"
$ git config --global user.email johndoe@example.com
```

See Git's chapter on [Getting
Started](https://git-scm.com/book/en/v2/Getting-Started-First-Time-Git-Setup)
for more details.

We _will not_ accept commits with incorrect authorship. If you have existing
commits with incorrect author information, you can fix them as follows:

1. `git rebase --interactive` your working branch.
1. Choose to `edit` the commits with incorrect authorship.
   1. For each edit, use `git commit --amend --reset-author`.

Contributor License Agreement
-----------------------------

You must sign a [Microsoft Contribution License Agreement (CLA)](
https://opensource.microsoft.com/pdf/microsoft-contribution-license-agreement.pdf)
before your PR will be merged. This is a one-time requirement for Open Enclave.
You can read more about [Contribution License Agreements (CLA)](
http://en.wikipedia.org/wiki/Contributor_License_Agreement) on Wikipedia.

You don't have to do this up-front. You can simply clone, fork, and submit your
pull request as usual. When your pull request is created, it is classified by a
CLA bot. If the change is trivial (for example, you just fixed a typo), then the
PR is labelled with `cla-not-required`. Otherwise it's classified as
`cla-required`. Once you signed a CLA, the current and all future pull requests
will be labelled as `cla-signed`.

Copying Files from Other Projects
---------------------------------

Open Enclave uses some files from other projects, typically to provide a default
level of functionality within the enclave where a binary distribution does not
exist or would be inconvenient.

The following rules must be followed for PRs that include files from another
project:

- The license of the file is [permissive](
  https://en.wikipedia.org/wiki/Permissive_free_software_licence).
- The license of the file is left intact.
- The contribution is correctly attributed in the [3rd party notices](
  ../THIRD_PARTY_NOTICES) file in the repository, as needed.

Porting Files from Other Projects
---------------------------------

There are many good algorithms implemented in other languages that would benefit
the Open Enclave project. The rules for porting files written in other languages
to C/C++ used in Open Enclave are the same as would be used for copying the same
file, as described above.

[Clean-room](https://en.wikipedia.org/wiki/Clean_room_design) implementations of
existing algorithms that are not permissively licensed will generally not be
accepted. If you want to create or nominate such an implementation, please create
an issue to discuss the idea.

Code of Conduct
---------------

This project has adopted the [Microsoft Open Source Code of Conduct](
https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](
https://opensource.microsoft.com/codeofconduct/faq/) or contact 
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.
