Using Doxygen in Open Enclave
=============================

This short document explains how to use Doxygen within Open Enclave.

## Overview

Doxygen is used to extract documentation from the Open Enclave source code. This
directory contains a CMake target, `doxygen`, for building the HTML formatted
documentation.

The generated HTML files are the only ones that are checked
into the GitHub repository. This allows one to browse the documentation from
GitHub Pages.

To update the generated documentation, create the CMake build tree by using the
instructions in [Building the Open Enclave SDK](/docs/GettingStartedDocs/Contributors/building_oe_sdk.md). Assuming that `build` is
the root of the CMake build tree, a successful `make` will build the HTML
reference documentation by default. You can also make the documentation directly
from the build folder:

```bash
make doxygen
```

The resulting documentation can be found in the CMake tree under:

```
build/output/share/doc/openenclave/html
```

Open Enclave SDK API documentation resides on the `gh-pages` branch. To update
the generated html files in the source tree for commit into GitHub, you will
need to do the following from the source tree root:

```bash
./scripts/deploy-docs
```

## Adding headers files to Doxygen

To add new header files to be processed by Doxygen, add them to the list in the
CMake command `doxygen_add_docs` in this [CMakeLists.txt](CMakeLists.txt). Note
that it is relative to `./include/openenclave`, from the root of the repo.

## Source code documentation conventions

Open Enclave uses the Doxygen Markdown style throughout the sources. To learn
more about Doxygen Markdown, refer to the [Doxygen Markdown Support](http://www.doxygen.nl/manual/markdown.html).

The sections below explain the basics.

### Comment blocks

In Open Enclave, Doxygen comment blocks are defined as follows.

```
/**
 *
 *
 */
```

### Brief description

The brief description is the first sentence that appears in the comment block,
terminated by a period.

```
/**
 * This is my brief description.
 */
```

### Detailed description

The detailed description follows the brief description.

```
/**
 * This is my brief description.
 *
 * This is my detailed description. It may contain many sentences.
 */
```

### Parameters

Parameters should be introduced as follows.

```
/**
 * ...
 *
 * @param param1 This is my first parameter.
 * @param param2 This is my second parameter.
 */
```
#### Return values

Return values may be specified as a list of paragraphs (**@retval**) or
as a single paragraph (**@returns**).

Here's an example of a list of paragraphs:

```
/**
 * ...
 *
 * @retval SUCCESS The function was successful.
 * @retval FAILED The function failed.
 */
```

Here's an example of a single paragraph:

```
/**
 * ...
 *
 * @returns Returns OK on success.
 */
```

### Emphasis

To emphasize text (italics), use single asterisks as follows.

```
/**
 * This is my *emphasis* example.
 *
 */
```

### Boldface

To bold text, use double asterisks as follows.

```
/**
 * This is my *bold* example.
 *
 */
```

### Lists

Lists are introduced by the hyphen character as follows.

```
/**
 * ...
 *
 * This is my list:
 * - Sunday
 * - Monday
 * - Tuesday
 * - Wednesday
 * - Thursday
 * - Friday
 * - Saturday
 *
 */
```

### Verbatim

To define a verbatim block of text, separate it by blank lines and indent it.
For example.

```
/**
 * ...
 *
 * This is my verbatim text:
 *
 *   This is my verbatim block of text.
 *
 * Continue with normal text.
 *
 */
```

### Disabling Doxygen documentation from blocks of code

To disable Doxygen documentation from blocks of code with `#defines` or
`#typedefs` use the `@cond` command. For example:

```
/**
 * @cond DEV
 *
 */

<your code section goes here>

/**
 * @endcond
 *
 */
```

Doxygen will not document the code between `@cond` and `@endcond` unless `DEV`
is specified in the `ENABLED_SECTIONS` of the doxygen.conf file.
