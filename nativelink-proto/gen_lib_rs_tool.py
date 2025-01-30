# Copyright 2022 The NativeLink Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generates a lib.rs file from input proto files."""

import argparse
import os
from pathlib import Path

_HEADER = """\
// Copyright 2022 The NativeLink Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// *** DO NOT MODIFY ***
// This file is auto-generated. To update it, run:
// `bazel run nativelink-proto:update_protos`

#![allow(
    clippy::default_trait_access,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::doc_markdown,
    clippy::large_enum_variant,
    clippy::missing_const_for_fn,
    rustdoc::invalid_html_tags
)]
"""


def print_package_part_to_mod(tree, indents = 0):
  tabs = "    " * indents
  if tree["filename"] is not None:
      print('%sinclude!("%s");' % (tabs, tree["filename"]))

  for mod_name, value in tree["children"].items():
      print("%spub mod %s {" % (tabs, mod_name))
      print_package_part_to_mod(value, indents + 1)
      print("%s}" % (tabs, ))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootdir', default=os.getcwd(),
                        help='Module paths will be relative to this path. Default CWD.')
    parser.add_argument('files', nargs='+',
                        help='pb.rs files used to generate lib.rs')
    args = parser.parse_args()
    print(_HEADER)

    tree_root = { "children": {}, "filename": None }
    for filepath in args.files:
        filepath = os.path.relpath(os.path.normpath(filepath), args.rootdir)
        assert filepath.endswith('.pb.rs'), "Expected " + filepath + " to end in '.pb.rs'"
        package_parts = filepath.split('.')[:-2]  # Remove `.pb.rs'.
        assert '.' not in package_parts and '..' not in package_parts, \
            "'%s' is not in proper root directory" % (filepath, )
        cur_node = tree_root
        for part in package_parts:
            if part not in cur_node["children"]:
                cur_node["children"][part] = { "children": {}, "filename": None }
            cur_node = cur_node["children"][part]
        assert not cur_node["filename"], "Duplicate package '%s'" % ('.'.join(package_parts), )
        cur_node["filename"] = '.'.join(package_parts) + '.pb.rs'

    print_package_part_to_mod(tree_root)


if __name__ == "__main__":
    main()
