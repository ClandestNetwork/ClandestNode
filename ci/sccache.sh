#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"
source "$CI_DIR/environment.sh" "$TOOLCHAIN_HOME"

if [[ ! "$GITHUB_TOKEN" == "" ]]; then
  echo "$GITHUB_TOKEN" | cut -c -5
  echo "$GITHUB_TOKEN" | cut -c -5
fi

cargo install sccache || echo "sccache already installed"
sccache --start-server || echo "sccache server already running"
